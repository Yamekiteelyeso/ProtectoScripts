const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const BASE = (process.env.BASE_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${PORT}`)).replace(/\/$/, '');
const BASE_DOMAIN = process.env.BASE_DOMAIN || '';
const STRICT = process.env.ANTI_HOOK === 'strict';
const MAX_SCRIPTS = 5;
const RESERVED = ['api', 'auth', 's', 'p', 'www', 'admin', 'lexy', 'login'];

// Base de datos SQLite
const VOL = process.env.RAILWAY_VOLUME_MOUNT_PATH;
const DB_FILE = process.env.DB_PATH || (VOL ? path.join(VOL, 'lexy.db') : (fs.existsSync('/data') ? '/data/lexy.db' : 'lexy.db'));
if (!process.env.DB_PATH && !VOL && process.env.RAILWAY_ENVIRONMENT) console.warn('[!] Sin Volume: los datos se borran en cada deploy. Agregá un Volume al servicio.');

let db;
try { fs.mkdirSync(path.dirname(path.resolve(DB_FILE)), { recursive: true }); db = new Database(DB_FILE); }
catch (e) { console.warn(`[!] No pude abrir ${DB_FILE} (${e.message}). Uso ./lexy.db`); db = new Database('lexy.db'); }

db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists users(id integer primary key, username text unique collate nocase not null, email text unique collate nocase, pass text, provider text, pid text, created integer);
create table if not exists scripts(id integer primary key, user_id integer not null, slug text unique not null, content text not null, enabled integer default 1, blocked integer default 0, created integer);
create table if not exists execs(id integer primary key, script_id integer not null, ts integer, ip_hash text, rbx_id text, rbx_name text);
create index if not exists ix_ex on execs(script_id, ts);
create table if not exists bans(script_id integer, rbx_id text, primary key(script_id, rbx_id));
`);
try { db.exec('alter table execs add column place text'); } catch {}
db.exec('create table if not exists meta(k text primary key, v text)');

const SECRET = process.env.JWT_SECRET || db.prepare("select v from meta where k='jwt'").get()?.v || (() => { const v = crypto.randomBytes(32).toString('hex'); db.prepare("insert into meta(k,v) values('jwt',?)").run(v); return v; })();

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

const BASE_ENV = process.env.BASE_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
app.use((req, res, next) => {
  req.cip = req.headers['x-real-ip'] || req.ip;
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol).split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] || req.get('host') || '').split(',')[0].trim();
  req.https = proto === 'https';
  req.base = (host ? `${proto}://${host}` : BASE_ENV || BASE).replace(/\/$/, '');
  next();
});

app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:', 'https://cdn.discordapp.com'], frameAncestors: ["'none'"],
  } },
}));

app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http' && !req.path.startsWith('/s/') && !/^(localhost|127\.)/.test(req.hostname)) return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
  next();
});

app.use(express.json({ limit: '600kb' }));
app.use(cookieParser());

const hash = (s) => crypto.createHash('sha256').update(s + SECRET).digest('hex').slice(0, 24);
const lim = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, validate: false, keyGenerator: (req) => req.cip || req.ip, message: { error: 'Demasiados intentos, esperá un momento' } });
const apiLim = lim(60e3, 120), authLim = lim(10 * 60e3, 40), loadLim = lim(60e3, 120);

/* ---------- Sesión ---------- */
const setSess = (req, res, u) => { const t = jwt.sign({ id: Number(u.id) }, SECRET, { expiresIn: '30d' }); res.cookie('lx', t, { httpOnly: true, sameSite: 'lax', secure: !!req.https, path: '/', maxAge: 30 * 864e5 }); return t; };
const tokenOf = (req) => req.cookies.lx || (/^Bearer (.+)$/.exec(req.headers.authorization || '') || [])[1];
const auth = (req, res, next) => {
  try {
    const p = jwt.verify(tokenOf(req), SECRET);
    const u = db.prepare('select id, username, email from users where id=?').get(p.id);
    if (!u) throw 0;
    if (p.iat && Date.now() / 1000 - p.iat > 86400) setSess(req, res, u);
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Iniciá sesión' }); }
};

/* ---------- Registro / Login ---------- */
app.post('/api/register', lim(60 * 60e3, 15), authLim, (req, res) => {
  const { username, password, email } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Usuario: 3-20 letras, números o _' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) return res.status(400).json({ error: 'La contraseña debe tener 8-72 caracteres' });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Correo inválido' });
  if (db.prepare('select 1 from users where username=? or (email is not null and email=?)').get(username, email || null)) return res.status(409).json({ error: 'Usuario o correo ya registrado' });
  const r = db.prepare('insert into users(username,email,pass,created) values(?,?,?,?)').run(username, email || null, bcrypt.hashSync(password, 11), Date.now());
  res.json({ ok: 1, token: setSess(req, res, { id: r.lastInsertRowid }) });
});

app.post('/api/login', authLim, (req, res) => {
  const id = String(req.body?.id || ''), pw = String(req.body?.password || '');
  const u = db.prepare('select * from users where (username=? or email=?) and pass is not null').get(id, id);
  if (!u || !bcrypt.compareSync(pw, u.pass)) return res.status(401).json({ error: 'Datos incorrectos' });
  res.json({ ok: 1, token: setSess(req, res, u) });
});

app.post('/api/logout', (req, res) => { res.clearCookie('lx', { path: '/' }); res.json({ ok: 1 }); });
app.get('/api/me', auth, (req, res) => res.json({ ...req.user, max: MAX_SCRIPTS }));

/* ---------- OAuth Google / Discord ---------- */
const OA = {
  google: { auth: 'https://accounts.google.com/o/oauth2/v2/auth', token: 'https://oauth2.googleapis.com/token', info: 'https://openidconnect.googleapis.com/v1/userinfo', scope: 'openid email profile', id: process.env.GOOGLE_CLIENT_ID, secret: process.env.GOOGLE_CLIENT_SECRET, map: (p) => ({ pid: p.sub, name: p.name || (p.email || 'user').split('@')[0], email: p.email_verified ? p.email : null }) },
  discord: { auth: 'https://discord.com/oauth2/authorize', token: 'https://discord.com/api/oauth2/token', info: 'https://discord.com/api/users/@me', scope: 'identify email', id: process.env.DISCORD_CLIENT_ID, secret: process.env.DISCORD_CLIENT_SECRET, map: (p) => ({ pid: p.id, name: p.global_name || p.username, email: p.verified ? p.email : null }) },
};

app.get('/api/providers', (req, res) => res.json({ google: !!OA.google.id, discord: !!OA.discord.id }));

app.get('/auth/:p', authLim, (req, res) => {
  const o = OA[req.params.p];
  if (!o || !o.id) return res.redirect('/?error=' + encodeURIComponent('Ese método no está configurado'));
  const n = crypto.randomBytes(16).toString('hex'), st = jwt.sign({ n, p: req.params.p }, SECRET, { expiresIn: '15m' });
  res.cookie('lx_st', n, { httpOnly: true, sameSite: 'lax', secure: !!req.https, path: '/', maxAge: 9e5 });
  res.redirect(o.auth + '?' + new URLSearchParams({ client_id: o.id, redirect_uri: `${req.base}/auth/${req.params.p}/callback`, response_type: 'code', scope: o.scope, state: st }));
});

const UA = { 'User-Agent': 'DiscordBot (https://lexyprotect, 1.0)', Accept: 'application/json' };
app.get('/auth/:p/callback', authLim, async (req, res) => {
  const o = OA[req.params.p], fail = (m) => res.redirect('/?error=' + encodeURIComponent(m));
  try {
    if (req.query.error) return fail('Cancelaste el inicio de sesión');
    let stp; try { stp = jwt.verify(String(req.query.state || ''), SECRET); } catch {}
    if (!o || !req.query.code || !stp || stp.p !== req.params.p || (req.cookies.lx_st && req.cookies.lx_st !== stp.n)) return fail('Sesión de login inválida, probá de nuevo');
    res.clearCookie('lx_st', { path: '/' });
    const tr = await fetch(o.token, { method: 'POST', headers: { ...UA, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: o.id, client_secret: o.secret, grant_type: 'authorization_code', code: req.query.code, redirect_uri: `${req.base}/auth/${req.params.p}/callback` }) });
    const t = await tr.json().catch(() => ({}));
    if (!t.access_token) return fail('No se pudo iniciar sesión' + (t.error ? ` (${t.error})` : ''));
    const pr = await fetch(o.info, { headers: { ...UA, Authorization: 'Bearer ' + t.access_token } });
    const pj = await pr.json().catch(() => ({}));
    const prof = o.map(pj);
    if (!prof.pid) return fail('No se pudo leer tu perfil');
    let u = db.prepare('select * from users where provider=? and pid=?').get(req.params.p, String(prof.pid));
    if (!u) {
      let name = String(prof.name || 'user').replace(/[^a-zA-Z0-9_]/g, '').slice(0, 14);
      if (name.length < 3) name = 'user' + crypto.randomInt(100, 9999);
      while (db.prepare('select 1 from users where username=?').get(name)) name = name.slice(0, 14) + crypto.randomInt(100, 9999);
      const email = prof.email && !db.prepare('select 1 from users where email=?').get(prof.email) ? prof.email : null;
      const r = db.prepare('insert into users(username,email,provider,pid,created) values(?,?,?,?,?)').run(name, email, req.params.p, String(prof.pid), Date.now());
      u = { id: r.lastInsertRowid };
    }
    res.redirect('/#t=' + setSess(req, res, u));
  } catch (e) { console.error('[oauth]', e); fail('Error al iniciar sesión'); }
});

/* ---------- API Scripts ---------- */
const urlFor = (slug, base = BASE) => (BASE_DOMAIN ? `https://${slug}.${BASE_DOMAIN}` : `${base}/s/${slug}`);
const own = (req) => db.prepare('select * from scripts where id=? and user_id=?').get(req.params.id, req.user.id);

app.get('/api/scripts', apiLim, auth, (req, res) => {
  const rows = db.prepare(`select s.id, s.slug, s.enabled, s.blocked, s.created, length(s.content) size,
    (select max(ts) from execs where script_id=s.id) last,
    (select count(*) from execs where script_id=s.id) total
    from scripts s where user_id=? order by id desc`).all(req.user.id);
  res.json(rows.map((r) => ({ ...r, url: urlFor(r.slug, req.base), loadstring: `loadstring(game:HttpGet("${urlFor(r.slug, req.base)}"))()` })));
});

app.post('/api/scripts', apiLim, auth, (req, res) => {
  const slug = String(req.body?.name || '').toLowerCase(), content = req.body?.content;
  if (!/^[a-z0-9-]{3,24}$/.test(slug) || RESERVED.includes(slug)) return res.status(400).json({ error: 'Nombre: 3-24 caracteres, minúsculas, números o guiones' });
  if (typeof content !== 'string' || !content.trim() || content.length > 500000) return res.status(400).json({ error: 'El script está vacío o pesa más de 500 KB' });
  if (db.prepare('select count(*) c from scripts where user_id=?').get(req.user.id).c >= MAX_SCRIPTS) return res.status(403).json({ error: `Llegaste al límite de ${MAX_SCRIPTS} scripts` });
  if (db.prepare('select 1 from scripts where slug=?').get(slug)) return res.status(409).json({ error: 'Ese nombre ya está en uso' });
  db.prepare('insert into scripts(user_id,slug,content,created) values(?,?,?,?)').run(req.user.id, slug, content, Date.now());
  res.json({ ok: 1 });
});

app.patch('/api/scripts/:id', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  const { content, enabled } = req.body || {};
  if (typeof content === 'string') {
    if (!content.trim() || content.length > 500000) return res.status(400).json({ error: 'Script inválido' });
    db.prepare('update scripts set content=? where id=?').run(content, s.id);
  }
  if (typeof enabled === 'boolean') db.prepare('update scripts set enabled=? where id=?').run(enabled ? 1 : 0, s.id);
  res.json({ ok: 1 });
});

app.get('/api/scripts/:id/content', apiLim, auth, (req, res) => { const s = own(req); s ? res.json({ content: s.content }) : res.status(404).json({ error: 'No existe' }); });
app.delete('/api/scripts/:id', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  db.prepare('delete from execs where script_id=?').run(s.id);
  db.prepare('delete from scripts where id=?').run(s.id);
  res.json({ ok: 1 });
});

app.get('/api/scripts/:id/stats', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  res.json({ ...weekStats('script_id=?', s.id), blocked: s.blocked });
});

/* ---------- Estadísticas ---------- */
const DAY = 864e5, WEEK = 7 * DAY;
function weekStats(where, ...p) {
  const today = new Date().setUTCHours(0, 0, 0, 0);
  const monday = today - ((new Date(today).getUTCDay() + 6) % 7) * DAY;
  const start = monday - 7 * WEEK, weeks = Array(8).fill(0);
  db.prepare(`select ts from execs where ts>=? and ${where}`).all(start, ...p).forEach((r) => { weeks[Math.min(7, Math.floor((r.ts - start) / WEEK))]++; });
  const t = db.prepare(`select count(*) total, coalesce(sum(ts>=?),0) today, coalesce(sum(ts>=?),0) week from execs where ${where}`).get(today, monday, ...p);
  return { ...t, weeks, start };
}

app.get('/api/overview', apiLim, auth, (req, res) => {
  const blocked = db.prepare('select coalesce(sum(blocked),0) b from scripts where user_id=?').get(req.user.id).b;
  res.json({ ...weekStats('script_id in (select id from scripts where user_id=?)', req.user.id), blocked });
});

/* ---------- Loader protegido ---------- */
const strikes = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of strikes) if (v.t < n - 36e5) strikes.delete(k); }, 6e4).unref();
const isBanned = (ip) => (strikes.get(ip)?.until || 0) > Date.now();
const strike = (ip) => { const s = strikes.get(ip) || { n: 0, until: 0, t: 0 }; s.t = Date.now(); if (++s.n >= 6) { s.until = Date.now() + 15 * 60e3; s.n = 0; } strikes.set(ip, s); };

const BOT_UA = /discord|telegrambot|whatsapp|slackbot|facebookexternalhit|twitterbot|googlebot|bingbot|yandex|baiduspider|curl|wget|python|aiohttp|axios|node-fetch|undici|go-http|postman|insomnia|httpie|libwww|scrapy|headless|phantomjs|puppeteer|playwright|spider|crawler|\bbot\b/i;
const isBrowser = (req) => { const h = req.headers; return !BOT_UA.test(h['user-agent'] || '') && !!(h['sec-fetch-mode'] || h['sec-fetch-dest'] || (h.accept || '').includes('text/html')); };
const deny = (res, code = 403) => res.status(code).type('html').send('<!doctype html><meta name="robots" content="noindex"><title>Lexy Protect</title><body style="background:#17101f;color:#efe8fb;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0"><p>Acceso denegado · Lexy Protect</p>');

const rid = () => 'l' + crypto.randomBytes(5).toString('hex');
function stub(k, url) {
  const N = {};
  'P g bye sp bad chk w v q o k C T dec kb db out f i j x y t u r s'.split(' ').forEach((v) => (N[v] = rid()));
  const lua = `local @P@ = game:GetService("Players").LocalPlayer
local @g@ = (getgenv and getgenv()) or _G
local function @bye@(m) pcall(function() @P@:Kick("Lexy Protect: " .. m) end) end
local @bad@ = {"httpspy","simplespy","remotespy","hydroxide","cobaltspy","dumper","httpdebug","networkspy"}
local function @chk@(s) s = tostring(s):lower() for _, @w@ in ipairs(@bad@) do if s:find(@w@, 1, true) then return true end end return false end
local @sp@ = false
pcall(function() for _, @v@ in ipairs({ @g@, _G, shared }) do for @q@ in pairs(@v@) do if @chk@(@q@) then @sp@ = true end end end end)
pcall(function() for _, @v@ in ipairs({ game:GetService("CoreGui"), (gethui and gethui()) or game:GetService("CoreGui") }) do for _, @o@ in ipairs(@v@:GetChildren()) do if @chk@(@o@.Name) then @sp@ = true end end end end)
if @sp@ then return @bye@("spy detectado") end
${STRICT ? `local function @t@(f) return type(f) ~= "function" or (islclosure and islclosure(f)) end
if @t@(loadstring) or @t@(game.HttpGet) then return @bye@("entorno modificado") end` : ''}
local @k@, @u@, @r@ = "${k}", "${url}", nil
pcall(function() @r@ = game:HttpGet(@u@) end)
if type(@r@) ~= "string" then pcall(function() local @q@ = request or http_request or (syn and syn.request); if @q@ then @r@ = @q@({ Url = @u@, Method = "GET" }).Body end end) end
if type(@r@) ~= "string" or @r@:sub(1, 2) ~= "LX" then return warn("[Lexy Protect] no se pudo cargar el script") end
local @s@ = @r@:sub(3)
local @C@ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local @T@ = {} for @i@ = 1, 64 do @T@[@C@:byte(@i@)] = @i@ - 1 end
local function @dec@(z)
  local @out@, @x@, @v@, @j@ = {}, 0, 0, 0
  for @i@ = 1, #z do
    local @y@ = @T@[z:byte(@i@)]
    if @y@ then @v@ = @v@ * 64 + @y@; @j@ = @j@ + 6
      if @j@ >= 8 then @j@ = @j@ - 8; @x@ = @x@ + 1; @out@[@x@] = math.floor(@v@ / 2 ^ @j@); @v@ = @v@ % 2 ^ @j@ end
    end
  end
  return @out@
end
local @kb@, @db@ = @dec@(@k@), @dec@(@s@)
local @f@ = {}
for @i@ = 1, #@db@, 4000 do
  local @q@ = {}
  for @j@ = @i@, math.min(@i@ + 3999, #@db@) do @q@[#@q@ + 1] = (bit32.bxor(@db@[@j@], @kb@[(@j@ - 1) % 16 + 1]) - (@j@ * 7) % 251) % 256 end
  @f@[#@f@ + 1] = string.char(table.unpack(@q@))
end
local @o@ = loadstring(table.concat(@f@))
@kb@, @db@, @f@, @k@, @s@, @r@ = nil, nil, nil, nil, nil, nil
if @o@ then @o@() end
`;
  return lua.replace(/@(\w+)@/g, (m, v) => N[v] || m);
}

function seal(text, key) {
  const buf = Buffer.from(text, 'utf8');
  for (let i = 0; i < buf.length; i++) buf[i] = ((buf[i] + ((i + 1) * 7) % 251) & 255) ^ key[i % 16];
  return buf.toString('base64');
}

const he = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ---------- Páginas HTML (Landing y Fallback de Login con Discord) ---------- */
function landing(res, slug, base) {
  slug = String(slug).toLowerCase();
  const r = db.prepare('select s.enabled, u.username owner, (select count(*) from execs where script_id=s.id) total from scripts s join users u on u.id=s.user_id where s.slug=?').get(slug);
  if (!r) return deny(res, 404);
  const ls = `loadstring(game:HttpGet("${urlFor(slug, base)}"))()`;
  res.status(200).type('html').set('Cache-Control', 'no-store').send(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${he(slug)} · Lexy Protect</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;700;800&family=JetBrains+Mono&display=swap" rel="stylesheet"><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.2rem;background:#130d1b;color:#f0e9fa;font:16px/1.55 'Bricolage Grotesque',system-ui,sans-serif}
.c{width:100%;max-width:560px;background:#1b1226;border:1px solid #34264a;border-radius:18px;padding:2rem}
.header-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.6rem}
.lg{display:flex;align-items:center;gap:.6rem;font-weight:800;color:#9a8cb3;font-size:.95rem}.lg i{width:26px;height:26px;border-radius:7px;background:#ff6fae;display:grid;place-items:center}
.discord-btn-sm{display:inline-flex;align-items:center;gap:.4rem;background:#5865F2;color:#fff;text-decoration:none;font-weight:700;font-size:.85rem;padding:.4rem .8rem;border-radius:8px;transition:background .2s}
.discord-btn-sm:hover{background:#4752C4}
h1{margin:0;font-size:2rem;letter-spacing:-.035em;font-weight:800;word-break:break-word}p{color:#9a8cb3;margin:.3rem 0 0}
code{display:block;margin:1.4rem 0 .8rem;background:#130d1b;border:1px solid #34264a;border-radius:10px;padding:.8rem 1rem;font:13px 'JetBrains Mono',monospace;color:#6fe3c1;overflow-x:auto;white-space:nowrap}
button{width:100%;border:0;border-radius:10px;padding:.8rem;background:#ff6fae;color:#2a0f1e;font:700 1rem inherit;font-family:inherit;cursor:pointer;transition:background .2s}button:hover{background:#ff8fc2}
.m{display:flex;justify-content:space-between;gap:1rem;margin-top:1.4rem;color:#9a8cb3;font-size:.9rem;flex-wrap:wrap}
.o{display:inline-flex;gap:.4rem;align-items:center;font-size:.85rem;border:1px solid #34264a;border-radius:999px;padding:.1rem .65rem;color:#9a8cb3;margin-top:.8rem}.o::before{content:"";width:7px;height:7px;border-radius:50%;background:${r.enabled ? '#6fe3c1' : '#ffc46b'}}
</style></head><body><main class="c">
<div class="header-bar">
  <div class="lg"><i><svg width="16" height="16" viewBox="0 0 24 24" fill="#130d1b"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg></i>Lexy Protect</div>
  ${OA.discord.id ? `<a href="/auth/discord" class="discord-btn-sm"><svg width="16" height="16" viewBox="0 0 127.14 96.36" fill="currentColor"><path d="M107.7 8.07A105.15 105.15 0 0 0 81.47 0a72.06 72.06 0 0 0-3.36 6.83 97.68 97.68 0 0 0-29.11 0A72.37 72.37 0 0 0 45.64 0a105.89 105.89 0 0 0-26.25 8.09C2.79 32.65-1.71 56.6.54 80.21a105.73 105.73 0 0 0 32.17 16.15 77.7 77.7 0 0 0 6.89-11.11 68.42 68.42 0 0 1-10.85-5.18c.91-.66 1.8-1.34 2.66-2a75.57 75.57 0 0 0 64.32 0c.87.68 1.76 1.36 2.66 2a68.68 68.68 0 0 1-10.87 5.19 77 77 0 0 0 6.89 11.1 105.25 105.25 0 0 0 32.19-16.14c2.64-27.38-4.51-51.11-18.91-72.14zM42.45 65.69c-6.28 0-11.41-5.77-11.41-12.87 0-7.1 5-12.87 11.41-12.87 6.45 0 11.53 5.82 11.41 12.87 0 7.1-4.96 12.87-11.41 12.87zm42.24 0c-6.28 0-11.41-5.77-11.41-12.87 0-7.1 5-12.87 11.41-12.87 6.45 0 11.53 5.82 11.41 12.87 0 7.1-4.96 12.87-11.41 12.87z"/></svg> Login</a>` : ''}
</div>
<h1>${he(slug)}</h1><p>Publicado por ${he(r.owner)}</p><span class="o">${r.enabled ? 'Activo' : 'Pausado por su dueño'}</span>
${r.enabled ? `<code id="c">${he(ls)}</code><button id="b">Copiar loadstring</button><p style="margin-top:1rem;font-size:.9rem">Pegalo en tu executor (Delta) y ejecutalo. El código del script está protegido y no se puede ver desde acá.</p>` : '<p style="margin-top:1.2rem">Este script no está disponible por ahora.</p>'}
<div class="m"><span>${Number(r.total).toLocaleString('es')} ejecuciones</span><span>Protegido por Lexy Protect</span></div></main>
<script>var b=document.getElementById('b');if(b)b.onclick=function(){navigator.clipboard.writeText(document.getElementById('c').textContent).then(function(){b.textContent='¡Copiado!';setTimeout(function(){b.textContent='Copiar loadstring'},1500)})}</script></body></html>`);
}

// Fallback visual aesthetic para la raíz si no existe un index.html personalizado
function defaultIndex(req, res) {
  res.status(200).type('html').send(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lexy Protect · Dashboard & Login</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;700;800&display=swap" rel="stylesheet"><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.2rem;background:#130d1b;color:#f0e9fa;font:16px/1.55 'Bricolage Grotesque',system-ui,sans-serif}
.card{width:100%;max-width:420px;background:#1b1226;border:1px solid #34264a;border-radius:20px;padding:2.2rem;text-align:center;box-shadow:0 10px 30px rgba(0,0,0,.3)}
.logo{display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:14px;background:#ff6fae;margin-bottom:1rem}
h1{margin:0 0 .4rem;font-size:1.8rem;font-weight:800}p{color:#9a8cb3;margin:0 0 1.8rem;font-size:.95rem}
.oauth-container{display:flex;flex-direction:column;gap:.8rem}
.btn-oauth{display:flex;align-items:center;justify-content:center;gap:.75rem;width:100%;padding:.85rem;border-radius:12px;font-weight:700;font-size:1rem;text-decoration:none;transition:transform .15s, opacity .15s}
.btn-oauth:hover{opacity:.92;transform:translateY(-1px)}
.btn-discord{background:#5865F2;color:#fff}
.btn-google{background:#e2e8f0;color:#1e293b}
.footer{margin-top:1.8rem;font-size:.8rem;color:#7a6b94}
</style></head><body><main class="card">
<div class="logo"><svg width="24" height="24" viewBox="0 0 24 24" fill="#130d1b"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg></div>
<h1>Lexy Protect</h1><p>Protege y gestiona tus scripts en segundos</p>
<div class="oauth-container">
  ${OA.discord.id ? `<a href="/auth/discord" class="btn-oauth btn-discord"><svg width="20" height="20" viewBox="0 0 127.14 96.36" fill="currentColor"><path d="M107.7 8.07A105.15 105.15 0 0 0 81.47 0a72.06 72.06 0 0 0-3.36 6.83 97.68 97.68 0 0 0-29.11 0A72.37 72.37 0 0 0 45.64 0a105.89 105.89 0 0 0-26.25 8.09C2.79 32.65-1.71 56.6.54 80.21a105.73 105.73 0 0 0 32.17 16.15 77.7 77.7 0 0 0 6.89-11.11 68.42 68.42 0 0 1-10.85-5.18c.91-.66 1.8-1.34 2.66-2a75.57 75.57 0 0 0 64.32 0c.87.68 1.76 1.36 2.66 2a68.68 68.68 0 0 1-10.87 5.19 77 77 0 0 0 6.89 11.1 105.25 105.25 0 0 0 32.19-16.14c2.64-27.38-4.51-51.11-18.91-72.14zM42.45 65.69c-6.28 0-11.41-5.77-11.41-12.87 0-7.1 5-12.87 11.41-12.87 6.45 0 11.53 5.82 11.41 12.87 0 7.1-4.96 12.87-11.41 12.87zm42.24 0c-6.28 0-11.41-5.77-11.41-12.87 0-7.1 5-12.87 11.41-12.87 6.45 0 11.53 5.82 11.41 12.87 0 7.1-4.96 12.87-11.41 12.87z"/></svg> Entrar con Discord</a>` : ''}
  ${OA.google.id ? `<a href="/auth/google" class="btn-oauth btn-google"><svg width="18" height="18" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3h3.88c2.27-2.09 3.665-5.17 3.665-9.12z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3c-1.08.72-2.45 1.16-4.05 1.16-3.1 0-5.74-2.1-6.68-4.92H1.3l-3.03v3.13C3.26 21.3 7.31 24 12 24z"/><path fill="#FBBC05" d="M5.32 14.33c-.24-.72-.38-1.49-.38-2.33s.14-1.61.38-2.33V6.54H1.3C.47 8.18 0 10.03 0 12s.47 3.82 1.3 5.46l4.02-3.13z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.3 6.54l4.02 3.13c.94-2.82 3.58-4.92 6.68-4.92z"/></svg> Entrar con Google</a>` : ''}
</div>
<div class="footer">Lexy Protect &copy; ${new Date().getFullYear()}</div></main></body></html>`);
}

const pend = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of pend) if (v.exp < n) pend.delete(k); }, 1e4).unref();

function serve(req, res, slug) {
  if (isBanned(req.cip)) return deny(res);
  if (isBrowser(req)) return landing(res, slug, req.base);
  const s = db.prepare('select id, enabled from scripts where slug=?').get(String(slug).toLowerCase());
  if (!s) return deny(res, 404);
  if (BOT_UA.test(req.headers['user-agent'] || '')) { db.prepare('update scripts set blocked=blocked+1 where id=?').run(s.id); strike(req.cip); return deny(res); }
  if (!s.enabled) return res.type('text/plain').set('Cache-Control', 'no-store').send('warn("[Lexy Protect] Este script está pausado por su dueño")');
  const r = db.prepare('insert into execs(script_id,ts,ip_hash,rbx_id,rbx_name,place) values(?,?,?,?,?,?)').run(s.id, Date.now(), hash(req.cip), '', '', '');
  const key = crypto.randomBytes(16), tok = crypto.randomBytes(18).toString('hex');
  pend.set(tok, { sid: s.id, eid: r.lastInsertRowid, key, exp: Date.now() + 30e3 });
  res.type('text/plain').set('Cache-Control', 'no-store').send(stub(key.toString('base64'), `${req.base}/s/${String(slug).toLowerCase()}/n/${tok}`));
}

app.get('/s/:slug/n/:tok', loadLim, (req, res) => {
  if (isBanned(req.cip)) return deny(res);
  const p = pend.get(req.params.tok); pend.delete(req.params.tok);
  const bad = !p || p.exp < Date.now() || isBrowser(req) || BOT_UA.test(req.headers['user-agent'] || '');
  const s = !bad && db.prepare('select id, enabled, content, slug from scripts where id=?').get(p.sid);
  if (bad || !s || !s.enabled || s.slug !== String(req.params.slug).toLowerCase()) { strike(req.cip); if (p) db.prepare('update scripts set blocked=blocked+1 where id=?').run(p.sid); return deny(res); }
  res.type('text/plain').set('Cache-Control', 'no-store').send('LX' + seal(`--[[lexy:${p.eid}]]\n${s.content}`, p.key));
});

app.use((req, res, next) => {
  if (BASE_DOMAIN && req.hostname.endsWith('.' + BASE_DOMAIN) && req.path === '/') {
    const sub = req.hostname.slice(0, -BASE_DOMAIN.length - 1);
    if (sub && sub !== 'www') return loadLim(req, res, () => serve(req, res, sub));
  }
  next();
});

app.get('/s/:slug', loadLim, (req, res) => serve(req, res, req.params.slug));

// Carga index.html o fallback si no existe
const HTML = ['index.html', 'public/index.html'].map((f) => path.join(__dirname, f)).find((f) => fs.existsSync(f));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => (HTML ? res.sendFile(HTML) : defaultIndex(req, res)));

app.get('/health', (req, res) => {
  try { db.prepare('select 1').get(); res.json({ ok: true, db: 'ok', persistente: !!(process.env.DB_PATH || VOL), url: BASE, google: !!OA.google.id, discord: !!OA.discord.id }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.use((err, req, res, next) => { console.error('[error]', err); res.status(err.status || 500).json({ error: 'Error del servidor: ' + (err.message || 'desconocido') }); });
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));

app.listen(PORT, () => console.log(`Lexy Protect en ${BASE} (puerto ${PORT}) · base: ${DB_FILE}`));
