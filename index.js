const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const BASE_DOMAIN = process.env.BASE_DOMAIN || ''; // opcional: habilita nombre.tudominio.com (requiere wildcard)
const STRICT = process.env.ANTI_HOOK === 'strict';
const PROD = BASE.startsWith('https');
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.JWT_SECRET) console.warn('[!] Define JWT_SECRET o las sesiones se cierran en cada reinicio.');
const MAX_SCRIPTS = 5;
const RESERVED = ['api', 'auth', 's', 'p', 'www', 'admin', 'lexy', 'login'];

const db = new Database(process.env.DB_PATH || 'lexy.db');
db.pragma('journal_mode = WAL');
db.exec(`
create table if not exists users(id integer primary key, username text unique collate nocase not null, email text unique collate nocase, pass text, provider text, pid text, created integer);
create table if not exists scripts(id integer primary key, user_id integer not null, slug text unique not null, content text not null, enabled integer default 1, blocked integer default 0, created integer);
create table if not exists execs(id integer primary key, script_id integer not null, ts integer, ip_hash text, rbx_id text, rbx_name text);
create index if not exists ix_ex on execs(script_id, ts);
create table if not exists bans(script_id integer, rbx_id text, primary key(script_id, rbx_id));
`);
try { db.exec('alter table execs add column place text'); } catch {}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], frameAncestors: ["'none'"],
  } },
}));
// Fuerza HTTPS en producción
app.use((req, res, next) => {
  if (PROD && req.headers['x-forwarded-proto'] === 'http') return res.redirect(301, BASE + req.originalUrl);
  next();
});
app.use(express.json({ limit: '600kb' }));
app.use(cookieParser());

const hash = (s) => crypto.createHash('sha256').update(s + SECRET).digest('hex').slice(0, 24);
const lim = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, message: { error: 'Demasiados intentos, esperá un momento' } });
const apiLim = lim(60e3, 120), authLim = lim(10 * 60e3, 20), loadLim = lim(60e3, 40);

/* ---------- Sesión ---------- */
const setSess = (res, u) => res.cookie('lx', jwt.sign({ id: u.id }, SECRET, { expiresIn: '14d' }), { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 14 * 864e5 });
const auth = (req, res, next) => {
  try {
    const p = jwt.verify(req.cookies.lx, SECRET);
    const u = db.prepare('select id, username, email from users where id=?').get(p.id);
    if (!u) throw 0;
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Iniciá sesión' }); }
};

/* ---------- Registro / login ---------- */
app.post('/api/register', lim(60 * 60e3, 6), authLim, (req, res) => {
  const { username, password, email } = req.body || {};
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Usuario: 3-20 letras, números o _' });
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) return res.status(400).json({ error: 'La contraseña debe tener 8-72 caracteres' });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Correo inválido' });
  if (db.prepare('select 1 from users where username=? or (email is not null and email=?)').get(username, email || null)) return res.status(409).json({ error: 'Usuario o correo ya registrado' });
  const r = db.prepare('insert into users(username,email,pass,created) values(?,?,?,?)').run(username, email || null, bcrypt.hashSync(password, 11), Date.now());
  setSess(res, { id: r.lastInsertRowid }); res.json({ ok: 1 });
});
app.post('/api/login', authLim, (req, res) => {
  const id = String(req.body?.id || ''), pw = String(req.body?.password || '');
  const u = db.prepare('select * from users where (username=? or email=?) and pass is not null').get(id, id);
  if (!u || !bcrypt.compareSync(pw, u.pass)) return res.status(401).json({ error: 'Datos incorrectos' });
  setSess(res, u); res.json({ ok: 1 });
});
app.post('/api/logout', (req, res) => { res.clearCookie('lx'); res.json({ ok: 1 }); });
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
  const st = crypto.randomBytes(16).toString('hex');
  res.cookie('lx_st', st, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 6e5 });
  res.redirect(o.auth + '?' + new URLSearchParams({ client_id: o.id, redirect_uri: `${BASE}/auth/${req.params.p}/callback`, response_type: 'code', scope: o.scope, state: st }));
});
app.get('/auth/:p/callback', authLim, async (req, res) => {
  const o = OA[req.params.p], fail = (m) => res.redirect('/?error=' + encodeURIComponent(m));
  try {
    if (!o || !req.query.code || req.query.state !== req.cookies.lx_st) return fail('Sesión de login inválida');
    res.clearCookie('lx_st');
    const t = await (await fetch(o.token, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: o.id, client_secret: o.secret, grant_type: 'authorization_code', code: req.query.code, redirect_uri: `${BASE}/auth/${req.params.p}/callback` }) })).json();
    if (!t.access_token) return fail('No se pudo iniciar sesión');
    const prof = o.map(await (await fetch(o.info, { headers: { Authorization: 'Bearer ' + t.access_token } })).json());
    let u = db.prepare('select * from users where provider=? and pid=?').get(req.params.p, String(prof.pid));
    if (!u) {
      let name = String(prof.name || 'user').replace(/[^a-zA-Z0-9_]/g, '').slice(0, 14) || 'user';
      while (db.prepare('select 1 from users where username=?').get(name)) name = name.slice(0, 14) + crypto.randomInt(100, 9999);
      const email = prof.email && !db.prepare('select 1 from users where email=?').get(prof.email) ? prof.email : null;
      const r = db.prepare('insert into users(username,email,provider,pid,created) values(?,?,?,?,?)').run(name, email, req.params.p, String(prof.pid), Date.now());
      u = { id: r.lastInsertRowid };
    }
    setSess(res, u); res.redirect('/');
  } catch (e) { console.error(e); fail('Error al iniciar sesión'); }
});

/* ---------- API de scripts ---------- */
const urlFor = (slug) => (BASE_DOMAIN ? `https://${slug}.${BASE_DOMAIN}` : `${BASE}/s/${slug}`);
const own = (req) => db.prepare('select * from scripts where id=? and user_id=?').get(req.params.id, req.user.id);

app.get('/api/scripts', apiLim, auth, (req, res) => {
  const rows = db.prepare(`select s.id, s.slug, s.enabled, s.blocked, s.created, length(s.content) size,
    (select max(ts) from execs where script_id=s.id) last,
    (select count(*) from execs where script_id=s.id) total
    from scripts s where user_id=? order by id desc`).all(req.user.id);
  res.json(rows.map((r) => ({ ...r, url: urlFor(r.slug), loadstring: `loadstring(game:HttpGet("${urlFor(r.slug)}"))()` })));
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

/* ---------- Estadísticas: total y por semanas ---------- */
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
const nonces = new Map(), strikes = new Map();
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of nonces) if (v.exp < n) nonces.delete(k);
  for (const [k, v] of strikes) if (v.until < n && v.n === 0) strikes.delete(k);
}, 30e3).unref();
// 6 intentos sospechosos = IP bloqueada 15 minutos
const isBanned = (ip) => (strikes.get(ip)?.until || 0) > Date.now();
const strike = (ip) => { const s = strikes.get(ip) || { n: 0, until: 0 }; if (++s.n >= 6) { s.until = Date.now() + 15 * 60e3; s.n = 0; } strikes.set(ip, s); };

const BOT_UA = /discord|bot\b|curl|wget|python|axios|node-fetch|undici|go-http|postman|insomnia|httpie|libwww|scrapy|headless|java\/|php|ruby|perl|spider|crawler|preview|telegram|whatsapp|slack|vercel|cloudflare|github|google|bing|yandex|facebook|twitter/i;
function suspicious(req) {
  const h = req.headers, ua = h['user-agent'] || '';
  if (h['sec-fetch-mode'] || h['sec-fetch-dest'] || h['sec-fetch-site'] || h['sec-ch-ua'] || h['upgrade-insecure-requests']) return true;
  if ((h.accept || '').includes('text/html')) return true;
  if (/mozilla/i.test(ua) && h['accept-language']) return true;
  if (h.origin || h.referer || h.cookie || h['x-forwarded-host'] === 'discord.com') return true;
  return BOT_UA.test(ua);
}
const deny = (res, code = 403) => res.status(code).type('html').send('<!doctype html><meta name="robots" content="noindex"><title>Lexy Protect</title><body style="background:#17101f;color:#efe8fb;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0"><p>Acceso denegado · Lexy Protect</p>');

// El cargador cambia en cada pedido: nombres aleatorios y textos como bytes
const rid = () => 'l' + crypto.randomBytes(5).toString('hex');
const bytes = (s) => 'string.char(' + [...Buffer.from(s)].join(',') + ')';
function stub(n) {
  const N = {};
  'P g bye ok r k d C T dec kb db out f hk nn U v b o x j t i y sp q w'.split(' ').forEach((v) => (N[v] = rid()));
  const lua = `local @P@ = game:GetService("Players").LocalPlayer
local @g@ = (getgenv and getgenv()) or _G
local function @bye@(m) pcall(function() @P@:Kick("Lexy Protect: " .. m) end) end
local @sp@ = false
pcall(function()
  for _, @v@ in ipairs({ @g@, _G, shared }) do
    for @q@, @w@ in pairs(@v@) do
      local @t@ = tostring(@q@):lower()
      if @t@:find("spy") or @t@:find("sniff") or @t@:find("hydroxide") or @t@:find("cobalt") or @t@:find("httplog") or (@t@:find("dump") and type(@w@) ~= "function") then @sp@ = true end
    end
  end
end)
if @sp@ then return @bye@("spy detectado") end
${STRICT ? `local function @hk@(f) return type(f) ~= "function" or (islclosure and islclosure(f)) end
if @hk@(loadstring) or @hk@(game.HttpGet) then return @bye@("entorno modificado") end` : ''}
local @nn@ = ${bytes(n)}
local @U@ = ${bytes(`${BASE}/p/${n}?i=`)}
local @ok@, @r@ = pcall(function() return game:HttpGet(@U@ .. @P@.UserId .. "&u=" .. @P@.Name .. "&pl=" .. game.PlaceId) end)
if not @ok@ or type(@r@) ~= "string" then return end
local @k@, @d@ = @r@:match("^([^.]+)%.(.+)$")
if not @k@ then return end
local @C@ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local @T@ = {} for @i@ = 1, 64 do @T@[@C@:byte(@i@)] = @i@ - 1 end
local function @dec@(s)
  local @o@, @x@, @v@, @b@ = {}, 0, 0, 0
  for @j@ = 1, #s do
    local @y@ = @T@[s:byte(@j@)]
    if @y@ then @v@ = @v@ * 64 + @y@; @b@ = @b@ + 6
      if @b@ >= 8 then @b@ = @b@ - 8; @x@ = @x@ + 1; @o@[@x@] = math.floor(@v@ / 2 ^ @b@); @v@ = @v@ % 2 ^ @b@ end
    end
  end
  return @o@
end
local @kb@, @db@, @out@ = @dec@(@k@), @dec@(@d@), {}
for @i@ = 1, 16 do @kb@[@i@] = bit32.bxor(@kb@[@i@], @nn@:byte((@i@ - 1) % #@nn@ + 1)) end
for @i@ = 1, #@db@, 4000 do
  local @t@ = {}
  for @j@ = @i@, math.min(@i@ + 3999, #@db@) do @t@[#@t@ + 1] = (bit32.bxor(@db@[@j@], @kb@[(@j@ - 1) % 16 + 1]) - (@j@ * 7) % 251) % 256 end
  @out@[#@out@ + 1] = string.char(table.unpack(@t@))
end
local @f@ = loadstring(table.concat(@out@))
@kb@, @db@, @out@, @k@, @d@, @r@ = nil, nil, nil, nil, nil, nil
if @f@ then @f@() end
`;
  return lua.replace(/@(\w+)@/g, (m, v) => N[v] || m);
}
// Cifra: suma por posición, XOR con clave de 16 bytes; la clave viaja XOR con el token
function seal(text, nonce) {
  const key = crypto.randomBytes(16), buf = Buffer.from(text, 'utf8');
  for (let i = 0; i < buf.length; i++) buf[i] = ((buf[i] + ((i + 1) * 7) % 251) & 255) ^ key[i % 16];
  const kx = Buffer.from(key.map((b, i) => b ^ nonce.charCodeAt(i % nonce.length)));
  return kx.toString('base64') + '.' + buf.toString('base64');
}

const isBrowser = (req) => { const h = req.headers; return !BOT_UA.test(h['user-agent'] || '') && !!(h['sec-fetch-mode'] || (h.accept || '').includes('text/html')); };
const he = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Página pública de cada script (como Luarmor): muestra el loadstring, nunca el código
function landing(res, slug) {
  slug = String(slug).toLowerCase();
  const r = db.prepare('select s.enabled, u.username owner, (select count(*) from execs where script_id=s.id) total from scripts s join users u on u.id=s.user_id where s.slug=?').get(slug);
  if (!r) return deny(res, 404);
  const ls = `loadstring(game:HttpGet("${urlFor(slug)}"))()`;
  res.status(200).type('html').set('Cache-Control', 'no-store').send(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${he(slug)} · Lexy Protect</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;700;800&family=JetBrains+Mono&display=swap" rel="stylesheet"><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.2rem;background:#130d1b;color:#f0e9fa;font:16px/1.55 'Bricolage Grotesque',system-ui,sans-serif}
.c{width:100%;max-width:560px;background:#1b1226;border:1px solid #34264a;border-radius:18px;padding:2rem}
.lg{display:flex;align-items:center;gap:.6rem;font-weight:800;color:#9a8cb3;font-size:.95rem;margin-bottom:1.6rem}.lg i{width:26px;height:26px;border-radius:7px;background:#ff6fae;display:grid;place-items:center}
h1{margin:0;font-size:2rem;letter-spacing:-.035em;font-weight:800;word-break:break-word}p{color:#9a8cb3;margin:.3rem 0 0}
code{display:block;margin:1.4rem 0 .8rem;background:#130d1b;border:1px solid #34264a;border-radius:10px;padding:.8rem 1rem;font:13px 'JetBrains Mono',monospace;color:#6fe3c1;overflow-x:auto;white-space:nowrap}
button{width:100%;border:0;border-radius:10px;padding:.8rem;background:#ff6fae;color:#2a0f1e;font:700 1rem inherit;font-family:inherit;cursor:pointer}button:hover{background:#ff8fc2}
.m{display:flex;justify-content:space-between;gap:1rem;margin-top:1.4rem;color:#9a8cb3;font-size:.9rem;flex-wrap:wrap}
.o{display:inline-flex;gap:.4rem;align-items:center;font-size:.85rem;border:1px solid #34264a;border-radius:999px;padding:.1rem .65rem;color:#9a8cb3;margin-top:.8rem}.o::before{content:"";width:7px;height:7px;border-radius:50%;background:${r.enabled ? '#6fe3c1' : '#ffc46b'}}
</style></head><body><main class="c"><div class="lg"><i><svg width="16" height="16" viewBox="0 0 24 24" fill="#130d1b"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg></i>Lexy Protect</div>
<h1>${he(slug)}</h1><p>Publicado por ${he(r.owner)}</p><span class="o">${r.enabled ? 'Activo' : 'Pausado por su dueño'}</span>
${r.enabled ? `<code id="c">${he(ls)}</code><button id="b">Copiar loadstring</button><p style="margin-top:1rem;font-size:.9rem">Pegalo en tu executor (Delta) y ejecutalo. El código del script está protegido y no se puede ver desde acá.</p>` : '<p style="margin-top:1.2rem">Este script no está disponible por ahora.</p>'}
<div class="m"><span>${Number(r.total).toLocaleString('es')} ejecuciones</span><span>Protegido por Lexy Protect</span></div></main>
<script>var b=document.getElementById('b');if(b)b.onclick=function(){navigator.clipboard.writeText(document.getElementById('c').textContent).then(function(){b.textContent='¡Copiado!';setTimeout(function(){b.textContent='Copiar loadstring'},1500)})}</script></body></html>`);
}

function serve(req, res, slug) {
  if (isBanned(req.ip)) return deny(res);
  if (isBrowser(req)) return landing(res, slug);
  const s = db.prepare('select id, enabled from scripts where slug=?').get(String(slug).toLowerCase());
  if (!s || !s.enabled) return deny(res, 404);
  if (suspicious(req)) { db.prepare('update scripts set blocked=blocked+1 where id=?').run(s.id); strike(req.ip); return deny(res); }
  const n = crypto.randomBytes(18).toString('base64url');
  nonces.set(n, { sid: s.id, ip: req.ip, ua: hash(req.headers['user-agent'] || ''), exp: Date.now() + 15e3 });
  res.type('text/plain').set('Cache-Control', 'no-store').send(stub(n));
}
// Subdominio opcional: nombre.BASE_DOMAIN
app.use((req, res, next) => {
  if (BASE_DOMAIN && req.hostname.endsWith('.' + BASE_DOMAIN) && req.path === '/') {
    const sub = req.hostname.slice(0, -BASE_DOMAIN.length - 1);
    if (sub && sub !== 'www') return loadLim(req, res, () => serve(req, res, sub));
  }
  next();
});
app.get('/s/:slug', loadLim, (req, res) => serve(req, res, req.params.slug));
app.get('/p/:n', loadLim, (req, res) => {
  if (isBanned(req.ip)) return deny(res);
  const n = nonces.get(req.params.n); nonces.delete(req.params.n); // un solo uso
  const uid = String(req.query.i || ''), un = String(req.query.u || ''), pl = String(req.query.pl || '');
  // Debe venir del mismo cliente (IP + User-Agent), a tiempo, y con los datos que manda el cargador real
  if (!n || n.exp < Date.now() || n.ip !== req.ip || n.ua !== hash(req.headers['user-agent'] || '') || suspicious(req) || !/^\d{1,15}$/.test(uid) || !/^\w{1,30}$/.test(un)) { strike(req.ip); return deny(res); }
  const s = db.prepare('select content from scripts where id=?').get(n.sid);
  if (!s) return deny(res, 404);
  const r = db.prepare('insert into execs(script_id,ts,ip_hash,rbx_id,rbx_name,place) values(?,?,?,?,?,?)').run(n.sid, Date.now(), hash(req.ip), uid, un, pl.replace(/\D/g, '').slice(0, 15));
  // Marca de agua: si el script se filtra, sabés qué ejecución fue
  const code = `--[[lexy:${r.lastInsertRowid}]]
${s.content}`;
  res.type('text/plain').set('Cache-Control', 'no-store').send(seal(code, req.params.n));
});

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`Lexy Protect en ${BASE} (puerto ${PORT})`));
