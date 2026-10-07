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
// URL pública: BASE_URL, o el dominio que Railway da solo (RAILWAY_PUBLIC_DOMAIN), o localhost
const BASE = (process.env.BASE_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : `http://localhost:${PORT}`)).replace(/\/$/, '');
const BASE_DOMAIN = process.env.BASE_DOMAIN || ''; // opcional: habilita nombre.tudominio.com (requiere wildcard)
const STRICT = process.env.ANTI_HOOK === 'strict';
const PROD = BASE.startsWith('https');
const MAX_SCRIPTS = 5, MAX_KEYS = 10;
// Link de invitación de tu Discord (ponelo en Railway como DISCORD_INVITE, ej. https://discord.gg/tuinvite)
const DC = (process.env.DISCORD_INVITE || 'https://discord.gg/qzeu6f8uG').trim();
const DSVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="#5865F2" aria-hidden="true"><path d="M20.317 4.37a19.8 19.8 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.74 19.74 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.1 13.1 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .078-.01c3.928 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .079.009c.12.099.246.198.373.292a.077.077 0 0 1-.006.127 12.3 12.3 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.095 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.095 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>';
const RESERVED = ['api', 'auth', 's', 'p', 'www', 'admin', 'lexy', 'login'];

// La base es un archivo SQLite que se crea sola: no hay que configurar nada.
// Si DB_PATH no se puede usar, cae a ./lexy.db
const VOL = process.env.RAILWAY_VOLUME_MOUNT_PATH; // Railway lo define solo si agregaste un Volume
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
for (const c of ['private integer default 0', 'skey text', 'key_ip text', 'key_at integer', 'key_uid text', 'lax integer default 0']) { try { db.exec('alter table scripts add column ' + c); } catch {} }
db.exec('create table if not exists meta(k text primary key, v text)');
// Secreto de sesiones: JWT_SECRET, o uno generado y guardado en la base (así las sesiones sobreviven a reinicios)
db.exec(`create table if not exists skeys(id integer primary key, script_id integer not null, k text unique not null, label text, key_ip text, key_uid text, key_at integer, lax integer default 0, enabled integer default 1, uses integer default 0, last integer, created integer);
create index if not exists ix_sk on skeys(script_id);`);
// migra las keys del modelo anterior (1 key por script) a la tabla nueva
for (const r of db.prepare('select id, skey, key_ip, key_uid, key_at, lax from scripts where private=1 and skey is not null and not exists (select 1 from skeys where script_id=scripts.id)').all())
  db.prepare('insert or ignore into skeys(script_id,k,label,key_ip,key_uid,key_at,lax,created) values(?,?,?,?,?,?,?,?)').run(r.id, r.skey, 'Key 1', r.key_ip, r.key_uid, r.key_at, r.lax || 0, Date.now());
const SECRET = process.env.JWT_SECRET || db.prepare("select v from meta where k='jwt'").get()?.v || (() => { const v = crypto.randomBytes(32).toString('hex'); db.prepare("insert into meta(k,v) values('jwt',?)").run(v); return v; })();

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
const BASE_ENV = process.env.BASE_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
app.use((req, res, next) => { req.cip = req.headers['x-real-ip'] || req.ip; const proto = String(req.headers['x-forwarded-proto'] || req.protocol).split(',')[0].trim(), host = String(req.headers['x-forwarded-host'] || req.get('host') || '').split(',')[0].trim();
  req.https = proto === 'https'; req.base = (host ? `${proto}://${host}` : BASE_ENV || BASE).replace(/\/$/, ''); next(); });
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], frameAncestors: ["'none'"],
  } },
}));
// Fuerza HTTPS en producción
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http' && !req.path.startsWith('/s/') && !/^(localhost|127\.)/.test(req.hostname)) return res.redirect(301, 'https://' + req.headers.host + req.originalUrl);
  next();
});
app.use(express.json({ limit: '600kb' }));
app.use(cookieParser());

const KA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
const genKey = () => Array.from({ length: 16 }, () => KA[crypto.randomInt(KA.length)]).join('');
const ipn = (ip) => String(ip || '').trim().replace(/^::ffff:/i, '').toLowerCase();
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
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
    if (p.iat && Date.now() / 1000 - p.iat > 86400) setSess(req, res, u); // renueva: la sesión se mantiene mientras uses la web
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Iniciá sesión' }); }
};

/* ---------- Registro / login ---------- */
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
app.get('/api/providers', (req, res) => res.json({ google: !!OA.google.id, discord: !!OA.discord.id, invite: DC }));
app.get('/auth/:p', authLim, (req, res) => {
  const o = OA[req.params.p];
  if (!o) return res.redirect('/?error=' + encodeURIComponent('Método de login desconocido'));
  if (!o.id || !o.secret) return res.redirect('/?error=' + encodeURIComponent(`Falta configurar ${req.params.p.toUpperCase()}_CLIENT_ID y ${req.params.p.toUpperCase()}_CLIENT_SECRET en Railway`));
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
    if (!t.access_token) { console.error('[oauth]', req.params.p, tr.status, JSON.stringify(t), 'redirect_uri=', `${req.base}/auth/${req.params.p}/callback`); return fail('No se pudo iniciar sesión' + (t.error ? ` (${t.error})` : '')); }
    const pr = await fetch(o.info, { headers: { ...UA, Authorization: 'Bearer ' + t.access_token } });
    const pj = await pr.json().catch(() => ({}));
    const prof = o.map(pj);
    if (!prof.pid) { console.error('[oauth] perfil inválido', pr.status, JSON.stringify(pj)); return fail('No se pudo leer tu perfil'); }
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

/* ---------- API de scripts ---------- */
const urlFor = (slug, base = BASE) => (BASE_DOMAIN ? `https://${slug}.${BASE_DOMAIN}` : `${base}/s/${slug}`);
const own = (req) => db.prepare('select * from scripts where id=? and user_id=?').get(req.params.id, req.user.id);

app.get('/api/scripts', apiLim, auth, (req, res) => {
  const rows = db.prepare(`select s.id, s.slug, s.enabled, s.blocked, s.created, length(s.content) size, s.private,
    (select max(ts) from execs where script_id=s.id) last,
    (select count(*) from execs where script_id=s.id) total
    from scripts s where user_id=? order by id desc`).all(req.user.id);
  const ks = {}; db.prepare('select id, script_id, k, label, (key_ip is not null) bound, key_at, lax, enabled, uses, last from skeys where script_id in (select id from scripts where user_id=?) order by id').all(req.user.id).forEach((k) => (ks[k.script_id] ||= []).push(k));
  res.json(rows.map((r) => ({ ...r, keys: ks[r.id] || [], url: urlFor(r.slug, req.base), loadstring: (r.private ? `script_key="${ks[r.id]?.[0]?.k || 'TU_KEY'}"; ` : '') + `loadstring(game:HttpGet("${urlFor(r.slug, req.base)}"))()` })));
});
app.post('/api/scripts', apiLim, auth, (req, res) => {
  const slug = String(req.body?.name || '').toLowerCase(), content = req.body?.content;
  if (!/^[a-z0-9-]{3,24}$/.test(slug) || RESERVED.includes(slug)) return res.status(400).json({ error: 'Nombre: 3-24 caracteres, minúsculas, números o guiones' });
  if (typeof content !== 'string' || !content.trim() || content.length > 500000) return res.status(400).json({ error: 'El script está vacío o pesa más de 500 KB' });
  if (db.prepare('select count(*) c from scripts where user_id=?').get(req.user.id).c >= MAX_SCRIPTS) return res.status(403).json({ error: `Llegaste al límite de ${MAX_SCRIPTS} scripts` });
  if (db.prepare('select 1 from scripts where slug=?').get(slug)) return res.status(409).json({ error: 'Ese nombre ya está en uso' });
  const priv = req.body?.private === true;
  const ri = db.prepare('insert into scripts(user_id,slug,content,created,private) values(?,?,?,?,?)').run(req.user.id, slug, content, Date.now(), priv ? 1 : 0);
  if (priv) db.prepare('insert into skeys(script_id,k,label,created) values(?,?,?,?)').run(ri.lastInsertRowid, genKey(), 'Key 1', Date.now());
  res.json({ ok: 1 });
});
app.patch('/api/scripts/:id', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  const { content, enabled, private: pr } = req.body || {};
  if (typeof content === 'string') {
    if (!content.trim() || content.length > 500000) return res.status(400).json({ error: 'Script inválido' });
    db.prepare('update scripts set content=? where id=?').run(content, s.id);
  }
  if (typeof enabled === 'boolean') db.prepare('update scripts set enabled=? where id=?').run(enabled ? 1 : 0, s.id);
  if (typeof pr === 'boolean') { db.prepare('update scripts set private=? where id=?').run(pr ? 1 : 0, s.id); if (pr && !db.prepare('select 1 from skeys where script_id=?').get(s.id)) db.prepare('insert into skeys(script_id,k,label,created) values(?,?,?,?)').run(s.id, genKey(), 'Key 1', Date.now()); }
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
  res.json({ ...weekStats('script_id=?', s.id), blocked: s.blocked, recent: db.prepare("select rbx_id, max(ts) ts from execs where script_id=? and rbx_id!='' group by rbx_id order by max(id) desc limit 8").all(s.id), bans: db.prepare('select rbx_id from bans where script_id=?').all(s.id) });
});

const ownKey = (req) => { const s = own(req); return { s, k: s && db.prepare('select * from skeys where id=? and script_id=?').get(req.params.kid, s.id) }; };
app.post('/api/scripts/:id/keys', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  if (!s.private) return res.status(400).json({ error: 'Hacé el script privado primero' });
  const n = db.prepare('select count(*) c from skeys where script_id=?').get(s.id).c;
  if (n >= MAX_KEYS) return res.status(403).json({ error: `Máximo ${MAX_KEYS} keys por script` });
  const label = String(req.body?.label || '').trim().slice(0, 30) || `Key ${n + 1}`;
  db.prepare('insert into skeys(script_id,k,label,created) values(?,?,?,?)').run(s.id, genKey(), label, Date.now()); res.json({ ok: 1 });
});
app.patch('/api/scripts/:id/keys/:kid', apiLim, auth, (req, res) => {
  const { k } = ownKey(req); if (!k) return res.status(404).json({ error: 'No existe' });
  const b = req.body || {}, v = typeof b.set_ip === 'string' ? b.set_ip.trim() : null;
  if (typeof b.key === 'string' && b.key !== k.k) {
    if (!/^[A-Za-z0-9_-]{6,40}$/.test(b.key)) return res.status(400).json({ error: 'Key: 6-40 caracteres (letras, números, _ o -)' });
    if (db.prepare('select 1 from skeys where k=?').get(b.key)) return res.status(409).json({ error: 'Esa key ya existe' });
  }
  if (v && !/^[0-9a-fA-F:.]{3,45}$/.test(v)) return res.status(400).json({ error: 'IP inválida' });
  if (typeof b.label === 'string') db.prepare('update skeys set label=? where id=?').run(b.label.trim().slice(0, 30), k.id);
  if (typeof b.key === 'string' && b.key !== k.k) db.prepare('update skeys set k=? where id=?').run(b.key, k.id);
  if (typeof b.enabled === 'boolean') db.prepare('update skeys set enabled=? where id=?').run(b.enabled ? 1 : 0, k.id);
  if (typeof b.lax === 'boolean') db.prepare('update skeys set lax=? where id=?').run(b.lax ? 1 : 0, k.id);
  if (b.reset_ip === true || v === '') db.prepare('update skeys set key_ip=null, key_uid=null, key_at=null where id=?').run(k.id);
  else if (v) db.prepare('update skeys set key_ip=?, key_at=? where id=?').run(hash(ipn(v)), Date.now(), k.id);
  res.json({ ok: 1 });
});
app.delete('/api/scripts/:id/keys/:kid', apiLim, auth, (req, res) => {
  const { k } = ownKey(req); if (!k) return res.status(404).json({ error: 'No existe' });
  db.prepare('delete from skeys where id=?').run(k.id); res.json({ ok: 1 });
});
app.post('/api/scripts/:id/ban', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  const u = String(req.body?.rbx_id || ''); if (!/^\d{1,12}$/.test(u)) return res.status(400).json({ error: 'UserId inválido' });
  db.prepare('insert or ignore into bans(script_id,rbx_id) values(?,?)').run(s.id, u); res.json({ ok: 1 });
});
app.delete('/api/scripts/:id/ban/:u', apiLim, auth, (req, res) => {
  const s = own(req); if (!s) return res.status(404).json({ error: 'No existe' });
  db.prepare('delete from bans where script_id=? and rbx_id=?').run(s.id, String(req.params.u)); res.json({ ok: 1 });
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

/* ---------- Loader protegido (una sola petición, sin tokens ni claves) ---------- */
const strikes = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of strikes) if (v.t < n - 864e5) strikes.delete(k); }, 6e4).unref();
// 6 intentos de bots = IP bloqueada 15 minutos (solo bots conocidos, nunca executors)
const isBanned = (ip) => (strikes.get(ip)?.until || 0) > Date.now();
const strike = (ip) => { const s = strikes.get(ip) || { n: 0, until: 0, t: 0 }; s.t = Date.now(); if (++s.n >= 6) { s.b = (s.b || 0) + 1; s.until = Date.now() + Math.min(24 * 36e5, 15 * 60e3 * 2 ** (s.b - 1)); s.n = 0; } strikes.set(ip, s); };

// Solo se bloquean bots/herramientas claramente identificadas: así Delta y cualquier executor pasan
const BOT_UA = /discord|telegrambot|whatsapp|slackbot|facebookexternalhit|twitterbot|googlebot|bingbot|yandex|baiduspider|curl|wget|python|aiohttp|axios|node-fetch|undici|go-http|postman|insomnia|httpie|libwww|scrapy|headless|phantomjs|puppeteer|playwright|spider|crawler|\bbot\b/i;
// Navegador = lo que abre el link a mano: ve la página con el loadstring, nunca el código
const isBrowser = (req) => { const h = req.headers; return !BOT_UA.test(h['user-agent'] || '') && !!(h['sec-fetch-mode'] || h['sec-fetch-dest'] || (h.accept || '').includes('text/html')); };
const deny = (res, code = 403) => res.status(code).type('html').send('<!doctype html><meta name="robots" content="noindex"><title>Lexy Protect</title><body style="background:#17101f;color:#efe8fb;font:16px system-ui;display:grid;place-items:center;height:100vh;margin:0"><p>Acceso denegado · Lexy Protect</p>');

const rid = () => 'l' + crypto.randomBytes(5).toString('hex');
// Etapa 1 (cargador, distinto en cada pedido): puntúa el entorno (anti-spy/anti-hook), trae la etapa 2 y descifra.
// Si el puntaje es alto NO expulsa: pide un señuelo, así un dumper se queda con código falso.
function stub(k, url) {
  const N = {};
  'P g bad chk w v q o k C T dec kb db out f i j x y t u r s h ky sc ks nx ka kz kc kd tt'.split(' ').forEach((v) => (N[v] = rid()));
  const lua = `local @P@ = game:GetService("Players").LocalPlayer
local @g@ = (getgenv and getgenv()) or _G
local @bad@ = {"httpspy","simplespy","remotespy","hydroxide","cobaltspy","dumper","httpdebug","networkspy","unveilr","deobf","sniffer","hookspy","scriptlogger","fiddler","wireshark"}
local function @chk@(s) s = tostring(s):lower() for _, @w@ in ipairs(@bad@) do if s:find(@w@, 1, true) then return true end end return false end
local @sc@ = 0
pcall(function() for _, @v@ in ipairs({ @g@, _G, shared }) do for @q@ in pairs(@v@) do if @chk@(@q@) then @sc@ = @sc@ + 3 end end end end)
pcall(function() for _, @v@ in ipairs({ game:GetService("CoreGui"), (gethui and gethui()) or game:GetService("CoreGui") }) do for _, @o@ in ipairs(@v@:GetChildren()) do if @chk@(@o@.Name) then @sc@ = @sc@ + 3 end end end end)
pcall(function() if game.HttpGet ~= game.HttpGet then @sc@ = @sc@ + 1 end end)
pcall(function() if type(loadstring) ~= "function" or type(game.HttpGet) ~= "function" then @sc@ = @sc@ + 1 end end)
${STRICT ? `pcall(function() if islclosure and (islclosure(loadstring) or islclosure(game.HttpGet)) then @sc@ = @sc@ + 3 end end)` : ''}
if @sc@ >= 3 then warn("[Lexy Protect] entorno no confiable") end
local @k@, @u@, @r@ = "${k}", "${url}", nil
local @ky@ = (tostring((getgenv and getgenv().script_key) or _G.script_key or ""):gsub("[^%w_%-]", ""))
local @t@ = @u@ .. "?u=" .. tostring(@P@.UserId) .. "&k=" .. @ky@ .. "&s=" .. @sc@
pcall(function() @r@ = game:HttpGet(@t@) end)
if type(@r@) ~= "string" then pcall(function() local @q@ = request or http_request or (syn and syn.request); if @q@ then @r@ = @q@({ Url = @t@, Method = "GET" }).Body end end) end
if type(@r@) == "string" and @r@:sub(1, 2) == "ER" then return warn("[Lexy Protect] " .. @r@:sub(3)) end
if type(@r@) ~= "string" or #@r@ < 11 or @r@:sub(1, 2) ~= "LX" then return warn("[Lexy Protect] no se pudo cargar el script") end
local @s@ = @r@:sub(11)
local @h@ = 5381
for @i@ = 1, #@s@ do @h@ = (@h@ * 33 + @s@:byte(@i@)) % 4294967296 end
if string.format("%08x", @h@) ~= @r@:sub(3, 10) then return warn("[Lexy Protect] integridad inválida (anti-tamper)") end
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
local function @ks@(@kb@)
  local @ka@ = bit32.bxor(@kb@[1] * 16777216 + @kb@[2] * 65536 + @kb@[3] * 256 + @kb@[4], 2654435769)
  local @kz@ = @kb@[5] * 16777216 + @kb@[6] * 65536 + @kb@[7] * 256 + @kb@[8]
  local @kc@ = @kb@[9] * 16777216 + @kb@[10] * 65536 + @kb@[11] * 256 + @kb@[12]
  local @kd@ = @kb@[13] * 16777216 + @kb@[14] * 65536 + @kb@[15] * 256 + @kb@[16]
  local function @nx@()
    local @tt@ = bit32.bxor(@ka@, bit32.lshift(@ka@, 11))
    @ka@, @kz@, @kc@ = @kz@, @kc@, @kd@
    @kd@ = bit32.bxor(bit32.bxor(@kd@, bit32.rshift(@kd@, 19)), bit32.bxor(@tt@, bit32.rshift(@tt@, 8)))
    return bit32.band(bit32.rshift(@kd@, 8), 255)
  end
  for _ = 1, 16 do @nx@() end
  return @nx@
end
local @db@, @f@ = @dec@(@s@), {}
local @nx@ = @ks@(@dec@(@k@))
for @i@ = 1, #@db@, 4000 do
  local @q@ = {}
  for @j@ = @i@, math.min(@i@ + 3999, #@db@) do @q@[#@q@ + 1] = bit32.bxor(@db@[@j@], @nx@()) end
  @f@[#@f@ + 1] = string.char(table.unpack(@q@))
end
local @o@ = loadstring(table.concat(@f@))
@db@, @f@, @k@, @s@, @r@ = nil, nil, nil, nil, nil
if @o@ then @o@() end
`;
  return lua.replace(/@(\w+)@/g, (m, v) => N[v] || m);
}
// Cifrado de flujo (xorshift128 sembrado con la clave de 16 bytes de cada pedido)
function seal(text, key) {
  let [a, b, c, d] = [0, 4, 8, 12].map((i) => key.readUInt32BE(i)); a = (a ^ 0x9E3779B9) >>> 0;
  const nx = () => { const t = (a ^ (a << 11)) >>> 0; a = b; b = c; c = d; d = (d ^ (d >>> 19) ^ t ^ (t >>> 8)) >>> 0; return (d >>> 8) & 255; };
  for (let i = 0; i < 16; i++) nx();
  const buf = Buffer.from(text, 'utf8');
  for (let i = 0; i < buf.length; i++) buf[i] ^= nx();
  return buf.toString('base64');
}
// Marca de agua invisible (ceros/unos con caracteres de ancho cero dentro de un comentario) con el ID de ejecución
const wm = (id) => '--' + Number(id).toString(2).replace(/0/g, '\u200b').replace(/1/g, '\u200c');

const he = (t) => String(t).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
// Página pública de cada script (como Luarmor): muestra el loadstring, nunca el código
function landing(res, slug, base) {
  slug = String(slug).toLowerCase();
  const r = db.prepare('select s.enabled, s.private, u.username owner, (select count(*) from execs where script_id=s.id) total from scripts s join users u on u.id=s.user_id where s.slug=?').get(slug);
  if (!r) return deny(res, 404);
  const ls = (r.private ? 'script_key="TU_KEY"; ' : '') + `loadstring(game:HttpGet("${urlFor(slug, base)}"))()`;
  res.status(200).type('html').set('Cache-Control', 'no-store').send(`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${he(slug)} · Lexy Protect</title>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@400;700;800&family=JetBrains+Mono&display=swap" rel="stylesheet"><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.2rem;background:#130d1b;color:#f0e9fa;font:16px/1.55 'Bricolage Grotesque',system-ui,sans-serif}
.c{width:100%;max-width:560px;background:#1b1226;border:1px solid #34264a;border-radius:18px;padding:2rem}
.lg{display:flex;align-items:center;gap:.6rem;font-weight:800;color:#9a8cb3;font-size:.95rem;margin-bottom:1.6rem}.lg i{width:26px;height:26px;border-radius:7px;background:#ff6fae;display:grid;place-items:center}
h1{margin:0;font-size:2rem;letter-spacing:-.035em;font-weight:800;word-break:break-word}p{color:#9a8cb3;margin:.3rem 0 0}
code{display:block;margin:1.4rem 0 .8rem;background:#130d1b;border:1px solid #34264a;border-radius:10px;padding:.8rem 1rem;font:13px 'JetBrains Mono',monospace;color:#6fe3c1;overflow-x:auto;white-space:nowrap}
button{width:100%;border:0;border-radius:10px;padding:.8rem;background:#ff6fae;color:#2a0f1e;font:700 1rem inherit;font-family:inherit;cursor:pointer}button:hover{background:#ff8fc2}
.m{display:flex;justify-content:space-between;gap:1rem;margin-top:1.4rem;color:#9a8cb3;font-size:.9rem;flex-wrap:wrap}
.dl{display:flex;align-items:center;gap:.5rem;margin-top:1.2rem;color:#4da3ff;text-decoration:underline;word-break:break-all;font-size:.92rem}
.o{display:inline-flex;gap:.4rem;align-items:center;font-size:.85rem;border:1px solid #34264a;border-radius:999px;padding:.1rem .65rem;color:#9a8cb3;margin-top:.8rem}.o::before{content:"";width:7px;height:7px;border-radius:50%;background:${r.enabled ? '#6fe3c1' : '#ffc46b'}}
</style></head><body><main class="c"><div class="lg"><i><svg width="16" height="16" viewBox="0 0 24 24" fill="#130d1b"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg></i>Lexy Protect</div>
<h1>${he(slug)}</h1><p>Publicado por ${he(r.owner)}</p><span class="o">${r.enabled ? 'Activo' : 'Pausado por su dueño'}</span>
${r.enabled ? `<code id="c">${he(ls)}</code><button id="b">Copiar loadstring</button><p style="margin-top:1rem;font-size:.9rem">${r.private ? 'Script privado: reemplazá TU_KEY por tu key. ' : ''}Pegalo en tu executor (Delta) y ejecutalo. El código del script está protegido y no se puede ver desde acá.</p>` : '<p style="margin-top:1.2rem">Este script no está disponible por ahora.</p>'}
<div class="m"><span>${Number(r.total).toLocaleString('es')} ejecuciones</span><span>Protegido por Lexy Protect</span></div>${DC ? `<a class="dl" id="dl" href="${he(DC)}">${DSVG}<span>${he(DC.replace(/^https?:\/\//, ''))}</span></a>` : ''}</main>
<script>var b=document.getElementById('b');if(b)b.onclick=function(){navigator.clipboard.writeText(document.getElementById('c').textContent).then(function(){b.textContent='¡Copiado!';setTimeout(function(){b.textContent='Copiar loadstring'},1500)})}var dl=document.getElementById('dl');if(dl)dl.onclick=function(e){e.preventDefault();var t=dl.getAttribute('href'),s=dl.querySelector('span'),o=s.textContent,ok=function(){s.textContent='¡Link copiado!';setTimeout(function(){s.textContent=o},1500)};(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(ok,function(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();try{document.execCommand('copy');ok()}catch(x){}a.remove()})};</script></body></html>`);
}

const pend = new Map(); // token -> { sid, key, exp }  (un solo uso)
setInterval(() => { const n = Date.now(); for (const [k, v] of pend) if (v.exp < n) pend.delete(k); }, 1e4).unref();
function serve(req, res, slug) {
  if (isBanned(req.cip)) return deny(res);
  if (isBrowser(req)) return landing(res, slug, req.base);
  const s = db.prepare('select id, enabled, private from scripts where slug=?').get(String(slug).toLowerCase());
  if (!s) return deny(res, 404);
  if (BOT_UA.test(req.headers['user-agent'] || '')) { db.prepare('update scripts set blocked=blocked+1 where id=?').run(s.id); strike(req.cip); return deny(res); }
  if (!s.enabled) return res.type('text/plain').set('Cache-Control', 'no-store').send('warn("[Lexy Protect] Este script está pausado por su dueño")');
  const r = s.private ? { lastInsertRowid: 0 } : db.prepare('insert into execs(script_id,ts,ip_hash,rbx_id,rbx_name,place) values(?,?,?,?,?,?)').run(s.id, Date.now(), hash(req.cip), '', '', ''); // los privados cuentan al validar la key
  const key = crypto.randomBytes(16), tok = crypto.randomBytes(18).toString('hex');
  pend.set(tok, { sid: s.id, eid: r.lastInsertRowid, key, exp: Date.now() + 30e3 });
  res.type('text/plain').set('Cache-Control', 'no-store').send(stub(key.toString('base64'), `${req.base}/s/${String(slug).toLowerCase()}/n/${tok}`));
}
// Etapa 2: el código cifrado solo sale con un token válido, de un solo uso y que dura 30 s.
// Un volcado de la etapa 1 no trae el código, y repetir la petición después falla.
app.get('/s/:slug/n/:tok', loadLim, (req, res) => {
  if (isBanned(req.cip)) return deny(res);
  const p = pend.get(req.params.tok); pend.delete(req.params.tok);
  const bad = !p || p.exp < Date.now() || isBrowser(req) || BOT_UA.test(req.headers['user-agent'] || '');
  const s = !bad && db.prepare('select id, enabled, content, slug, private from scripts where id=?').get(p.sid);
  if (bad || !s || !s.enabled || s.slug !== String(req.params.slug).toLowerCase()) { strike(req.cip); if (p) db.prepare('update scripts set blocked=blocked+1 where id=?').run(p.sid); return deny(res); }
  const er = (m) => res.type('text/plain').set('Cache-Control', 'no-store').send('ER' + m);
  const uid = /^\d{1,12}$/.test(String(req.query.u || '')) ? String(req.query.u) : '';
  if (uid && db.prepare('select 1 from bans where script_id=? and rbx_id=?').get(s.id, uid)) return er('Tu cuenta está bloqueada en este script');
  if (s.private) {
    const kk = String(req.query.k || ''), K = /^[A-Za-z0-9_-]{1,64}$/.test(kk) ? db.prepare('select * from skeys where script_id=? and k=?').get(s.id, kk) : null;
    if (!K) { strike(req.cip); return er('Key inválida o faltante. Usá: script_key="TU_KEY"; loadstring(...)()'); }
    if (!K.enabled) return er('Esta key está desactivada');
    const ih = hash(ipn(req.cip));
    if (K.key_ip && K.key_ip !== ih && K.key_ip !== hash(req.cip)) {
      // modo "misma cuenta": si cambió la IP pero es el mismo UserId que la reclamó, la key lo sigue
      if (K.lax && uid && K.key_uid && uid === K.key_uid) db.prepare('update skeys set key_ip=? where id=?').run(ih, K.id);
      else return er('Esta key ya fue reclamada por otra IP. Pedile al dueño que la reinicie.');
    } else if (!K.key_ip) db.prepare('update skeys set key_ip=?, key_uid=?, key_at=? where id=?').run(ih, uid, Date.now(), K.id); // la reclama el primero que la usa
    db.prepare('update skeys set uses=uses+1, last=? where id=?').run(Date.now(), K.id);
  }
  if (!p.eid) p.eid = db.prepare('insert into execs(script_id,ts,ip_hash,rbx_id,rbx_name,place) values(?,?,?,?,?,?)').run(s.id, Date.now(), hash(req.cip), '', '', '').lastInsertRowid;
  if (uid) db.prepare('update execs set rbx_id=? where id=?').run(uid, p.eid); // anti-skid: queda registrado quién lo ejecutó
  const decoy = Number(req.query.s) >= 3; // entorno con spy/dumper: se entrega un señuelo
  if (decoy) db.prepare('update scripts set blocked=blocked+1 where id=?').run(s.id);
  const src = decoy ? 'print("[Lexy Protect] entorno no confiable: el script no se ejecutó")' : s.content;
  const body = seal(`--[[lexy:${p.eid}]]\n${src}\n${wm(p.eid)}`, p.key);
  let ck = 5381; for (let i = 0; i < body.length; i++) ck = (ck * 33 + body.charCodeAt(i)) % 4294967296;
  res.type('text/plain').set('Cache-Control', 'no-store').send('LX' + ck.toString(16).padStart(8, '0') + body);
});
// Subdominio opcional: nombre.BASE_DOMAIN
app.use((req, res, next) => {
  if (BASE_DOMAIN && req.hostname.endsWith('.' + BASE_DOMAIN) && req.path === '/') {
    const sub = req.hostname.slice(0, -BASE_DOMAIN.length - 1);
    if (sub && sub !== 'www') return loadLim(req, res, () => serve(req, res, sub));
  }
  next();
});
app.get('/s/:slug', loadLim, (req, res) => serve(req, res, req.params.slug));

// La web: index.html en la raíz (también acepta public/index.html)
const HTML = ['index.html', 'public/index.html'].map((f) => path.join(__dirname, f)).find((f) => fs.existsSync(f));
if (!HTML) console.error('[!] No encuentro index.html. Tiene que estar en la raíz del repo, al lado de index.js.');
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => (HTML ? res.sendFile(HTML) : res.status(500).type('text').send('Falta el archivo index.html en tu repo de GitHub. Subilo en la raíz, al lado de index.js.')));
// Diagnóstico rápido: abrí /health en tu link para ver si el servidor y la base andan
app.get('/health', (req, res) => {
  try { db.prepare('select 1').get(); res.json({ ok: true, redirect_uris: { discord: `${req.base}/auth/discord/callback`, google: `${req.base}/auth/google/callback` }, invite: !!DC, db: 'ok', persistente: !!(process.env.DB_PATH || VOL), url: BASE, google: !!OA.google.id, discord: !!OA.discord.id }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});
app.use((err, req, res, next) => { console.error('[error]', err); res.status(err.status || 500).json({ error: 'Error del servidor: ' + (err.message || 'desconocido') }); });
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
app.listen(PORT, () => console.log(`Lexy Protect en ${BASE} (puerto ${PORT}) · base: ${DB_FILE}`));
