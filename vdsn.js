// V.D.S.N: the whole site in one file.
// Run:  node vdsn.js     then open http://localhost:3000
// Needs Node.js 16+. No packages to install. Data is saved in a "data" folder next to this file.

const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SHARED = process.env.SHARED_PASSWORD ||
  'GevijypAlexCsyPssoMrxs';

const DATA = path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
const read = (n, d) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, n), 'utf8')); } catch { return d; } };
const write = (n, v) => fs.writeFileSync(path.join(DATA, n), JSON.stringify(v, null, 2));

// ---------- helpers ----------
const sha = s => crypto.createHash('sha256').update(s).digest();
const sameStr = (a, b) => crypto.timingSafeEqual(sha(String(a)), sha(String(b)));
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const checkPw = (pw, stored) => {
  const [salt, h] = stored.split(':');
  const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};
const html = (res, page) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(page); };
const readBody = req => new Promise(r => {
  let s = '';
  req.on('data', c => { s += c; if (s.length > 10000) req.destroy(); });
  req.on('end', () => { try { r(JSON.parse(s || '{}')); } catch { r({}); } });
});
const cookie = (req, name) => {
  const m = new RegExp('(?:^|; )' + name + '=([a-f0-9]+)').exec(req.headers.cookie || '');
  return m && m[1];
};
const YEAR = 31536000;
const setCookie = (req, name, val, age) =>
  name + '=' + val + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + age +
  (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '');

// ---------- saved state (survives restarts, so people stay remembered) ----------
const store = read('sessions.json', { gates: [], sessions: {} });
const saveStore = () => write('sessions.json', store);
const sessionUser = req => { const t = cookie(req, 'sid'); return t && store.sessions[t]; };
const gateOpen = req => { const t = cookie(req, 'gate'); return !!t && store.gates.includes(t); };

const fails = new Map(); // rate limit by ip
const blocked = ip => { const f = fails.get(ip); return f && f.until > Date.now(); };
const fail = ip => { const n = ((fails.get(ip) || {}).n || 0) + 1; fails.set(ip, { n, until: n >= 5 ? Date.now() + 60000 : 0 }); };

function logEvent(username, action, ok) {
  const log = read('logins.json', []);
  log.unshift({ username: String(username).slice(0, 40), action, success: ok, time: new Date().toISOString() });
  write('logins.json', log.slice(0, 1000)); // passwords are never stored here
}
const cleanUrl = u => { try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x.href : null; } catch { return null; } };

// ---------- pages ----------
const STYLE = `
:root{--bg:#050505;--panel:#161616;--red:#ff2b3a;--dim:#a01822}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--red);font-family:'Courier New',monospace;min-height:100vh}
h1,h2,p,label,span,a,button,input,div,strong,th,td{color:var(--red)}
a{text-decoration:none}
button{background:#000;border:1px solid var(--red);padding:9px 14px;font-family:inherit;cursor:pointer;border-radius:6px}
button:hover{background:var(--red);color:#000}
input{background:#000;border:1px solid var(--dim);padding:10px;font-family:inherit;border-radius:6px;width:100%;margin:6px 0 14px;outline:none}
input:focus{border-color:var(--red);box-shadow:0 0 8px var(--dim)}
input::placeholder{color:var(--dim)}
.hidden{display:none!important}
`;

const MAIN_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>V.D.S.N</title>
<style>${STYLE}
.box{max-width:360px;margin:16vh auto 0;padding:28px;background:var(--panel);border:1px solid var(--dim);border-radius:12px}
.logo{font-size:44px;letter-spacing:6px;text-align:center;margin:0 0 22px;text-shadow:0 0 14px var(--dim)}
.err{min-height:20px;margin-bottom:10px}
.row{display:flex;gap:8px}.row button{flex:1}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--dim)}
header nav{display:flex;gap:16px;align-items:center}
#grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:18px;padding:24px 20px}
.tile{position:relative;height:160px;background:var(--panel);border:1px solid #222;border-radius:10px;cursor:pointer;display:flex;align-items:flex-end;padding:14px;font-weight:bold;transition:.15s}
.tile:hover{border-color:var(--red);box-shadow:0 0 14px rgba(255,43,58,.35)}
.tile .x{position:absolute;top:6px;right:6px;padding:2px 8px;font-size:12px;opacity:.5}
.tile:hover .x{opacity:1}
.add{justify-content:center;align-items:center;border:2px dashed var(--dim);background:transparent;font-size:34px}
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;z-index:10}
.win{width:min(1100px,94vw);height:86vh;background:var(--panel);border:1px solid var(--red);border-radius:10px;display:flex;flex-direction:column;box-shadow:0 0 30px rgba(255,43,58,.4)}
.bar{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--dim)}
.bar div{display:flex;gap:8px}
iframe{flex:1;border:0;background:#fff;border-radius:0 0 10px 10px}
.note{padding:6px 14px;font-size:12px;opacity:.7}
.form{width:min(380px,92vw);padding:24px;background:var(--panel);border:1px solid var(--red);border-radius:10px}
</style></head><body>

<div id="gate" class="box hidden">
  <h1 class="logo">V.D.S.N</h1>
  <label>Shared password</label>
  <input id="sp" type="password" placeholder="shared password" autocomplete="off">
  <div class="err" id="gerr"></div>
  <button id="gbtn" style="width:100%">CONTINUE</button>
</div>

<div id="acct" class="box hidden">
  <h1 class="logo" style="font-size:30px">V.D.S.N</h1>
  <label>Username</label><input id="u" autocomplete="username" placeholder="username">
  <label>Password</label><input id="p" type="password" autocomplete="current-password" placeholder="password">
  <div class="err" id="aerr"></div>
  <div class="row"><button id="login">LOG IN</button><button id="signup">CREATE ACCOUNT</button></div>
  <p style="font-size:12px;margin-bottom:0"><a href="/records">Public login record</a></p>
</div>

<div id="app" class="hidden">
  <header><strong>V.D.S.N</strong>
    <nav><a href="/records">Login record</a><span id="who"></span><button id="out">Log out</button></nav>
  </header>
  <div id="grid"></div>
</div>
<div id="overlay" class="hidden"></div>

<script>
var $ = function (id) { return document.getElementById(id); };
function api(url, method, data) {
  return fetch(url, { method: method || 'GET', headers: { 'Content-Type': 'application/json' }, body: data ? JSON.stringify(data) : undefined })
    .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, data: d }; }); });
}
function view(name) {
  ['gate', 'acct', 'app'].forEach(function (id) { $(id).classList.toggle('hidden', id !== name); });
}
function start() {
  api('/api/state').then(function (r) {
    var s = r.data.stage;
    if (s === 'app') { $('who').textContent = r.data.username; view('app'); load(); }
    else view(s === 'account' ? 'acct' : 'gate');
  });
}

$('gbtn').onclick = function () {
  api('/api/gate', 'POST', { password: $('sp').value }).then(function (r) {
    if (r.ok) { $('sp').value = ''; $('gerr').textContent = ''; start(); } else $('gerr').textContent = r.data.error || 'Wrong password.';
  });
};
$('sp').onkeydown = function (e) { if (e.key === 'Enter') $('gbtn').onclick(); };

function account(mode) {
  api('/api/account', 'POST', { mode: mode, username: $('u').value.trim(), password: $('p').value }).then(function (r) {
    if (r.ok) { $('p').value = ''; $('aerr').textContent = ''; start(); }
    else { $('aerr').textContent = r.data.error || 'Failed'; if (r.data.stage === 'gate') start(); }
  });
}
$('login').onclick = function () { account('login'); };
$('signup').onclick = function () { account('signup'); };
$('p').onkeydown = function (e) { if (e.key === 'Enter') account('login'); };
$('out').onclick = function () { api('/api/logout', 'POST').then(start); };

function load() {
  api('/api/tiles').then(function (r) {
    var grid = $('grid'); grid.innerHTML = '';
    (r.data || []).forEach(function (t) {
      var d = document.createElement('div'); d.className = 'tile';
      var name = document.createElement('span'); name.textContent = t.title; d.appendChild(name);
      var x = document.createElement('button'); x.className = 'x'; x.textContent = '\\u2715';
      x.onclick = function (e) {
        e.stopPropagation();
        if (confirm('Delete "' + t.title + '"?')) api('/api/tiles/' + t.id, 'DELETE').then(load);
      };
      d.appendChild(x);
      d.onclick = function () { openWin(t); };
      grid.appendChild(d);
    });
    var add = document.createElement('div'); add.className = 'tile add'; add.textContent = '+'; add.onclick = addForm;
    grid.appendChild(add);
  });
}
function show(node) { var o = $('overlay'); o.innerHTML = ''; o.appendChild(node); o.classList.remove('hidden'); }
function closeWin() { $('overlay').classList.add('hidden'); $('overlay').innerHTML = ''; }

function openWin(t) {
  var w = document.createElement('div'); w.className = 'win';
  var bar = document.createElement('div'); bar.className = 'bar';
  var title = document.createElement('strong'); title.textContent = t.title;
  var btns = document.createElement('div');
  var ext = document.createElement('button'); ext.textContent = 'Open in new tab'; ext.onclick = function () { window.open(t.link, '_blank', 'noopener'); };
  var cl = document.createElement('button'); cl.textContent = 'Close'; cl.onclick = closeWin;
  btns.appendChild(ext); btns.appendChild(cl); bar.appendChild(title); bar.appendChild(btns);
  var note = document.createElement('div'); note.className = 'note';
  note.textContent = 'If this stays blank, the site blocks embedding. Use "Open in new tab".';
  var f = document.createElement('iframe'); f.src = t.link; f.referrerPolicy = 'no-referrer';
  w.appendChild(bar); w.appendChild(note); w.appendChild(f); show(w);
}
function addForm() {
  var f = document.createElement('div'); f.className = 'form';
  f.innerHTML = '<h2 style="margin-top:0">New window</h2><label>Name</label><input id="nt" placeholder="Subject 95"><label>Link</label><input id="nl" placeholder="https://example.com"><div class="err" id="ferr"></div><div class="row"><button id="save">Save</button><button id="cancel">Cancel</button></div>';
  show(f);
  $('cancel').onclick = closeWin;
  $('save').onclick = function () {
    api('/api/tiles', 'POST', { title: $('nt').value.trim(), link: $('nl').value.trim() }).then(function (r) {
      if (r.ok) { closeWin(); load(); } else $('ferr').textContent = r.data.error;
    });
  };
}
$('overlay').onclick = function (e) { if (e.target.id === 'overlay') closeWin(); };
start();
</script></body></html>`;

const RECORDS_PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>V.D.S.N Record</title>
<style>${STYLE}
body{padding:24px}table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #3a0a0f}tr:hover td{background:#160507}
</style></head><body>
<a href="/">&larr; Back</a>
<h1>PUBLIC LOGIN RECORD</h1>
<p>Latest 1000 events. Passwords are never recorded.</p>
<table><thead><tr><th>Time</th><th>Username</th><th>Action</th><th>Result</th></tr></thead><tbody id="rows"></tbody></table>
<script>
fetch('/api/logins').then(function (r) { return r.json(); }).then(function (list) {
  var tb = document.getElementById('rows');
  list.forEach(function (e) {
    var tr = document.createElement('tr');
    [new Date(e.time).toLocaleString(), e.username, e.action, e.success ? 'SUCCESS' : 'FAILED'].forEach(function (v) {
      var td = document.createElement('td'); td.textContent = v; tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
});
</script></body></html>`;

// ---------- server ----------
http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  const ip = req.socket.remoteAddress;

  if (p === '/' && req.method === 'GET') return html(res, MAIN_PAGE);
  if (p === '/records') return html(res, RECORDS_PAGE);
  if (p === '/api/logins' || p === '/logins.json') return send(res, 200, read('logins.json', [])); // public record

  if (p === '/api/state') {
    const u = sessionUser(req);
    if (u && gateOpen(req)) return send(res, 200, { stage: 'app', username: u });
    return send(res, 200, { stage: gateOpen(req) ? 'account' : 'gate' });
  }

  if (p === '/api/gate' && req.method === 'POST') {
    if (blocked(ip)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
    const { password = '' } = await readBody(req);
    if (!sameStr(String(password).trim(), SHARED.trim())) {
      fail(ip);
      return setTimeout(() => send(res, 401, { error: 'Wrong password.' }), 600);
    }
    fails.delete(ip);
    const t = crypto.randomBytes(24).toString('hex');
    store.gates.push(t); saveStore();
    return send(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, 'gate', t, YEAR) });
  }

  if (p === '/api/account' && req.method === 'POST') {
    if (!gateOpen(req)) return send(res, 403, { error: 'Enter the shared password first.', stage: 'gate' });
    if (blocked(ip)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
    const { mode, username = '', password = '' } = await readBody(req);
    const name = String(username).trim();
    const key = name.toLowerCase();
    if (!/^[A-Za-z0-9_.-]{3,24}$/.test(name)) return send(res, 400, { error: 'Username: 3-24 letters, numbers, _ . -' });
    if (String(password).length < 4) return send(res, 400, { error: 'Password must be at least 4 characters.' });

    const users = read('users.json', {});
    let ok = false;
    if (mode === 'signup') {
      if (Object.hasOwn(users, key)) return send(res, 409, { error: 'That username is taken.' });
      users[key] = { display: name, hash: hashPw(String(password)) };
      write('users.json', users);
      ok = true;
      logEvent(name, 'signup', true);
    } else {
      ok = Object.hasOwn(users, key) && checkPw(String(password), users[key].hash);
      logEvent(name, 'login', ok);
      if (!ok) {
        fail(ip);
        return setTimeout(() => send(res, 401, { error: 'Wrong username or password.' }), 600);
      }
    }
    fails.delete(ip);
    const t = crypto.randomBytes(24).toString('hex');
    store.sessions[t] = users[key].display; saveStore();
    return send(res, 200, { ok: true, username: users[key].display }, { 'Set-Cookie': setCookie(req, 'sid', t, YEAR) });
  }

  if (p === '/api/logout' && req.method === 'POST') {
    const t = cookie(req, 'sid');
    if (t) { delete store.sessions[t]; saveStore(); }
    return send(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, 'sid', '', 0) });
  }

  if (p.startsWith('/api/tiles')) {
    if (!sessionUser(req) || !gateOpen(req)) return send(res, 401, { error: 'Login required' });
    const tiles = read('tiles.json', []);
    if (req.method === 'GET') return send(res, 200, tiles);
    if (req.method === 'POST') {
      const { title, link } = await readBody(req);
      const href = cleanUrl(link);
      if (!href) return send(res, 400, { error: 'Enter a valid http(s) link.' });
      const t = { id: crypto.randomUUID(), title: String(title || href).slice(0, 60), link: href };
      tiles.push(t); write('tiles.json', tiles);
      return send(res, 200, t);
    }
    if (req.method === 'DELETE') {
      write('tiles.json', tiles.filter(t => t.id !== p.split('/').pop()));
      return send(res, 200, { ok: true });
    }
  }

  send(res, 404, { error: 'Not found' });
}).listen(PORT, () => console.log('V.D.S.N running on http://localhost:' + PORT));
