// On-premises server (e.g. BCC National Data Centre): node server.mjs, behind nginx/TLS.
// অন-প্রেম সার্ভার (যেমন বিসিসি জাতীয় ডেটা সেন্টার): nginx/TLS-এর পেছনে চালান।
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGate } from './auth/core.mjs';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.resolve(process.env.OBS_PUBLIC_DIR || path.join(ROOT, 'public'));
const USERS_FILE = path.resolve(process.env.OBS_USERS_FILE || path.join(ROOT, 'users.json'));
const AUDIT_FILE = path.resolve(process.env.OBS_AUDIT_FILE || path.join(ROOT, 'audit.log'));
const TRUST_PROXY = process.env.OBS_TRUST_PROXY === '1';

// Users file is re-read whenever it changes: removing a person takes effect on their next click.
let usersCache = { mtime: 0, data: '[]' };
function getUsers() {
  if (process.env.OBS_USERS) return process.env.OBS_USERS;
  try {
    const st = fs.statSync(USERS_FILE);
    if (st.mtimeMs !== usersCache.mtime) usersCache = { mtime: st.mtimeMs, data: fs.readFileSync(USERS_FILE, 'utf8') };
  } catch { usersCache = { mtime: 0, data: '[]' }; }
  return usersCache.data;
}
function log(event) {
  const line = JSON.stringify(event);
  console.log(line);
  try { fs.appendFileSync(AUDIT_FILE, line + '\n', { mode: 0o600 }); } catch (e) { console.error('audit write failed', e.message); }
}
async function readAudit(n) {
  try { return fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').slice(-n); } catch { return []; }
}

const gate = createGate({
  secret: process.env.OBS_SESSION_SECRET,
  getUsers,
  sessionHours: process.env.OBS_SESSION_HOURS,
  epoch: process.env.OBS_SESSION_EPOCH,
  allowedCidrs: (process.env.OBS_ALLOWED_CIDRS || '').split(',').map((s) => s.trim()),
  secureCookie: process.env.OBS_INSECURE_HTTP !== '1',
  clientIp: (req) => req.headers.get('x-obs-peer'),
  log,
  readAudit,
});

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json', '.woff2': 'font/woff2' };

function staticFile(urlPath) {
  let rel;
  try { rel = decodeURIComponent(urlPath); } catch { return null; }
  if (rel.includes('\0')) return null;
  let file = path.resolve(PUBLIC_DIR, '.' + path.posix.normalize('/' + rel));
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) return null; // no escaping the public folder
  try { if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html'); } catch { return null; }
  return fs.existsSync(file) ? file : null;
}

const server = http.createServer(async (req, res) => {
  try {
    const peer = TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress : req.socket.remoteAddress;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (k !== 'x-obs-peer') headers.set(k, Array.isArray(v) ? v.join(', ') : v);
    headers.set('x-obs-peer', peer || 'unknown');
    let body;
    if (req.method === 'POST') {
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 16384) { res.writeHead(413).end(); return; } chunks.push(c); }
      body = Buffer.concat(chunks);
    }
    const proto = TRUST_PROXY && req.headers['x-forwarded-proto'] ? req.headers['x-forwarded-proto'] : 'http';
    const request = new Request(`${proto}://${req.headers.host || 'localhost'}${req.url}`, { method: req.method, headers, body });
    const result = await gate.handle(request);
    if (result.response) {
      const r = result.response;
      const out = {};
      r.headers.forEach((v, k) => { if (k !== 'set-cookie') out[k] = v; });
      const cookies = r.headers.getSetCookie();
      if (cookies.length) out['set-cookie'] = cookies;
      res.writeHead(r.status, out);
      res.end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    const file = staticFile(new URL(request.url).pathname);
    if (!file || !['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...result.headers }).end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', ...result.headers });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Server error');
  }
});

server.listen(PORT, HOST, () => console.log(JSON.stringify({ ev: 'server_start', host: HOST, port: PORT, public: PUBLIC_DIR })));
