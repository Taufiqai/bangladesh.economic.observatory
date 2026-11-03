// End-to-end test of the access gate: runs server.mjs on a free port and the Vercel middleware in-process.
// npm test
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { hashPassword, newTotpSecret, totpNow, signSession, b64u } from '../auth/core.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-'));
const usersFile = path.join(tmp, 'users.json');
const auditFile = path.join(tmp, 'audit.log');
const SECRET = 'test-secret-' + 'x'.repeat(40);

const A = { email: 'analyst@cabinet.gov.bd', name: 'পরীক্ষা কর্মকর্তা', role: 'admin', pw: 'Correct-Horse-1', totp: newTotpSecret() };
const B = { email: 'member@cabinet.gov.bd', name: 'Committee Member', role: 'viewer', pw: 'Battery-Staple-2', totp: newTotpSecret() };
async function writeUsers(list) {
  const users = [];
  for (const u of list) users.push({ email: u.email, name: u.name, role: u.role, active: u.active !== false, pw: await hashPassword(u.pw), totp: u.totp });
  fs.writeFileSync(usersFile, JSON.stringify({ users }));
}
await writeUsers([A, B]);

let results = [];
async function t(name, fn) {
  try { await fn(); results.push(['PASS', name]); } catch (e) { results.push(['FAIL', name + ' :: ' + e.message]); }
}

function start(port, epoch = '1') {
  const p = spawn(process.execPath, [path.join(ROOT, 'server.mjs')], {
    env: { ...process.env, PORT: String(port), OBS_SESSION_SECRET: SECRET, OBS_USERS_FILE: usersFile, OBS_AUDIT_FILE: auditFile, OBS_SESSION_EPOCH: epoch },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return new Promise((resolve, reject) => {
    p.stdout.on('data', (d) => { if (String(d).includes('server_start')) resolve(p); });
    p.stderr.on('data', (d) => process.stderr.write(d));
    p.on('exit', (c) => reject(new Error('server exited ' + c)));
  });
}
const PORT = 18000 + Math.floor(Math.random() * 1000);
const base = `http://127.0.0.1:${PORT}`;
let srv = await start(PORT);

const H = { accept: 'text/html' };
async function login(u, code, extra = {}) {
  const body = new URLSearchParams({ email: u.email, password: extra.pw ?? u.pw, code, next: extra.next ?? '/' });
  return fetch(base + '/_auth/login', { method: 'POST', body, redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(extra.headers || {}) } });
}
const cookieOf = (res) => (res.headers.getSetCookie()[0] || '').split(';')[0];

await t('no session: page redirects to login', async () => {
  const r = await fetch(base + '/', { redirect: 'manual', headers: H });
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/_auth/login?next=%2F');
});
await t('no session: data endpoints answer 401', async () => {
  assert.equal((await fetch(base + '/_auth/me')).status, 401);
  assert.equal((await fetch(base + '/index.html')).status, 401);
});
await t('login page is bilingual, no-index, not frameable', async () => {
  const r = await fetch(base + '/_auth/login');
  const s = await r.text();
  assert.equal(r.status, 200);
  assert.ok(s.includes('বাংলাদেশ অর্থনৈতিক পর্যবেক্ষণাগার') && s.includes('Sign in'));
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.ok(r.headers.get('x-robots-tag').includes('noindex'));
});
await t('wrong password rejected with a generic message', async () => {
  const r = await login(A, await totpNow(A.totp), { pw: 'wrong' });
  assert.equal(r.status, 401);
  assert.ok((await r.text()).includes('ইমেইল, পাসওয়ার্ড বা কোড সঠিক নয়'));
});
await t('right password, wrong code rejected', async () => {
  assert.equal((await login(A, '000000')).status, 401);
});
await t('unknown email rejected', async () => {
  assert.equal((await login({ email: 'nobody@example.com', pw: 'x' }, '123456')).status, 401);
});
await t('cross-site login POST refused', async () => {
  const r = await login(A, await totpNow(A.totp), { headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
});

let cookieA;
await t('correct password + code signs in; cookie is HttpOnly, Secure, host-only', async () => {
  const r = await login(A, await totpNow(A.totp), { next: '/?tab=sim' });
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/?tab=sim');
  const sc = r.headers.getSetCookie()[0];
  assert.ok(sc.startsWith('__Host-obs_session=') && sc.includes('HttpOnly') && sc.includes('Secure') && sc.includes('SameSite=Lax'));
  cookieA = cookieOf(r);
});
await t('the same code cannot be used twice', async () => {
  assert.equal((await login(A, await totpNow(A.totp))).status, 401);
});
await t('signed-in user sees the observatory with security headers', async () => {
  const r = await fetch(base + '/', { headers: { cookie: cookieA } });
  const s = await r.text();
  assert.equal(r.status, 200);
  assert.ok(s.includes('Bangladesh Economic Observatory') && s.includes('/_auth/guard.js'));
  assert.equal(r.headers.get('cache-control'), 'private, no-store, max-age=0');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
});
await t('/_auth/me returns name for the watermark', async () => {
  const j = await (await fetch(base + '/_auth/me', { headers: { cookie: cookieA } })).json();
  assert.equal(j.email, A.email); assert.equal(j.name, A.name); assert.equal(j.role, 'admin');
});
await t('open redirect blocked', async () => {
  const r = await login(A, await totpNow(A.totp, Date.now() + 30000), { next: '//evil.example/x' });
  assert.equal(r.status, 303);
  assert.equal(r.headers.get('location'), '/');
});
await t('tampered cookie rejected', async () => {
  const [name, val] = cookieA.split('=');
  const [body, sig] = val.split('.');
  const payload = JSON.parse(new TextDecoder().decode(b64u.dec(body)));
  payload.e = B.email;
  const forged = `${name}=${b64u.enc(new TextEncoder().encode(JSON.stringify(payload)))}.${sig}`;
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: forged, ...H } })).status, 303);
});
await t('expired session rejected', async () => {
  const tok = await signSession({ e: A.email, ep: '1', pv: 'x', iat: Date.now() - 9e6, exp: Date.now() - 1000 }, SECRET);
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: '__Host-obs_session=' + tok, ...H } })).status, 303);
});
await t('path traversal cannot reach server files', async () => {
  for (const p of ['/../server.mjs', '/%2e%2e/server.mjs', '/..%2fauth/core.mjs', '/../users.json']) {
    const r = await fetch(base + p, { headers: { cookie: cookieA } });
    assert.notEqual(r.status, 200, p);
  }
});
await t('admin can read the audit log; it records sign-ins and failures', async () => {
  const s = await (await fetch(base + '/_auth/audit', { headers: { cookie: cookieA } })).text();
  assert.ok(s.includes('login_ok') && s.includes('login_fail'));
});
await t('five failures lock the account even for the right password', async () => {
  for (let i = 0; i < 5; i++) await login(B, '111111', { pw: 'nope' });
  assert.equal((await login(B, await totpNow(B.totp))).status, 429);
});
await t('viewer cannot open the audit log', async () => {
  // C is a fresh viewer (B is locked)
  const C = { email: 'viewer2@cabinet.gov.bd', name: 'Viewer', role: 'viewer', pw: 'Viewer-Pass-3', totp: newTotpSecret() };
  await writeUsers([A, B, C]);
  await new Promise((r) => setTimeout(r, 30));
  const ck = cookieOf(await login(C, await totpNow(C.totp)));
  assert.ok(ck);
  assert.equal((await fetch(base + '/_auth/audit', { headers: { cookie: ck } })).status, 403);
});
await t('removing a person from the list ends access at the next request', async () => {
  await writeUsers([B]);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: cookieA, ...H } })).status, 303);
  await writeUsers([A, B]);
});
const D = { email: 'reset.test@cabinet.gov.bd', name: 'Reset Test', role: 'viewer', pw: 'Before-Reset-4', totp: newTotpSecret() };
const E = { email: 'epoch.test@cabinet.gov.bd', name: 'Epoch Test', role: 'viewer', pw: 'Epoch-Pass-5', totp: newTotpSecret() };
await writeUsers([A, B, D, E]);
await new Promise((r) => setTimeout(r, 30));
await t('resetting a person\'s password ends their existing sessions', async () => {
  const ck = cookieOf(await login(D, await totpNow(D.totp)));
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: ck, ...H } })).status, 200);
  D.pw = 'After-Reset-6';
  await writeUsers([A, B, D, E]);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: ck, ...H } })).status, 303);
});
await t('logout clears the cookie', async () => {
  const r = await fetch(base + '/_auth/logout', { redirect: 'manual', headers: { cookie: cookieA } });
  assert.equal(r.status, 303);
  assert.ok(r.headers.getSetCookie()[0].includes('Max-Age=0'));
});
const keep = cookieOf(await login(E, await totpNow(E.totp)));
await t('session valid before the epoch change', async () => {
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: keep, ...H } })).status, 200);
});
srv.kill(); await new Promise((r) => setTimeout(r, 200));
srv = await start(PORT, '2');
await t('changing OBS_SESSION_EPOCH signs everyone out at once', async () => {
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: keep, ...H } })).status, 303);
});
srv.kill();

// ---- Vercel middleware, in-process ----
process.env.OBS_SESSION_SECRET = SECRET;
process.env.OBS_USERS = b64u.enc(new TextEncoder().encode(fs.readFileSync(usersFile, 'utf8')));
process.env.OBS_SESSION_EPOCH = '1';
const mw = (await import(path.join(ROOT, 'middleware.js'))).default;
const V = 'https://observatory.example.gov.bd';
await t('Vercel: unauthenticated page goes to login', async () => {
  const r = await mw(new Request(V + '/', { headers: H }));
  assert.equal(r.status, 303);
});
await t('Vercel: sign-in then pass-through with security headers', async () => {
  const body = new URLSearchParams({ email: A.email, password: A.pw, code: await totpNow(A.totp, Date.now() - 30000), next: '/' });
  const r = await mw(new Request(V + '/_auth/login', { method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded', origin: V, 'x-forwarded-for': '203.0.113.9' } }));
  assert.equal(r.status, 303);
  const ck = r.headers.getSetCookie()[0].split(';')[0];
  const ok = await mw(new Request(V + '/', { headers: { cookie: ck, ...H } }));
  assert.equal(ok.headers.get('x-middleware-next'), '1');
  assert.ok(ok.headers.get('x-middleware-override-headers') !== undefined);
  assert.equal(ok.headers.get('x-frame-options'), 'DENY');
});
await t('Vercel: missing secret fails closed (503)', async () => {
  const saved = process.env.OBS_SESSION_SECRET;
  delete process.env.OBS_SESSION_SECRET;
  const fresh = (await import(path.join(ROOT, 'middleware.js') + '?fresh=' + Date.now())).default;
  const r = await fresh(new Request(V + '/', { headers: H }));
  assert.equal(r.status, 503);
  process.env.OBS_SESSION_SECRET = saved;
});
await t('Vercel: network allowlist blocks outside addresses', async () => {
  process.env.OBS_ALLOWED_CIDRS = '10.0.0.0/8, 103.48.16.0/22';
  const fresh = (await import(path.join(ROOT, 'middleware.js') + '?cidr=' + Date.now())).default;
  assert.equal((await fresh(new Request(V + '/_auth/login', { headers: { 'x-forwarded-for': '198.51.100.7' } }))).status, 403);
  assert.equal((await fresh(new Request(V + '/_auth/login', { headers: { 'x-forwarded-for': '10.20.30.40' } }))).status, 200);
  delete process.env.OBS_ALLOWED_CIDRS;
});

fs.rmSync(tmp, { recursive: true, force: true });
for (const [s, n] of results) console.log(`${s}  ${n}`);
const failed = results.filter((r) => r[0] === 'FAIL').length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
