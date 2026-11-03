// Bangladesh Economic Observatory: access gate (core logic)
// বাংলাদেশ অর্থনৈতিক পর্যবেক্ষণাগার: প্রবেশ-নিয়ন্ত্রণের মূল কোড
//
// Uses only Web-standard APIs (Request, Response, Web Crypto), so the same code
// runs in Vercel Routing Middleware and in the on-premises Node server (server.mjs).
//
// Layers: (1) named allowlist, (2) password + authenticator-app code (TOTP),
// (3) HMAC-signed session cookie with fixed lifetime and a global revoke switch,
// (4) audit log, (5) per-user watermark, (6) no-index / no-store / no-frame headers,
// optional (7) network allowlist (government IP ranges).

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export const AUTH_PREFIX = '/_auth/';
const PBKDF2_ITERATIONS = 210000;
const MAX_FAILS = 5; // per person
const MAX_FAILS_IP = 30; // per network address: offices share one public IP, so this is looser
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;

export const SECURITY_HEADERS = {
  'Cache-Control': 'private, no-store, max-age=0',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

// ---------- encoding helpers ----------
export const b64u = {
  enc(bytes) {
    let s = '';
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const c of clean) {
    value = (value << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

function timingSafeEqual(a, b) {
  const x = typeof a === 'string' ? enc.encode(a) : a;
  const y = typeof b === 'string' ? enc.encode(b) : b;
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

export function randomBytes(n) { const u = new Uint8Array(n); globalThis.crypto.getRandomValues(u); return u; }

// ---------- passwords (PBKDF2-SHA256) ----------
async function pbkdf2(password, salt, iterations) {
  const key = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}
export async function hashPassword(password, iterations = PBKDF2_ITERATIONS) {
  const salt = randomBytes(16);
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2$${iterations}$${b64u.enc(salt)}$${b64u.enc(hash)}`;
}
const DUMMY_HASH = `pbkdf2$${PBKDF2_ITERATIONS}$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
export async function verifyPassword(password, stored) {
  const parts = String(stored || DUMMY_HASH).split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const it = Number(parts[1]);
  if (!Number.isFinite(it) || it < 100000 || it > 2000000) return false;
  const got = await pbkdf2(String(password), b64u.dec(parts[2]), it);
  return timingSafeEqual(got, b64u.dec(parts[3]));
}

// ---------- TOTP (RFC 6238, SHA-1, 30 s, 6 digits) ----------
async function hotp(secretBytes, counter) {
  const key = await subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 2 ** 32));
  dv.setUint32(4, counter >>> 0);
  const h = new Uint8Array(await subtle.sign('HMAC', key, buf));
  const o = h[h.length - 1] & 15;
  const code = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000;
  return String(code).padStart(6, '0');
}
export async function totpNow(secretB32, now = Date.now()) {
  return hotp(base32Decode(secretB32), Math.floor(now / 30000));
}
// Returns the matched time-step, or -1. Accepts one step of clock drift either way.
export async function verifyTotp(secretB32, code, now = Date.now(), window = 1) {
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c) || !secretB32) return -1;
  const secret = base32Decode(secretB32);
  const step = Math.floor(now / 30000);
  for (let d = -window; d <= window; d++) {
    if (timingSafeEqual(await hotp(secret, step + d), c)) return step + d;
  }
  return -1;
}
export function newTotpSecret() { return base32Encode(randomBytes(20)); }
export function otpauthUrl(secretB32, email, issuer = 'BD Economic Observatory') {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ---------- signed sessions ----------
const keyCache = new Map();
async function hmacKey(secret) {
  if (!keyCache.has(secret)) {
    keyCache.set(secret, subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']));
  }
  return keyCache.get(secret);
}
export async function signSession(payload, secret) {
  const body = b64u.enc(enc.encode(JSON.stringify(payload)));
  const sig = b64u.enc(await subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  return `${body}.${sig}`;
}
export async function readSession(token, secret) {
  if (!token || typeof token !== 'string' || token.length > 4096) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expect = b64u.enc(await subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  if (!timingSafeEqual(expect, sig)) return null;
  try { return JSON.parse(new TextDecoder().decode(b64u.dec(body))); } catch { return null; }
}

// ---------- small utilities ----------
function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function safeNext(n) {
  const s = String(n || '/');
  if (!s.startsWith('/') || s.startsWith('//') || s.startsWith('/\\') || s.startsWith(AUTH_PREFIX)) return '/';
  return s.slice(0, 512);
}
function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
export function ipAllowed(ip, cidrs) {
  if (!cidrs || !cidrs.length) return true;
  const clean = String(ip || '').replace(/^::ffff:/, '');
  const n = ipv4ToInt(clean);
  for (const c of cidrs) {
    const [base, bitsStr] = c.split('/');
    if (n === null || ipv4ToInt(base) === null) { if (clean === base) return true; continue; }
    const bits = bitsStr === undefined ? 32 : Number(bitsStr);
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    if (((n & mask) >>> 0) === ((ipv4ToInt(base) & mask) >>> 0)) return true;
  }
  return false;
}
export function normaliseUsers(raw) {
  let data = raw;
  if (typeof data === 'string') {
    const t = data.trim();
    if (!t) return [];
    data = JSON.parse(t.startsWith('{') || t.startsWith('[') ? t : new TextDecoder().decode(b64u.dec(t.replace(/=+$/, ''))));
  }
  const list = Array.isArray(data) ? data : (data && data.users) || [];
  return list.map((u) => ({ ...u, email: String(u.email || '').trim().toLowerCase() })).filter((u) => u.email);
}

// ---------- the gate ----------
export function createGate(cfg) {
  if (!cfg.secret || cfg.secret.length < 32) throw new Error('OBS_SESSION_SECRET must be at least 32 characters');
  const sessionMs = (Number(cfg.sessionHours) || 8) * 3600 * 1000;
  const epoch = String(cfg.epoch || '1');
  const secure = cfg.secureCookie !== false;
  const cookieName = secure ? '__Host-obs_session' : 'obs_session';
  const cidrs = (cfg.allowedCidrs || []).filter(Boolean);
  const log = cfg.log || ((e) => console.log(JSON.stringify(e)));
  const fails = new Map(); // key -> {times:[], lockedUntil}
  const lastStep = new Map(); // email -> last accepted TOTP step (replay guard)
  const now = cfg.now || (() => Date.now());

  const users = () => normaliseUsers(cfg.getUsers());
  const credVersion = (u) => String(u.pw || '').slice(-10) + String(u.totp || '').slice(-4);
  const findUser = (email) => users().find((u) => u.email === String(email || '').trim().toLowerCase() && u.active !== false);

  function clientIp(req) {
    return cfg.clientIp?.(req)
      || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim()
      || req.headers.get('x-real-ip') || 'unknown';
  }
  function audit(ev, req, extra = {}) {
    log({ t: new Date(now()).toISOString(), ev, ip: clientIp(req), ua: (req.headers.get('user-agent') || '').slice(0, 160), ...extra });
  }
  function html(body, status = 200, extraHeaders = {}) {
    return new Response(body, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...extraHeaders } });
  }
  function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...SECURITY_HEADERS } });
  }
  function redirect(location, extraHeaders = {}) {
    return new Response(null, { status: 303, headers: { Location: location, ...SECURITY_HEADERS, ...extraHeaders } });
  }
  function cookie(value, maxAgeSec) {
    return `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
  }

  function isLocked(key) {
    const f = fails.get(key);
    return !!(f && f.lockedUntil && f.lockedUntil > now());
  }
  function addFail(key, max = MAX_FAILS) {
    const t = now();
    const f = fails.get(key) || { times: [], lockedUntil: 0 };
    f.times = f.times.filter((x) => t - x < FAIL_WINDOW_MS);
    f.times.push(t);
    if (f.times.length >= max) { f.lockedUntil = t + LOCK_MS; f.times = []; }
    fails.set(key, f);
    if (fails.size > 10000) fails.clear();
  }

  async function currentUser(req) {
    const token = parseCookies(req.headers.get('cookie'))[cookieName];
    const s = await readSession(token, cfg.secret);
    if (!s || s.ep !== epoch || typeof s.exp !== 'number' || s.exp < now()) return null;
    const u = findUser(s.e);
    if (!u) return null; // removed or disabled: access ends at the next request
    if (s.pv !== credVersion(u)) return null; // password/authenticator reset ends that person's old sessions
    return { email: u.email, name: u.name || u.email, role: u.role || 'viewer', exp: s.exp };
  }

  async function handleLogin(req, url) {
    const origin = req.headers.get('origin');
    if (origin && origin !== 'null') {
      try { if (new URL(origin).host !== url.host) return html(loginPage({ error: 'origin' }), 403); } catch { return html(loginPage({ error: 'origin' }), 403); }
    }
    const form = new URLSearchParams(await req.text());
    const email = String(form.get('email') || '').trim().toLowerCase().slice(0, 200);
    const password = String(form.get('password') || '').slice(0, 512);
    const code = String(form.get('code') || '').slice(0, 12);
    const next = safeNext(form.get('next'));
    const ip = clientIp(req);
    const keyUser = `u:${email}`, keyIp = `ip:${ip}`;

    if (isLocked(keyUser) || isLocked(keyIp)) {
      audit('login_locked', req, { email });
      return html(loginPage({ error: 'locked', next, email }), 429);
    }
    const user = findUser(email);
    const pwOk = await verifyPassword(password, user?.pw); // runs even for unknown users (equal timing)
    let step = -1;
    if (user && pwOk) step = await verifyTotp(user.totp, code, now());
    const replay = step !== -1 && (lastStep.get(email) ?? -1) >= step;
    if (!user || !pwOk || step === -1 || replay) {
      addFail(keyUser); addFail(keyIp, MAX_FAILS_IP);
      audit('login_fail', req, { email, reason: !user ? 'unknown_or_disabled' : !pwOk ? 'password' : replay ? 'code_reused' : 'code' });
      return html(loginPage({ error: 'bad', next, email }), 401);
    }
    lastStep.set(email, step);
    fails.delete(keyUser);
    const exp = now() + sessionMs;
    const token = await signSession({ e: user.email, ep: epoch, pv: credVersion(user), iat: now(), exp, sid: b64u.enc(randomBytes(9)) }, cfg.secret);
    audit('login_ok', req, { email: user.email, role: user.role || 'viewer' });
    return redirect(next, { 'Set-Cookie': cookie(token, Math.floor(sessionMs / 1000)) });
  }

  // Returns {response} to send now, or {pass: true, headers, user} to let the request reach the site.
  async function handle(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (!ipAllowed(clientIp(req), cidrs)) {
      audit('network_denied', req, { path });
      return { response: html(blockedPage(), 403) };
    }

    if (path === '/_auth/login') {
      if (req.method === 'POST') return { response: await handleLogin(req, url) };
      const u = await currentUser(req);
      if (u) return { response: redirect(safeNext(url.searchParams.get('next'))) };
      return { response: html(loginPage({ next: safeNext(url.searchParams.get('next')), notice: url.searchParams.get('m') })) };
    }
    if (path === '/_auth/logout') {
      const u = await currentUser(req);
      if (u) audit('logout', req, { email: u.email });
      return { response: redirect('/_auth/login?m=out', { 'Set-Cookie': cookie('', 0) }) };
    }

    const user = await currentUser(req);
    if (!user) {
      if (path.startsWith(AUTH_PREFIX) || !(req.headers.get('accept') || '').includes('text/html')) {
        return { response: json({ error: 'unauthorized' }, 401) };
      }
      audit('redirect_to_login', req, { path });
      return { response: redirect(`/_auth/login?next=${encodeURIComponent(path + url.search)}`) };
    }

    if (path === '/_auth/me') return { response: json(user) };
    if (path === '/_auth/guard.js') {
      return { response: new Response(GUARD_JS, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', ...SECURITY_HEADERS } }) };
    }
    if (path === '/_auth/audit') {
      if (user.role !== 'admin') return { response: json({ error: 'forbidden' }, 403) };
      const lines = cfg.readAudit ? await cfg.readAudit(300) : null;
      return { response: html(auditPage(lines)) };
    }
    if (path.startsWith(AUTH_PREFIX)) return { response: json({ error: 'not_found' }, 404) };

    if (path === '/' || path.endsWith('.html')) audit('page_view', req, { email: user.email, path });
    return { pass: true, headers: { ...SECURITY_HEADERS }, user };
  }

  return { handle, currentUser, cookieName };
}

// ---------- pages (bilingual, no external resources) ----------
const PAGE_CSS = `
:root{color-scheme:light dark;--bg:#f7f6f2;--panel:#fff;--fg:#1f1e1b;--muted:#6b6a64;--line:#e3e1da;--bad:#c53030;--ok:#2e8b57;--acc:#1f1e1b}
@media (prefers-color-scheme:dark){:root{--bg:#151513;--panel:#1f1f1c;--fg:#ecebe6;--muted:#a3a19a;--line:#33322e;--bad:#f06a6a;--ok:#5cc08a;--acc:#ecebe6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:"Noto Sans Bengali","Kalpurush","SolaimanLipi",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;min-height:100vh;display:grid;place-items:center;padding:16px}
main{width:100%;max-width:420px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:28px}
.k{font:12px ui-monospace,Menlo,monospace;letter-spacing:.06em;color:var(--muted);text-transform:uppercase;margin:0 0 6px}
h1{font-family:Georgia,"Noto Serif Bengali",serif;font-weight:400;font-size:24px;line-height:1.25;margin:0 0 4px}
.en{color:var(--muted);font-size:13px;margin:0 0 20px}
label{display:block;font-size:13px;margin:14px 0 4px}label span{color:var(--muted)}
input{width:100%;font:inherit;font-size:16px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
input:focus{outline:2px solid var(--acc);outline-offset:1px}
button{margin-top:20px;width:100%;font:inherit;font-size:15px;font-weight:600;padding:11px;border:0;border-radius:8px;background:var(--acc);color:var(--bg);cursor:pointer}
.msg{border-radius:8px;padding:10px 12px;font-size:13.5px;line-height:1.5;margin:0 0 6px;border:1px solid}
.msg.bad{color:var(--bad);border-color:var(--bad)}.msg.ok{color:var(--ok);border-color:var(--ok)}
.foot{margin:18px 0 0;font-size:12px;color:var(--muted);line-height:1.55}
table{border-collapse:collapse;width:100%;font:12px ui-monospace,Menlo,monospace}td,th{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}
`;

const MESSAGES = {
  bad: ['ইমেইল, পাসওয়ার্ড বা কোড সঠিক নয়।', 'Email, password or code is not correct.'],
  locked: ['বারবার ভুল চেষ্টার কারণে প্রবেশ ১৫ মিনিটের জন্য স্থগিত।', 'Too many failed attempts. Try again in 15 minutes.'],
  origin: ['অনুরোধটি এই সাইট থেকে আসেনি।', 'The request did not come from this site.'],
  out: ['আপনি লগ-আউট করেছেন।', 'You have signed out.'],
};

export function loginPage({ error, next = '/', email = '', notice } = {}) {
  const m = error ? MESSAGES[error] : notice && MESSAGES[notice];
  const cls = error ? 'bad' : 'ok';
  return `<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>প্রবেশ · বাংলাদেশ অর্থনৈতিক পর্যবেক্ষণাগার</title><style>${PAGE_CSS}</style></head><body><main>
<p class="k">সীমিত প্রবেশ · Restricted access</p>
<h1>বাংলাদেশ অর্থনৈতিক পর্যবেক্ষণাগার</h1>
<p class="en">Bangladesh Economic Observatory · Cabinet Division</p>
${m ? `<p class="msg ${cls}" role="alert">${esc(m[0])}<br><span>${esc(m[1])}</span></p>` : ''}
<form method="post" action="/_auth/login" autocomplete="on">
<input type="hidden" name="next" value="${esc(next)}">
<label for="email">ইমেইল <span>· Email</span></label>
<input id="email" name="email" type="email" required autocomplete="username" value="${esc(email)}" autofocus>
<label for="password">পাসওয়ার্ড <span>· Password</span></label>
<input id="password" name="password" type="password" required autocomplete="current-password">
<label for="code">অথেনটিকেটর অ্যাপের ৬ অঙ্কের কোড <span>· 6-digit code</span></label>
<input id="code" name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autocomplete="one-time-code">
<button type="submit">প্রবেশ করুন · Sign in</button>
</form>
<p class="foot">এই সাইট কেবল মন্ত্রিপরিষদ বিভাগ কর্তৃক অনুমোদিত ব্যক্তিদের জন্য। প্রতিটি প্রবেশ ও প্রচেষ্টা লিপিবদ্ধ হয়। তথ্য প্রকাশ রুলস অব বিজনেস, ১৯৯৬-এর রুল ২৮ দ্বারা নিয়ন্ত্রিত।<br>For authorised persons only. Every sign-in and attempt is logged.</p>
</main></body></html>`;
}

function blockedPage() {
  return `<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>প্রবেশ নিষেধ</title><style>${PAGE_CSS}</style></head><body><main><h1>প্রবেশ নিষেধ</h1><p class="en">Access is allowed only from the government network.</p><p class="foot">এই সাইট কেবল সরকারি নেটওয়ার্ক থেকে খোলা যায়।</p></main></body></html>`;
}

function auditPage(lines) {
  const rows = (lines || []).map((l) => {
    let e; try { e = JSON.parse(l); } catch { return ''; }
    return `<tr><td>${esc(e.t)}</td><td>${esc(e.ev)}</td><td>${esc(e.email || '')}</td><td>${esc(e.ip)}</td><td>${esc(e.reason || e.path || '')}</td></tr>`;
  }).reverse().join('');
  const body = lines
    ? `<table><tr><th>সময় (UTC)</th><th>ঘটনা</th><th>ইমেইল</th><th>আইপি</th><th>বিবরণ</th></tr>${rows}</table>`
    : '<p class="foot">এই হোস্টিংয়ে অডিট লগ প্ল্যাটফর্মের লগে থাকে (Vercel: Project → Logs)।</p>';
  return `<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>অডিট লগ</title><style>${PAGE_CSS}main{max-width:1000px}</style></head><body><main><p class="k">Admin · Audit log</p><h1>অডিট লগ</h1><p class="en">সর্বশেষ ৩০০টি ঘটনা, নতুনটি আগে · <a href="/">পর্যবেক্ষণাগার</a></p>${body}</main></body></html>`;
}

// Runs inside the observatory page: personal watermark, signed-in chip, auto sign-out at expiry.
const GUARD_JS = `(() => {
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  fetch('/_auth/me', { credentials: 'same-origin', cache: 'no-store' })
    .then((r) => (r.ok ? r.json() : null))
    .then((u) => {
      if (!u) { location.href = '/_auth/login?next=' + encodeURIComponent(location.pathname); return; }
      const stamp = new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dhaka', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      const label = u.name + ' · ' + u.email + ' · ' + stamp;
      const svg = "<svg xmlns='http://www.w3.org/2000/svg' width='460' height='260'><text x='20' y='150' transform='rotate(-22 230 130)' font-family='sans-serif' font-size='14' fill='rgba(128,128,128,0.16)'>" + esc(label) + '</text></svg>';
      const wm = document.createElement('div');
      wm.setAttribute('aria-hidden', 'true');
      wm.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483646;background-repeat:repeat;background-image:url("data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg) + '");-webkit-print-color-adjust:exact;print-color-adjust:exact';
      document.body.appendChild(wm);
      const chip = document.createElement('div');
      chip.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:2147483647;font:12px system-ui,sans-serif;background:rgba(30,30,28,.88);color:#fff;border-radius:999px;padding:6px 12px;display:flex;gap:10px;align-items:center';
      const who = document.createElement('span'); who.textContent = u.name;
      const out = document.createElement('a'); out.href = '/_auth/logout'; out.textContent = 'লগ-আউট'; out.style.cssText = 'color:#9fd0ff;text-decoration:none';
      chip.append(who, out);
      document.body.appendChild(chip);
      const ms = u.exp - Date.now();
      if (ms > 0 && ms < 2147483647) setTimeout(() => { location.href = '/_auth/login?m=out'; }, ms + 1000);
    })
    .catch(() => {});
})();`;
