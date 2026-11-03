// User management for the access gate. ব্যবহারকারী ব্যবস্থাপনা।
//   node tools/users.mjs add <email> "<name>" [viewer|admin]
//   node tools/users.mjs reset <email>          new password and new authenticator key
//   node tools/users.mjs disable|enable|remove <email>
//   node tools/users.mjs list
//   node tools/users.mjs export                 one-line value for the OBS_USERS environment variable (Vercel)
//   node tools/users.mjs secret                 new random OBS_SESSION_SECRET
import fs from 'node:fs';
import path from 'node:path';
import { hashPassword, newTotpSecret, otpauthUrl, b64u, randomBytes, normaliseUsers } from '../auth/core.mjs';

const FILE = path.resolve(process.env.OBS_USERS_FILE || 'users.json');
const OUT_DIR = path.resolve(process.env.OBS_HANDOVER_DIR || 'handover');
const load = () => (fs.existsSync(FILE) ? normaliseUsers(fs.readFileSync(FILE, 'utf8')) : []);
const save = (users) => fs.writeFileSync(FILE, JSON.stringify({ users }, null, 2) + '\n', { mode: 0o600 });

function newPassword() {
  const A = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const r = randomBytes(18);
  let s = '';
  for (let i = 0; i < 18; i++) s += A[r[i] % A.length];
  return `${s.slice(0, 6)}-${s.slice(6, 12)}-${s.slice(12)}`;
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function handover(user, password) {
  fs.mkdirSync(OUT_DIR, { recursive: true, mode: 0o700 });
  const url = otpauthUrl(user.totp, user.email);
  let qr = '';
  try {
    const QR = (await import('qrcode')).default;
    qr = await QR.toString(url, { type: 'svg', margin: 1, width: 220 });
  } catch {
    qr = '<p>(QR তৈরির জন্য <code>npm install</code> চালান; নিচের গোপন কী হাতে লিখেও যোগ করা যায়।)</p>';
  }
  const file = path.join(OUT_DIR, `${user.email.replace(/[^a-z0-9@._-]/gi, '_')}.html`);
  fs.writeFileSync(file, `<!doctype html><meta charset="utf-8"><title>প্রবেশ তথ্য · ${esc(user.name)}</title>
<style>body{font-family:"Noto Sans Bengali",Nikosh,sans-serif;max-width:640px;margin:32px auto;padding:0 16px;line-height:1.6}code{font-size:15px;background:#f1f0eb;padding:2px 6px;border-radius:4px}.box{border:1px solid #ccc;border-radius:8px;padding:16px;margin:16px 0}</style>
<h2>বাংলাদেশ অর্থনৈতিক পর্যবেক্ষণাগার: ব্যক্তিগত প্রবেশ তথ্য</h2>
<p><b>গোপনীয়।</b> কেবল প্রাপকের জন্য। সিলমোহরকৃত খামে হস্তান্তর করুন; মুদ্রণের পর ফাইলটি মুছে ফেলুন।</p>
<div class="box"><p>নাম: <b>${esc(user.name)}</b><br>ইমেইল: <code>${esc(user.email)}</code><br>প্রাথমিক পাসওয়ার্ড: <code>${esc(password)}</code></p></div>
<div class="box"><p><b>ধাপ ১.</b> মোবাইলে Google Authenticator বা Microsoft Authenticator অ্যাপ খুলে নিচের QR কোড স্ক্যান করুন।</p>${qr}
<p>স্ক্যান না হলে গোপন কী হাতে লিখুন: <code>${esc(user.totp)}</code></p>
<p><b>ধাপ ২.</b> সাইটে ইমেইল, পাসওয়ার্ড ও অ্যাপে দেখানো ৬ অঙ্কের কোড দিয়ে প্রবেশ করুন। কোড প্রতি ৩০ সেকেন্ডে বদলায়।</p></div>
<p>পাসওয়ার্ড বা ফোন হারালে সঙ্গে সঙ্গে প্রশাসককে জানান; প্রবেশ বন্ধ করে নতুন তথ্য দেওয়া হবে।</p>`, { mode: 0o600 });
  return { file, url };
}

const [cmd, email, name, role] = process.argv.slice(2);
const users = load();
const find = (e) => users.find((u) => u.email === String(e || '').toLowerCase());

switch (cmd) {
  case 'add': {
    if (!email || !name) throw new Error('usage: add <email> "<name>" [viewer|admin]');
    if (find(email)) throw new Error(`${email} already exists; use reset`);
    const password = newPassword();
    const u = { email: email.toLowerCase(), name, role: role === 'admin' ? 'admin' : 'viewer', active: true, pw: await hashPassword(password), totp: newTotpSecret(), added: new Date().toISOString() };
    users.push(u); save(users);
    const h = await handover(u, password);
    console.log(`added ${u.email} (${u.role})\nhandover sheet: ${h.file}`);
    break;
  }
  case 'reset': {
    const u = find(email); if (!u) throw new Error('no such user');
    const password = newPassword();
    u.pw = await hashPassword(password); u.totp = newTotpSecret(); u.reset = new Date().toISOString(); save(users);
    const h = await handover(u, password);
    console.log(`reset ${u.email}\nhandover sheet: ${h.file}`);
    break;
  }
  case 'disable': case 'enable': {
    const u = find(email); if (!u) throw new Error('no such user');
    u.active = cmd === 'enable'; save(users); console.log(`${cmd}d ${u.email}`);
    break;
  }
  case 'remove': {
    const i = users.findIndex((u) => u.email === String(email).toLowerCase()); if (i < 0) throw new Error('no such user');
    users.splice(i, 1); save(users); console.log(`removed ${email}`);
    break;
  }
  case 'list':
    for (const u of users) console.log(`${u.active === false ? 'DISABLED' : 'active  '}  ${u.role.padEnd(6)}  ${u.email}  ${u.name}`);
    break;
  case 'export':
    console.log(b64u.enc(new TextEncoder().encode(JSON.stringify({ users }))));
    break;
  case 'secret':
    console.log(b64u.enc(randomBytes(48)));
    break;
  default:
    console.log('commands: add, reset, disable, enable, remove, list, export, secret');
}
