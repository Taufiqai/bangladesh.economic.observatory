// Vercel Routing Middleware: every request passes through the access gate first.
// Vercel রাউটিং মিডলওয়্যার: প্রতিটি অনুরোধ আগে প্রবেশ-নিয়ন্ত্রণ পার হয়।
import { next } from '@vercel/functions';
import { createGate } from './auth/core.mjs';

export const config = {
  matcher: ['/', '/:path*'],
  runtime: 'nodejs',
};

let gate;
function getGate() {
  if (!gate) {
    gate = createGate({
      secret: process.env.OBS_SESSION_SECRET,
      getUsers: () => process.env.OBS_USERS || '',
      sessionHours: process.env.OBS_SESSION_HOURS,
      epoch: process.env.OBS_SESSION_EPOCH,
      allowedCidrs: (process.env.OBS_ALLOWED_CIDRS || '').split(',').map((s) => s.trim()),
      secureCookie: true,
    });
  }
  return gate;
}

export default async function middleware(request) {
  let g;
  try {
    g = getGate();
  } catch (err) {
    console.error(JSON.stringify({ ev: 'gate_misconfigured', error: String(err.message || err) }));
    // Fail closed: if the gate is not configured, nobody gets in.
    return new Response('Access gate is not configured. / প্রবেশ-নিয়ন্ত্রণ কনফিগার করা হয়নি।', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  const result = await g.handle(request);
  if (result.response) return result.response;
  return next({ headers: result.headers });
}
