import driveService from '../server/drive-service.js';
const { env, isAuthConfigured, isDriveConfigured, safeEqual, signSession, readSession, setSessionCookie, clearSessionCookie, originMatchesRequest, sendJson, bodyObject } = driveService;

const attemptBuckets = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 8;
function isRateLimited(req) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  const now = Date.now();
  const prior = attemptBuckets.get(ip) || { count: 0, start: now };
  if (now - prior.start > WINDOW_MS) { attemptBuckets.set(ip, { count: 0, start: now }); return false; }
  return prior.count >= MAX_ATTEMPTS;
}
function recordFailure(req) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  const now = Date.now();
  const prior = attemptBuckets.get(ip) || { count: 0, start: now };
  const bucket = now - prior.start > WINDOW_MS ? { count: 1, start: now } : { count: prior.count + 1, start: prior.start };
  attemptBuckets.set(ip, bucket);
  // Defensive bound for warm function instances; production should also apply Vercel Firewall rate limiting.
  if (attemptBuckets.size > 1000) for (const [key, value] of attemptBuckets) if (now - value.start > WINDOW_MS) attemptBuckets.delete(key);
}

export default function handler(req, res) {
  if (req.method === 'GET') {
    const session = readSession(req);
    return sendJson(res, 200, { authenticated: !!session, role: session ? session.role : null, driveEnabled: isDriveConfigured() });
  }
  if (req.method === 'DELETE') {
    if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
    clearSessionCookie(req, res);
    return sendJson(res, 200, { authenticated: false });
  }
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
  if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
  if (!isAuthConfigured()) return sendJson(res, 503, { error: 'APP_AUTH_NOT_CONFIGURED' });
  if (isRateLimited(req)) return sendJson(res, 429, { error: 'Terlalu banyak percobaan PIN. Tunggu 15 menit sebelum mencoba lagi.' });

  const body = bodyObject(req);
  const role = String(body.role || '').toLowerCase();
  const pin = String(body.pin || '');
  if (!['admin', 'staff'].includes(role) || pin.length > 256) return sendJson(res, 400, { error: 'INVALID_CREDENTIALS' });
  const expected = role === 'admin' ? env('KARTU_STOCK_ADMIN_PIN') : env('KARTU_STOCK_STAFF_PIN');
  if (!safeEqual(pin, expected)) {
    recordFailure(req);
    return sendJson(res, 401, { authenticated: false, error: role === 'admin' ? 'PIN Admin salah.' : 'PIN Staff salah.' });
  }

  attemptBuckets.delete(String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim());
  const token = signSession(role);
  setSessionCookie(req, res, token);
  return sendJson(res, 200, { authenticated: true, role });
};
