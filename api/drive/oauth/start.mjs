import crypto from 'node:crypto';
import driveService from '../../../server/drive-service.js';
const { env, isAuthConfigured, safeEqual, encodeState, originMatchesRequest, sendJson, bodyObject } = driveService;

export default function handler(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
  if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
  const setupKey = env('KARTU_STOCK_DRIVE_SETUP_KEY');
  const clientId = env('KARTU_STOCK_GOOGLE_CLIENT_ID');
  const redirectUri = env('KARTU_STOCK_GOOGLE_REDIRECT_URI');
  if (!setupKey || setupKey.length < 24 || !clientId || !env('KARTU_STOCK_GOOGLE_CLIENT_SECRET') || !redirectUri || !isAuthConfigured()) {
    return sendJson(res, 503, { error: 'Konfigurasi awal OAuth belum lengkap di Vercel.' });
  }
  const body = bodyObject(req);
  if (!safeEqual(String(body.setupKey || ''), setupKey)) return sendJson(res, 403, { error: 'Kunci setup tidak cocok.' });

  const state = encodeState({ iat: Date.now(), nonce: crypto.randomBytes(20).toString('hex') });
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'https://www.googleapis.com/auth/drive.file');
  url.searchParams.set('access_type', 'offline');
  url.searchParams.set('prompt', 'consent');
  url.searchParams.set('include_granted_scopes', 'true');
  url.searchParams.set('state', state);
  return sendJson(res, 200, { authorizationUrl: url.toString() });
};
