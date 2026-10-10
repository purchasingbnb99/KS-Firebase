import crypto from 'node:crypto';

const SESSION_COOKIE = 'ks_drive_session';
const SESSION_SECONDS = 8 * 60 * 60;
const PRODUCT_FOLDER_NAME = 'KARTU STOCK Foto Produk';
const MAX_PHOTO_BYTES = 100 * 1024;
let cachedAccessToken = '';
let cachedAccessTokenExpiresAt = 0;

function env(name) { return String(process.env[name] || '').trim(); }
function isAuthConfigured() {
  return env('KARTU_STOCK_SESSION_SECRET').length >= 32 &&
    env('KARTU_STOCK_ADMIN_PIN').length >= 8 &&
    env('KARTU_STOCK_STAFF_PIN').length >= 8;
}
function isDriveConfigured() {
  return isAuthConfigured() && !!env('KARTU_STOCK_GOOGLE_CLIENT_ID') &&
    !!env('KARTU_STOCK_GOOGLE_CLIENT_SECRET') && !!env('KARTU_STOCK_GOOGLE_REFRESH_TOKEN');
}
function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}
function signText(text, secret = env('KARTU_STOCK_SESSION_SECRET')) {
  return crypto.createHmac('sha256', secret).update(text).digest('base64url');
}
function encodeState(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${data}.${signText(data)}`;
}
function decodeState(token) {
  if (!token || !token.includes('.')) return null;
  const [data, signature] = token.split('.', 2);
  if (!safeEqual(signText(data), signature)) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!payload || !Number.isFinite(Number(payload.iat))) return null;
    if (Date.now() - Number(payload.iat) > 10 * 60 * 1000 || Number(payload.iat) > Date.now() + 60 * 1000) return null;
    return payload;
  } catch (_) { return null; }
}
function signSession(role) {
  const now = Date.now();
  const payload = { role, iat: now, exp: now + SESSION_SECONDS * 1000, nonce: crypto.randomBytes(12).toString('hex') };
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${data}.${signText(data)}`;
}
function parseCookies(req) {
  const raw = String(req.headers.cookie || '');
  const cookies = {};
  raw.split(';').forEach(part => {
    const pos = part.indexOf('=');
    if (pos < 0) return;
    const name = part.slice(0, pos).trim();
    const value = part.slice(pos + 1).trim();
    if (name) cookies[name] = value;
  });
  return cookies;
}
function readSession(req) {
  if (!isAuthConfigured()) return null;
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token || !token.includes('.')) return null;
  const [data, signature] = token.split('.', 2);
  if (!safeEqual(signText(data), signature)) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!['admin', 'staff'].includes(payload.role) || Number(payload.exp) <= Date.now()) return null;
    return payload;
  } catch (_) { return null; }
}
function isSecureRequest(req) {
  const forwarded = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return forwarded === 'https' || !!req.socket?.encrypted;
}
function setSessionCookie(req, res, token) {
  const secure = isSecureRequest(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${SESSION_SECONDS}${secure}`);
}
function clearSessionCookie(req, res) {
  const secure = isSecureRequest(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0${secure}`);
}
function originMatchesRequest(req) {
  const origin = String(req.headers.origin || '').trim();
  if (!origin) return true; // non-browser clients are still protected by the signed session/PIN
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim().toLowerCase();
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  const protocol = forwardedProto === 'https' || req.socket?.encrypted ? 'https:' : 'http:';
  try {
    const parsedOrigin = new URL(origin);
    return parsedOrigin.host.toLowerCase() === host && parsedOrigin.protocol === protocol;
  } catch (_) { return false; }
}
function sendJson(res, status, value) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(value));
}
function bodyObject(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (_) { return {}; } }
  return {};
}
function sanitizeFileName(value) {
  const safe = String(value || 'foto-produk.jpg').normalize('NFKD')
    .replace(/[^a-zA-Z0-9._ -]/g, '-')
    .replace(/\s+/g, ' ')
    .replace(/\.\.+/g, '.')
    .trim().slice(0, 100);
  return (safe || 'foto-produk.jpg').toLowerCase().endsWith('.jpg') ? (safe || 'foto-produk.jpg') : `${safe || 'foto-produk'}.jpg`;
}

async function getDriveAccessToken() {
  if (!isDriveConfigured()) throw new Error('DRIVE_NOT_CONFIGURED');
  if (cachedAccessToken && cachedAccessTokenExpiresAt > Date.now() + 60 * 1000) return cachedAccessToken;
  const params = new URLSearchParams({
    client_id: env('KARTU_STOCK_GOOGLE_CLIENT_ID'),
    client_secret: env('KARTU_STOCK_GOOGLE_CLIENT_SECRET'),
    refresh_token: env('KARTU_STOCK_GOOGLE_REFRESH_TOKEN'),
    grant_type: 'refresh_token'
  });
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) {
    cachedAccessToken = '';
    cachedAccessTokenExpiresAt = 0;
    console.error('Google OAuth refresh failed with status', response.status);
    throw new Error('GOOGLE_TOKEN_REFRESH_FAILED');
  }
  cachedAccessToken = result.access_token;
  cachedAccessTokenExpiresAt = Date.now() + Math.max(60, Number(result.expires_in || 3600)) * 1000;
  return cachedAccessToken;
}
async function driveApi(accessToken, url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { Authorization: `Bearer ${accessToken}`, ...(options.headers || {}) }
  });
  if (!response.ok) {
    // Do not log or send tokens, file contents, client secrets, or refresh tokens.
    const status = response.status;
    await response.arrayBuffer().catch(() => null);
    const error = new Error('GOOGLE_DRIVE_API_FAILED');
    error.status = status;
    throw error;
  }
  return response;
}
async function getOrCreateProductFolder(accessToken) {
  // drive.file scope can manage app-created folders/files without making the folder public.
  const q = `name = '${PRODUCT_FOLDER_NAME}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
  const listUrl = `https://www.googleapis.com/drive/v3/files?q=${encodeURIComponent(q)}&pageSize=20&fields=files(id,name,mimeType,parents)`;
  const listResponse = await driveApi(accessToken, listUrl);
  const list = await listResponse.json();
  const existing = Array.isArray(list.files) ? list.files.find(file => file.mimeType === 'application/vnd.google-apps.folder') : null;
  if (existing?.id) return existing;

  const createResponse = await driveApi(accessToken, 'https://www.googleapis.com/drive/v3/files?fields=id,name,mimeType', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: PRODUCT_FOLDER_NAME, mimeType: 'application/vnd.google-apps.folder' })
  });
  const created = await createResponse.json();
  if (!created.id) throw new Error('GOOGLE_DRIVE_FOLDER_CREATE_FAILED');
  return created;
}
async function getDriveFileInProductFolder(accessToken, fileId, folderId) {
  if (!/^[a-zA-Z0-9_-]{10,200}$/.test(String(fileId || ''))) return null;
  const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?fields=id,name,mimeType,parents,size,trashed`;
  const response = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error('GOOGLE_DRIVE_METADATA_FAILED');
  const file = await response.json();
  if (file.trashed || !Array.isArray(file.parents) || !file.parents.includes(folderId)) return null;
  if (!String(file.mimeType || '').startsWith('image/')) return null;
  if (Number(file.size || 0) > MAX_PHOTO_BYTES) return null;
  return file;
}
async function uploadDrivePhoto(accessToken, fileName, mimeType, bytes) {
  const folder = await getOrCreateProductFolder(accessToken);
  const boundary = `ks_${crypto.randomBytes(12).toString('hex')}`;
  const metadata = JSON.stringify({ name: sanitizeFileName(fileName), mimeType, parents: [folder.id] });
  const start = Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: ${mimeType}\r\n\r\n`, 'utf8');
  const end = Buffer.from(`\r\n--${boundary}--`, 'utf8');
  const body = Buffer.concat([start, bytes, end]);
  const response = await driveApi(accessToken, 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,mimeType,parents', {
    method: 'POST', headers: { 'Content-Type': `multipart/related; boundary=${boundary}` }, body
  });
  const file = await response.json();
  if (!file.id) throw new Error('GOOGLE_DRIVE_UPLOAD_FAILED');
  return { ...file, folderId: folder.id };
}
async function readDrivePhoto(accessToken, fileId) {
  const folder = await getOrCreateProductFolder(accessToken);
  const file = await getDriveFileInProductFolder(accessToken, fileId, folder.id);
  if (!file) return null;
  const response = await driveApi(accessToken, `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (!bytes.length || bytes.length > MAX_PHOTO_BYTES) return null;
  return { file, bytes };
}
async function deleteDrivePhoto(accessToken, fileId) {
  const folder = await getOrCreateProductFolder(accessToken);
  const file = await getDriveFileInProductFolder(accessToken, fileId, folder.id);
  if (!file) return false;
  const response = await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}`, {
    method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!response.ok && response.status !== 404) throw new Error('GOOGLE_DRIVE_DELETE_FAILED');
  return true;
}
function verifySignedState(state) { return decodeState(state); }

export default {
  SESSION_COOKIE, SESSION_SECONDS, MAX_PHOTO_BYTES,
  env, isAuthConfigured, isDriveConfigured, safeEqual, encodeState, verifySignedState,
  signSession, readSession, setSessionCookie, clearSessionCookie, originMatchesRequest,
  sendJson, bodyObject, sanitizeFileName, getDriveAccessToken, getOrCreateProductFolder,
  uploadDrivePhoto, readDrivePhoto, deleteDrivePhoto
};
