import crypto from 'node:crypto';
import driveService from './_lib/drive-service.mjs';

const {
  env,
  readSession,
  originMatchesRequest,
  sendJson,
  bodyObject
} = driveService;

const EXPECTED_PROJECT_ID = 'kartustock-8c988';
const FIRESTORE_SCOPE = 'https://www.googleapis.com/auth/datastore';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${EXPECTED_PROJECT_ID}/databases/(default)/documents`;
const MAX_SNAPSHOT_BYTES = 800000;
const MAX_PRODUCTS = 25000;

let cachedAccessToken = '';
let cachedAccessTokenExpiresAt = 0;
let cachedTokenForEmail = '';

function jsonError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function readServiceAccount() {
  let account = null;
  const rawJson = env('FIREBASE_SERVICE_ACCOUNT_JSON');

  if (rawJson) {
    try {
      account = JSON.parse(rawJson);
    } catch (_) {
      throw jsonError(503, 'FIREBASE_SERVICE_ACCOUNT_INVALID',
        'FIREBASE_SERVICE_ACCOUNT_JSON tidak dapat dibaca sebagai JSON. Periksa Environment Variables Vercel.');
    }
  } else {
    account = {
      project_id: env('FIREBASE_PROJECT_ID'),
      client_email: env('FIREBASE_CLIENT_EMAIL'),
      private_key: env('FIREBASE_PRIVATE_KEY')
    };
  }

  const projectId = String(account?.project_id || env('FIREBASE_PROJECT_ID') || '').trim();
  const clientEmail = String(account?.client_email || env('FIREBASE_CLIENT_EMAIL') || '').trim();
  const privateKey = String(account?.private_key || env('FIREBASE_PRIVATE_KEY') || '').replace(/\\n/g, '\n').trim();

  if (projectId !== EXPECTED_PROJECT_ID) {
    throw jsonError(503, 'FIREBASE_PROJECT_MISMATCH',
      `Service Account harus berasal dari project ${EXPECTED_PROJECT_ID}.`);
  }
  if (!clientEmail || !privateKey.includes('BEGIN PRIVATE KEY')) {
    throw jsonError(503, 'FIREBASE_SERVICE_ACCOUNT_NOT_CONFIGURED',
      'Service Account Firestore belum dikonfigurasi di Environment Variables Vercel.');
  }

  return { projectId, clientEmail, privateKey };
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

async function getFirestoreAccessToken(account) {
  if (
    cachedAccessToken &&
    cachedAccessTokenExpiresAt > Date.now() + 60_000 &&
    cachedTokenForEmail === account.clientEmail
  ) {
    return cachedAccessToken;
  }

  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: account.clientEmail,
    scope: FIRESTORE_SCOPE,
    aud: TOKEN_URL,
    iat: now,
    exp: now + 3600
  }));
  const unsigned = `${header}.${claims}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();

  let signature;
  try {
    signature = signer.sign(account.privateKey, 'base64url');
  } catch (_) {
    throw jsonError(503, 'FIREBASE_PRIVATE_KEY_INVALID',
      'Private key Service Account tidak valid. Periksa format private_key pada Vercel.');
  }

  const assertion = `${unsigned}.${signature}`;
  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    })
  });

  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) {
    console.error('Firestore service-account token exchange failed:', response.status, result.error || 'TOKEN_ERROR');
    throw jsonError(503, 'FIREBASE_TOKEN_EXCHANGE_FAILED',
      'Vercel gagal memperoleh token Firestore. Periksa Service Account dan izin project.');
  }

  cachedAccessToken = String(result.access_token);
  cachedAccessTokenExpiresAt = Date.now() + Math.max(60, Number(result.expires_in || 3600)) * 1000;
  cachedTokenForEmail = account.clientEmail;
  return cachedAccessToken;
}

function decodeFirestoreValue(value) {
  if (!value || typeof value !== 'object') return null;
  if ('nullValue' in value) return null;
  if ('stringValue' in value) return value.stringValue;
  if ('booleanValue' in value) return value.booleanValue;
  if ('integerValue' in value) return Number(value.integerValue);
  if ('doubleValue' in value) return Number(value.doubleValue);
  if ('timestampValue' in value) return value.timestampValue;
  if ('referenceValue' in value) return value.referenceValue;
  if ('bytesValue' in value) return value.bytesValue;
  if ('arrayValue' in value) return (value.arrayValue.values || []).map(decodeFirestoreValue);
  if ('mapValue' in value) return decodeFirestoreMap(value.mapValue.fields || {});
  return null;
}

function decodeFirestoreMap(fields) {
  const result = {};
  for (const [key, value] of Object.entries(fields || {})) {
    result[key] = decodeFirestoreValue(value);
  }
  return result;
}

function encodeFirestoreValue(value) {
  if (value === null || value === undefined) return { nullValue: 'NULL_VALUE' };
  if (typeof value === 'string') return { stringValue: value };
  if (typeof value === 'boolean') return { booleanValue: value };
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('SNAPSHOT_NUMBER_INVALID');
    return Number.isSafeInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }
  if (Array.isArray(value)) {
    return { arrayValue: { values: value.map(encodeFirestoreValue) } };
  }
  if (typeof value === 'object') {
    return { mapValue: { fields: encodeFirestoreMap(value) } };
  }
  return { stringValue: String(value) };
}

function encodeFirestoreMap(value) {
  const fields = {};
  for (const [key, fieldValue] of Object.entries(value || {})) {
    fields[key] = encodeFirestoreValue(fieldValue);
  }
  return fields;
}

async function firestoreRequest(accessToken, url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      ...(options.headers || {})
    }
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const status = String(payload?.error?.status || '');
    const message = String(payload?.error?.message || '');
    const error = new Error('FIRESTORE_API_ERROR');
    error.status = response.status;
    error.code = status || `HTTP_${response.status}`;
    error.detail = message.slice(0, 240);
    throw error;
  }
  return payload;
}

function validPeriod(period) {
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(period || ''))) return false;
  const [year, month] = period.split('-').map(Number);
  return year >= 2020 && year <= 2100 && month >= 1 && month <= 12;
}

function previousPeriod(period) {
  const [year, month] = period.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 2, 1));
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

function jakartaDateParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Jakarta',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(date);
  const result = {};
  for (const part of parts) if (part.type !== 'literal') result[part.type] = part.value;
  return result;
}

function jakartaPeriodKey(parts = jakartaDateParts()) {
  return `${parts.year}-${parts.month}`;
}

function lastDayOfPeriod(period) {
  const [year, month] = period.split('-').map(Number);
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function periodLabel(period) {
  const [year, month] = period.split('-').map(Number);
  return new Date(Date.UTC(year, month - 1, 1)).toLocaleDateString('id-ID', {
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC'
  });
}

function normalizeProduct(doc) {
  const data = decodeFirestoreMap(doc.fields || {});
  const documentId = String(doc.name || '').split('/').pop();
  const stock = Number(data.stock ?? 0);
  const unitPrice = Number(data.price ?? 0);
  const sku = String(data.sku || '').trim().toUpperCase();

  if (!Number.isFinite(stock) || stock < 0) {
    throw jsonError(422, 'INVALID_PRODUCT_STOCK',
      `Stok tidak valid pada SKU ${sku || documentId}. Snapshot dibatalkan.`);
  }
  if (!Number.isFinite(unitPrice) || unitPrice < 0) {
    throw jsonError(422, 'INVALID_PRODUCT_PRICE',
      `Harga satuan tidak valid pada SKU ${sku || documentId}. Snapshot dibatalkan.`);
  }

  const assetValue = stock * unitPrice;
  if (!Number.isFinite(assetValue)) {
    throw jsonError(422, 'INVALID_ASSET_VALUE',
      `Nilai aset tidak valid pada SKU ${sku || documentId}. Snapshot dibatalkan.`);
  }

  return {
    product_id: String(data.id || documentId),
    sku,
    name: String(data.name || '').trim(),
    origin: String(data.origin || 'lokal').trim().toLowerCase(),
    category: String(data.category || 'General'),
    warehouse: String(data.warehouse || 'Gudang Utama A'),
    shelf: String(data.shelf || 'A-01'),
    stock,
    unit_price: unitPrice,
    asset_value: assetValue
  };
}

async function listAllProducts(accessToken) {
  const records = [];
  let pageToken = '';

  do {
    const url = new URL(`${FIRESTORE_BASE}/products`);
    url.searchParams.set('pageSize', '1000');
    if (pageToken) url.searchParams.set('pageToken', pageToken);

    const result = await firestoreRequest(accessToken, url.toString());
    const docs = Array.isArray(result.documents) ? result.documents : [];
    records.push(...docs);

    if (records.length > MAX_PRODUCTS) {
      throw jsonError(413, 'PRODUCT_LIMIT_EXCEEDED',
        `Jumlah barang melebihi batas snapshot saat ini (${MAX_PRODUCTS.toLocaleString('id-ID')} SKU). Snapshot dibatalkan.`);
    }
    pageToken = String(result.nextPageToken || '');
  } while (pageToken);

  return records;
}

async function getSnapshot(accessToken, period) {
  const url = `${FIRESTORE_BASE}/monthlyAssetSnapshots/${encodeURIComponent(period)}`;
  try {
    const result = await firestoreRequest(accessToken, url);
    return decodeFirestoreMap(result.fields || {});
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function createSnapshot(accessToken, period, session) {
  const jakarta = jakartaDateParts();
  const currentPeriod = jakartaPeriodKey(jakarta);
  const lastDay = lastDayOfPeriod(period);

  if (period !== currentPeriod || Number(jakarta.day) !== lastDay) {
    throw jsonError(400, 'MONTH_END_ONLY',
      `Tutup buku hanya dapat dilakukan pada hari terakhir bulan berjalan di zona waktu Asia/Jakarta (${lastDay} ${periodLabel(period)}).`);
  }

  const existing = await getSnapshot(accessToken, period);
  if (existing) {
    throw jsonError(409, 'SNAPSHOT_ALREADY_EXISTS',
      'Snapshot periode ini sudah dibuat. Data tidak ditimpa.');
  }

  const productDocs = await listAllProducts(accessToken);
  if (!productDocs.length) {
    throw jsonError(422, 'PRODUCTS_EMPTY',
      'Tidak ada master barang di Firestore. Snapshot kosong tidak dibuat.');
  }

  const items = productDocs.map(normalizeProduct)
    .sort((a, b) => String(a.sku).localeCompare(String(b.sku), undefined, {
      numeric: true,
      sensitivity: 'base'
    }));

  const totalAsset = items.reduce((sum, item) => sum + item.asset_value, 0);
  const totalStock = items.reduce((sum, item) => sum + item.stock, 0);
  const localValue = items
    .filter(item => item.origin === 'lokal')
    .reduce((sum, item) => sum + item.asset_value, 0);
  const importValue = items
    .filter(item => item.origin === 'import')
    .reduce((sum, item) => sum + item.asset_value, 0);
  const capturedAt = new Date().toISOString();

  const payload = {
    schema_version: 1,
    period,
    period_label: periodLabel(period),
    snapshot_status: 'closed',
    snapshot_method: 'manual_month_end_closing',
    captured_at: capturedAt,
    captured_by: 'Admin',
    captured_role: String(session.role || 'admin'),
    source: 'Firestore products collection (server read)',
    item_count: items.length,
    total_stock_quantity: totalStock,
    total_asset_value: totalAsset,
    total_asset_local: localValue,
    total_asset_import: importValue,
    total_asset_other: totalAsset - localValue - importValue,
    items
  };

  const bytes = Buffer.byteLength(JSON.stringify(payload), 'utf8');
  if (bytes > MAX_SNAPSHOT_BYTES) {
    throw jsonError(413, 'SNAPSHOT_TOO_LARGE',
      `Data snapshot sekitar ${(bytes / 1024).toFixed(0)} KB. Batas aman dokumen tunggal terlampaui; snapshot dibatalkan.`);
  }

  // Firestore createDocument is create-only: a document with the same period ID cannot be overwritten.
  const createUrl = new URL(`${FIRESTORE_BASE}/monthlyAssetSnapshots`);
  createUrl.searchParams.set('documentId', period);
  try {
    await firestoreRequest(accessToken, createUrl.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fields: encodeFirestoreMap(payload) })
    });
  } catch (error) {
    if (error.status === 409 || /ALREADY_EXISTS|FAILED_PRECONDITION/i.test(String(error.code || ''))) {
      throw jsonError(409, 'SNAPSHOT_ALREADY_EXISTS',
        'Snapshot periode ini sudah dibuat. Data tidak ditimpa.');
    }
    throw error;
  }

  return payload;
}

function readRequestPeriod(req) {
  let url;
  try {
    const host = String(req.headers['x-forwarded-host'] || req.headers.host || 'localhost');
    const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
    url = new URL(req.url || '/', `${proto}://${host}`);
  } catch (_) {
    throw jsonError(400, 'INVALID_REQUEST_URL', 'Alamat permintaan tidak valid.');
  }

  const period = url.searchParams.get('period') || '';
  if (!validPeriod(period)) {
    throw jsonError(400, 'INVALID_PERIOD', 'Periode harus menggunakan format YYYY-MM yang valid.');
  }
  return period;
}

function publicError(error) {
  if (
    error?.message === 'FIRESTORE_API_ERROR' &&
    ['PERMISSION_DENIED', 'UNAUTHENTICATED'].includes(String(error?.code || ''))
  ) {
    return {
      status: 503,
      code: 'FIRESTORE_IAM_PERMISSION_DENIED',
      message: 'Service Account tidak memiliki izin Firestore yang dibutuhkan. Periksa IAM custom role pada Google Cloud project.'
    };
  }
  if (error?.status && error?.code) {
    return {
      status: error.status,
      code: error.code,
      message: error.message
    };
  }
  if (error?.status === 404) {
    return {
      status: 503,
      code: 'FIRESTORE_RESOURCE_NOT_FOUND',
      message: 'Database Firestore tidak ditemukan pada project yang dikonfigurasi.'
    };
  }
  return {
    status: 500,
    code: 'MONTHLY_ASSET_OPERATION_FAILED',
    message: 'Operasi Monthly Asset Valuation gagal. Periksa konfigurasi Service Account dan log Vercel.'
  };
}

export default async function handler(req, res) {
  if (!['GET', 'POST'].includes(req.method)) {
    return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'Metode tidak diizinkan.' });
  }

  if (!originMatchesRequest(req)) {
    return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED', message: 'Origin permintaan tidak diizinkan.' });
  }

  const session = readSession(req);
  if (!session) {
    return sendJson(res, 401, {
      error: 'ADMIN_SESSION_REQUIRED',
      message: 'Sesi Admin server tidak aktif. Login Admin kembali.'
    });
  }
  if (session.role !== 'admin') {
    return sendJson(res, 403, {
      error: 'ADMIN_ONLY',
      message: 'Monthly Asset Valuation hanya dapat diakses Admin.'
    });
  }

  try {
    const account = readServiceAccount();
    const accessToken = await getFirestoreAccessToken(account);

    if (req.method === 'GET') {
      const period = readRequestPeriod(req);
      const previous = previousPeriod(period);
      const [snapshot, previousSnapshot] = await Promise.all([
        getSnapshot(accessToken, period),
        getSnapshot(accessToken, previous)
      ]);
      return sendJson(res, 200, { snapshot, previousSnapshot });
    }

    const body = bodyObject(req);
    const period = String(body.period || '').trim();
    if (!validPeriod(period)) {
      return sendJson(res, 400, {
        error: 'INVALID_PERIOD',
        message: 'Periode harus menggunakan format YYYY-MM yang valid.'
      });
    }

    const snapshot = await createSnapshot(accessToken, period, session);
    return sendJson(res, 201, { snapshot });
  } catch (error) {
    const result = publicError(error);
    if (result.status >= 500) {
      console.error('Monthly Asset Valuation API error:', error?.code || error?.message || 'UNKNOWN');
    }
    return sendJson(res, result.status, {
      error: result.code,
      message: result.message
    });
  }
}
