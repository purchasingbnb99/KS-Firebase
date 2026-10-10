import driveService from '../../_lib/drive-service.mjs';
const { env, verifySignedState, sendJson } = driveService;

function htmlEscape(value) {
  return String(value || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function sendHtml(res, status, html) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'");
  res.end(html);
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
  const code = String(req.query?.code || '');
  const state = verifySignedState(String(req.query?.state || ''));
  if (!state || !code) {
    return sendHtml(res, 400, '<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Setup gagal</title><body style="font:16px system-ui;background:#0b1120;color:#e2e8f0;padding:2rem"><h1>Setup OAuth tidak valid atau sudah kedaluwarsa.</h1><p>Buka halaman setup lagi dan ulangi proses.</p></body></html>');
  }
  const clientId = env('KARTU_STOCK_GOOGLE_CLIENT_ID');
  const clientSecret = env('KARTU_STOCK_GOOGLE_CLIENT_SECRET');
  const redirectUri = env('KARTU_STOCK_GOOGLE_REDIRECT_URI');
  try {
    const params = new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' });
    const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
    const tokens = await response.json().catch(() => ({}));
    if (!response.ok || !tokens.refresh_token) {
      console.error('OAuth callback failed without logging secrets. Status:', response.status);
      const message = !response.ok ? 'Google gagal menyelesaikan OAuth. Periksa redirect URI, consent screen, dan akun yang dipilih.' : 'Google tidak mengembalikan refresh token. Cabut izin aplikasi lalu ulangi dengan persetujuan baru.';
      return sendHtml(res, 400, `<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Setup gagal</title><body style="font:16px system-ui;background:#0b1120;color:#e2e8f0;padding:2rem"><h1>OAuth belum selesai</h1><p>${htmlEscape(message)}</p></body></html>`);
    }
    const refreshToken = htmlEscape(tokens.refresh_token);
    const html = `<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Token Drive didapat</title></head><body style="font:16px system-ui;background:#0b1120;color:#e2e8f0;padding:2rem;max-width:760px;margin:auto"><h1 style="color:#4ade80">Otorisasi Google berhasil</h1><p>Refresh token hanya ditampilkan di halaman ini dan tidak disimpan oleh aplikasi secara persisten. Jangan kirim token ini lewat chat, email, atau repository.</p><label for="token">Salin nilai ini ke Vercel Environment Variable <code>KARTU_STOCK_GOOGLE_REFRESH_TOKEN</code></label><textarea id="token" readonly spellcheck="false" style="display:block;box-sizing:border-box;width:100%;min-height:120px;padding:12px;margin:12px 0;background:#020617;color:#f8fafc;border:1px solid #334155;border-radius:8px">${refreshToken}</textarea><button onclick="navigator.clipboard.writeText(document.getElementById('token').value)" style="padding:10px 16px;border:0;border-radius:8px;background:#fb923c;color:#111827;font-weight:700">Salin token</button><p style="color:#94a3b8">Setelah nilai disimpan di Vercel, hapus environment variable setup key bila Anda tidak membutuhkannya lagi, lalu redeploy Production.</p><p style="color:#94a3b8">Setelah token disalin, tutup halaman ini.</p></body></html>`;
    return sendHtml(res, 200, html);
  } catch (error) {
    console.error('OAuth callback network failure:', error.message || 'UNKNOWN');
    return sendHtml(res, 502, '<!doctype html><html lang="id"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Setup gagal</title><body style="font:16px system-ui;background:#0b1120;color:#e2e8f0;padding:2rem"><h1>Gagal menghubungi Google OAuth</h1><p>Coba lagi setelah memeriksa konfigurasi deployment.</p></body></html>');
  }
};
