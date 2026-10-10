import driveService from '../../server/drive-service.js';
const { MAX_PHOTO_BYTES, isDriveConfigured, readSession, originMatchesRequest, sendJson, bodyObject, getDriveAccessToken, uploadDrivePhoto, readDrivePhoto, deleteDrivePhoto } = driveService;

export default async function handler(req, res) {
  if (!isDriveConfigured()) return sendJson(res, 503, { error: 'Google Drive belum dikonfigurasi. Mode penyimpanan lama tetap digunakan.' });
  const session = readSession(req);
  if (!session) return sendJson(res, 401, { error: 'Sesi aplikasi sudah berakhir. Masuk kembali menggunakan PIN aplikasi.' });

  if (req.method === 'GET') {
    const fileId = String(req.query?.id || '');
    if (!fileId) return sendJson(res, 400, { error: 'FILE_ID_REQUIRED' });
    try {
      const accessToken = await getDriveAccessToken();
      const result = await readDrivePhoto(accessToken, fileId);
      if (!result) return sendJson(res, 404, { error: 'PHOTO_NOT_FOUND' });
      res.statusCode = 200;
      res.setHeader('Content-Type', result.file.mimeType || 'image/jpeg');
      res.setHeader('Content-Length', String(result.bytes.length));
      res.setHeader('Cache-Control', 'private, no-store, max-age=0');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
      return res.end(result.bytes);
    } catch (error) {
      console.error('Drive photo read failed:', error.message || 'UNKNOWN');
      return sendJson(res, 502, { error: 'Foto tidak dapat diambil dari Google Drive saat ini.' });
    }
  }

  if (req.method === 'POST') {
    if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
    if (session.role !== 'admin') return sendJson(res, 403, { error: 'ADMIN_REQUIRED' });
    const body = bodyObject(req);
    const dataUrl = String(body.dataUrl || '');
    const match = dataUrl.length <= 150 * 1024 ? dataUrl.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/i) : null;
    if (!match) return sendJson(res, 400, { error: 'FORMAT_IMAGE_NOT_SUPPORTED_OR_TOO_LARGE' });
    const mimeType = 'image/jpeg';
    const bytes = Buffer.from(match[1], 'base64');
    if (!bytes.length || bytes.length > MAX_PHOTO_BYTES) return sendJson(res, 413, { error: 'PHOTO_TOO_LARGE' });
    if (bytes.length < 3 || bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes[2] !== 0xff) return sendJson(res, 400, { error: 'INVALID_IMAGE_CONTENT' });
    const fileName = String(body.fileName || 'foto-produk.jpg').slice(0, 160);
    try {
      const accessToken = await getDriveAccessToken();
      const file = await uploadDrivePhoto(accessToken, fileName, mimeType, bytes);
      return sendJson(res, 201, { fileId: file.id, fileName: file.name, src: `/api/drive/photos?id=${encodeURIComponent(file.id)}` });
    } catch (error) {
      console.error('Drive photo upload failed:', error.message || 'UNKNOWN');
      return sendJson(res, 502, { error: 'Upload foto ke Google Drive gagal. Data barang belum disimpan.' });
    }
  }

  if (req.method === 'DELETE') {
    if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
    if (session.role !== 'admin') return sendJson(res, 403, { error: 'ADMIN_REQUIRED' });
    const fileId = String(req.query?.id || '');
    if (!fileId) return sendJson(res, 400, { error: 'FILE_ID_REQUIRED' });
    try {
      const accessToken = await getDriveAccessToken();
      await deleteDrivePhoto(accessToken, fileId);
      return sendJson(res, 200, { deleted: true });
    } catch (error) {
      console.error('Drive photo cleanup failed:', error.message || 'UNKNOWN');
      return sendJson(res, 502, { error: 'Pembersihan foto sementara gagal.' });
    }
  }
  return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
};
