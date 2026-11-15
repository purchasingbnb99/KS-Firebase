import driveService from '../_lib/drive-service.mjs';
const {
  isDriveConfigured,
  readSession,
  originMatchesRequest,
  sendJson,
  bodyObject,
  getDriveAccessToken,
  getExistingProductFolder,
  auditDrivePhotoInProductFolder
} = driveService;

const MAX_AUDIT_FILES = 5;

export default async function handler(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
  if (!originMatchesRequest(req)) return sendJson(res, 403, { error: 'ORIGIN_NOT_ALLOWED' });
  if (!isDriveConfigured()) return sendJson(res, 503, { error: 'GOOGLE_DRIVE_NOT_CONFIGURED' });

  const session = readSession(req);
  if (!session) return sendJson(res, 401, { error: 'ADMIN_SESSION_REQUIRED' });
  if (session.role !== 'admin') return sendJson(res, 403, { error: 'ADMIN_REQUIRED' });

  const body = bodyObject(req);
  const input = Array.isArray(body.fileIds) ? body.fileIds : [];
  const fileIds = [...new Set(input.map(value => String(value || '').trim()).filter(Boolean))];
  if (!fileIds.length) return sendJson(res, 400, { error: 'FILE_IDS_REQUIRED' });
  if (fileIds.length > MAX_AUDIT_FILES) return sendJson(res, 400, { error: `MAX_${MAX_AUDIT_FILES}_UNIQUE_FILES_PER_REQUEST` });

  try {
    const accessToken = await getDriveAccessToken();
    const folder = await getExistingProductFolder(accessToken);
    if (!folder?.id) {
      const results = fileIds.map(fileId => ({ file_id: fileId, status: 'product_folder_not_found' }));
      return sendJson(res, 200, {
        generated_at: new Date().toISOString(), mode: 'read_only_drive_content_check',
        summary: { total_checked: results.length, healthy: 0, attention_required: results.length, checksum_verified: 0, total_size_bytes: 0 },
        results
      });
    }
    const results = [];
    // Sequential inspection deliberately limits Drive request bursts and serverless execution time.
    for (const fileId of fileIds) {
      try {
        results.push(await auditDrivePhotoInProductFolder(accessToken, fileId, folder.id));
      } catch (error) {
        console.error('Drive photo health check item failed:', error?.message || 'UNKNOWN');
        results.push({ file_id: fileId, status: 'check_failed' });
      }
    }
    const summary = {
      total_checked: results.length,
      healthy: results.filter(item => item.status === 'healthy').length,
      attention_required: results.filter(item => item.status !== 'healthy').length,
      checksum_verified: results.filter(item => item.checksum === 'verified_md5').length,
      total_size_bytes: results.filter(item => item.status === 'healthy').reduce((sum, item) => sum + Number(item.size_bytes || 0), 0)
    };
    return sendJson(res, 200, {
      generated_at: new Date().toISOString(),
      mode: 'read_only_drive_content_check',
      summary,
      results
    });
  } catch (error) {
    console.error('Drive photo health audit failed:', error?.message || 'UNKNOWN');
    return sendJson(res, 502, {
      error: error?.message === 'GOOGLE_TOKEN_REFRESH_FAILED' ? 'GOOGLE_TOKEN_REFRESH_FAILED' : 'DRIVE_PHOTO_AUDIT_FAILED'
    });
  }
}
