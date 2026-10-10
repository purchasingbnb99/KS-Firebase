import driveService from '../../server/drive-service.js';
const { isAuthConfigured, isDriveConfigured, sendJson } = driveService;

export default function handler(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { enabled: false, error: 'METHOD_NOT_ALLOWED' });
  // Only a boolean is returned. Never expose OAuth credentials, folder details, or PIN configuration.
  return sendJson(res, 200, { enabled: isDriveConfigured(), authConfigured: isAuthConfigured(), storage: isDriveConfigured() ? 'google-drive-private' : 'firestore-legacy' });
};
