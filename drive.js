// Google Drive upload (OAuth refresh token of the account that owns the folders)
// Files go to: <DRIVE_ROOT_FOLDER>/<Location name>/<file>.pdf
const ROOT = () => process.env.DRIVE_ROOT_FOLDER || 'MBG-Daily Report';
const enabled = () => !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REFRESH_TOKEN);

let cached = { token: null, exp: 0 };
async function accessToken() {
  if (cached.token && Date.now() < cached.exp) return cached.token;
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
      refresh_token: process.env.GOOGLE_REFRESH_TOKEN, grant_type: 'refresh_token'
    })
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Google auth failed: ' + (j.error_description || j.error));
  cached = { token: j.access_token, exp: Date.now() + (j.expires_in - 60) * 1000 };
  return cached.token;
}

async function api(url, opts = {}) {
  const r = await fetch(url, { ...opts, headers: { Authorization: 'Bearer ' + await accessToken(), ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error('Drive error ' + r.status + ': ' + (j.error?.message || ''));
  return j;
}

const q = s => s.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
async function ensureFolder(name, parentId) {
  const query = `mimeType='application/vnd.google-apps.folder' and trashed=false and name='${q(name)}'` + (parentId ? ` and '${parentId}' in parents` : ` and 'root' in parents`);
  const found = await api('https://www.googleapis.com/drive/v3/files?fields=files(id)&q=' + encodeURIComponent(query));
  if (found.files?.length) return found.files[0].id;
  const made = await api('https://www.googleapis.com/drive/v3/files?fields=id', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, mimeType: 'application/vnd.google-apps.folder', ...(parentId ? { parents: [parentId] } : {}) })
  });
  return made.id;
}

// Uploads (or replaces, when existingId still exists) a PDF; returns the Drive file id
async function savePdf(buffer, fileName, folderName, existingId) {
  const root = await ensureFolder(ROOT());
  const folder = await ensureFolder(folderName || 'No location', root);
  if (existingId) {
    try {
      // Replace content, rename and move to the current folder (location may have changed)
      const meta = await api(`https://www.googleapis.com/drive/v3/files/${existingId}?fields=parents,trashed`);
      if (!meta.trashed) {
        const move = meta.parents?.includes(folder) ? '' : `&addParents=${folder}&removeParents=${(meta.parents || []).join(',')}`;
        await api(`https://www.googleapis.com/upload/drive/v3/files/${existingId}?uploadType=media${move}`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/pdf' }, body: buffer
        });
        await api(`https://www.googleapis.com/drive/v3/files/${existingId}`, {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: fileName })
        });
        return existingId;
      }
    } catch { /* file was deleted in Drive: upload a new one */ }
  }
  const boundary = 'mbg' + Date.now();
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` + JSON.stringify({ name: fileName, parents: [folder] }) +
      `\r\n--${boundary}\r\nContent-Type: application/pdf\r\n\r\n`),
    buffer,
    Buffer.from(`\r\n--${boundary}--`)
  ]);
  const made = await api('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id', {
    method: 'POST', headers: { 'Content-Type': 'multipart/related; boundary=' + boundary }, body
  });
  return made.id;
}

async function deleteFile(id) {
  const r = await fetch(`https://www.googleapis.com/drive/v3/files/${id}`, { method: 'DELETE', headers: { Authorization: 'Bearer ' + await accessToken() } });
  if (!r.ok && r.status !== 404) throw new Error('Drive delete failed: ' + r.status);
}

module.exports = { savePdf, deleteFile, enabled };
