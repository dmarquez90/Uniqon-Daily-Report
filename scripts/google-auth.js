// One-time Google authorization for Drive uploads.
// Usage (PowerShell): $env:GOOGLE_CLIENT_ID="..."; $env:GOOGLE_CLIENT_SECRET="..."; node scripts/google-auth.js
// Opens a sign-in link; after you approve, the refresh token is written to .google-token.txt (git-ignored).
// Scope is drive.file only: the app can see just the files and folders it creates itself.
const http = require('http');
const fs = require('fs');
const { GOOGLE_CLIENT_ID: id, GOOGLE_CLIENT_SECRET: secret } = process.env;
if (!id || !secret) { console.error('Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET first.'); process.exit(1); }

let redirect;
const server = http.createServer(async (req, res) => {
  const code = new URL(req.url, redirect).searchParams.get('code');
  if (!code) return res.end('Waiting for Google…');
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code, client_id: id, client_secret: secret, redirect_uri: redirect, grant_type: 'authorization_code' })
  });
  const j = await r.json();
  if (!j.refresh_token) { res.end('No refresh token returned: ' + JSON.stringify(j)); console.error(j); process.exit(1); }
  fs.writeFileSync('.google-token.txt', j.refresh_token);
  res.end('Done. You can close this tab. The refresh token was saved to .google-token.txt');
  console.log('Saved refresh token to .google-token.txt — paste it into Vercel as GOOGLE_REFRESH_TOKEN, then delete the file.');
  process.exit(0);
});

// Port 0 = any free port (Windows reserves some port ranges); Desktop OAuth clients accept any loopback port
server.listen(0, '127.0.0.1', () => {
  redirect = `http://127.0.0.1:${server.address().port}/callback`;
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: id, redirect_uri: redirect, response_type: 'code', access_type: 'offline', prompt: 'consent',
    scope: 'https://www.googleapis.com/auth/drive.file'
  });
  console.log('Open this link in your browser and sign in with the Google account that owns the Drive:\n\n' + url + '\n');
});
