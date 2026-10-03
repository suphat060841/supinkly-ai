/**
 * รันในเครื่องตัวเอง (ไม่ใช่บน Render):
 *   GMAIL_CLIENT_ID=... GMAIL_CLIENT_SECRET=... node get-gmail-token.js
 * แล้วเปิดลิงก์ที่แสดง อนุญาตสิทธิ์ จะได้ refresh token แสดงในเทอร์มินัล
 * ต้องเพิ่ม http://localhost:53682/callback ใน Authorized redirect URIs ของ OAuth client
 */
const http = require('http');
const { URL, URLSearchParams } = require('url');

const clientId = process.env.GMAIL_CLIENT_ID;
const clientSecret = process.env.GMAIL_CLIENT_SECRET;
if (!clientId || !clientSecret) {
    console.error('ตั้งค่า GMAIL_CLIENT_ID และ GMAIL_CLIENT_SECRET ก่อน');
    process.exit(1);
}
const PORT = 53682;
const redirectUri = `http://localhost:${PORT}/callback`;

const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/gmail.send',
    access_type: 'offline',
    prompt: 'consent'
}).toString();

http.createServer(async (req, res) => {
    const u = new URL(req.url, `http://localhost:${PORT}`);
    if (u.pathname !== '/callback') { res.writeHead(404); return res.end(); }
    const code = u.searchParams.get('code');
    if (!code) { res.writeHead(400); return res.end('no code'); }
    try {
        const r = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                code, client_id: clientId, client_secret: clientSecret,
                redirect_uri: redirectUri, grant_type: 'authorization_code'
            }).toString()
        });
        const data = await r.json();
        if (!data.refresh_token) throw new Error(JSON.stringify(data));
        console.log('\nGMAIL_REFRESH_TOKEN=' + data.refresh_token + '\n');
        res.end('Done. กลับไปดูเทอร์มินัลได้เลย');
    } catch (e) {
        console.error(e.message);
        res.end('Error: ' + e.message);
    }
    setTimeout(() => process.exit(0), 500);
}).listen(PORT, () => {
    console.log('เปิดลิงก์นี้ในเบราว์เซอร์:\n\n' + authUrl + '\n');
});
