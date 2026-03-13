const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const PORT = process.env.PORT || 3000;

// ─── Config ──────────────────────────────────────────────────────────
const DASHBOARD_PIN     = process.env.DASHBOARD_PIN     || '1313';
const SUPABASE_URL      = process.env.SUPABASE_URL      || 'https://supabase.voz-clara.com';
const SUPABASE_KEY      = process.env.SUPABASE_KEY      || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NzMzNjU4MzksImV4cCI6MjA4ODcyNTgzOX0.2sH9PY8d6MMiT0ab9e3WCdk7hIFC9QqFkMOLfrXpIqY';
const MASTER_KEY_STR    = process.env.VOZCLARA_MASTER_KEY || 'c972912e449d8cc665d9ef3bc6f8ca5ded042b1c2a7a6b712aa37362e42c3a14';
const VOZCLARA_WA_URL   = process.env.VOZCLARA_WA_URL   || 'https://vozclara-wa.zeabur.app';
// Owner phone — used as PBKDF2 salt for WhatsApp QR encryption
const OWNER_PHONE       = process.env.OWNER_PHONE       || '18092044903';

// ─── Sessions (in-memory) ─────────────────────────────────────────────
const sessions = new Map();
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function getSession(req) {
  const c = req.headers.cookie || '';
  const m = c.match(/rewa_session=([a-f0-9]+)/);
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s || s.expires < Date.now()) return null;
  return s;
}

// ─── Decryption ───────────────────────────────────────────────────────
// PBKDF2(MASTER_KEY_STR, userId, 100000, 32, sha256) + AES-256-GCM
// Same scheme as all 3 vozclara services
function deriveKey(userId) {
  if (!MASTER_KEY_STR) return null;
  return crypto.pbkdf2Sync(MASTER_KEY_STR, userId || 'default', 100000, 32, 'sha256');
}

function decryptField(encBase64, ivBase64, tagBase64, userId) {
  if (!encBase64 || !ivBase64 || !tagBase64) return null;
  try {
    const key = deriveKey(userId);
    if (!key) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivBase64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagBase64, 'base64'));
    let dec = decipher.update(encBase64, 'base64', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch { return null; }
}

// Decrypt a row from the transcriptions table
function decryptRow(row) {
  // The userId for WhatsApp QR is always OWNER_PHONE
  // For Telegram rows, the user_identifier in vozclara_transcriptions is the telegram_id
  const userId = OWNER_PHONE;

  const text = decryptField(row.text_encrypted, row.encryption_iv, row.encryption_tag, userId);
  let summary = null;
  let translation = null;

  // Extra metadata stored in audio_url JSON
  if (row.audio_url) {
    try {
      const meta = JSON.parse(row.audio_url);
      if (meta.summary_iv) {
        summary = decryptField(row.summary_encrypted, meta.summary_iv, meta.summary_tag, userId);
        if (meta.translation_encrypted) {
          translation = decryptField(meta.translation_encrypted, meta.translation_iv, meta.translation_tag, userId);
        }
      }
    } catch {}
  }

  return {
    id: row.id,
    text: text || '[encrypted — key mismatch]',
    summary,
    translation,
    language: row.language,
    source: row.source,
    sender_name: row.sender_name,
    chat_name: row.chat_name,
    duration_seconds: row.duration_seconds,
    created_at: row.created_at,
  };
}

// ─── Supabase fetch ───────────────────────────────────────────────────
function supaFetch(endpoint) {
  return new Promise((resolve, reject) => {
    const u = new URL(SUPABASE_URL + endpoint);
    const opts = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'apikey': SUPABASE_KEY,
        'Content-Type': 'application/json',
        'Prefer': 'count=exact',
      },
    };
    const req = https.request(opts, (res) => {
      let data = '';
      const count = res.headers['content-range'] || '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve({ data: JSON.parse(data), count }); }
        catch(e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── Proxy helper ─────────────────────────────────────────────────────
function proxyUrl(targetUrl, res) {
  const u = new URL(targetUrl);
  const proto = u.protocol === 'https:' ? https : http;
  proto.get({ hostname: u.hostname, path: u.pathname + u.search, headers: { 'User-Agent': 'Rewa/1.0' } }, (r) => {
    res.writeHead(r.statusCode, { 'Content-Type': r.headers['content-type'] || 'image/png', 'Cache-Control': 'no-cache' });
    r.pipe(res);
  }).on('error', () => { res.writeHead(502); res.end('QR unavailable'); });
}

// ─── Helpers ──────────────────────────────────────────────────────────
const mime = { '.html':'text/html;charset=utf-8', '.css':'text/css', '.js':'application/javascript', '.svg':'image/svg+xml', '.png':'image/png' };

function sendJson(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
  res.end(b);
}
function parseBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', d => b += d);
    req.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}

// ─── HTTP server ──────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ── Auth ────────────────────────────────────────────────────────────

  if (pathname === '/api/login' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.pin === DASHBOARD_PIN) {
      const token = genToken();
      sessions.set(token, { expires: Date.now() + 24 * 3600 * 1000 });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `rewa_session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`,
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      sendJson(res, 401, { error: 'Invalid PIN' });
    }
    return;
  }

  if (pathname === '/logout') {
    res.writeHead(302, { 'Set-Cookie': 'rewa_session=; Max-Age=0; Path=/', 'Location': '/login' });
    res.end();
    return;
  }

  // ── Private API (PIN protected) ─────────────────────────────────────

  if (pathname.startsWith('/api/')) {
    if (!getSession(req)) { sendJson(res, 401, { error: 'Unauthorized' }); return; }

    // Transcriptions — reads from `transcriptions` table (encrypted) + decrypts server-side
    if (pathname === '/api/transcriptions') {
      const limit  = Math.min(parseInt(parsed.query.limit) || 50, 100);
      const offset = parseInt(parsed.query.offset) || 0;
      const search = parsed.query.q || '';
      const source = parsed.query.source || '';

      let endpoint = `/rest/v1/transcriptions?select=id,source,sender_name,chat_name,duration_seconds,language,text_encrypted,summary_encrypted,encryption_iv,encryption_tag,audio_url,created_at&order=created_at.desc&limit=${limit}&offset=${offset}`;
      if (source && source !== 'all') endpoint += `&source=eq.${encodeURIComponent(source)}`;

      try {
        const r = await supaFetch(endpoint);
        let rows = (r.data || []).map(decryptRow);

        // Client-side text filter (decrypted)
        if (search) {
          const q = search.toLowerCase();
          rows = rows.filter(r => (r.text || '').toLowerCase().includes(q) || (r.summary || '').toLowerCase().includes(q) || (r.chat_name || '').toLowerCase().includes(q));
        }

        sendJson(res, 200, { rows, count: r.count });
      } catch(e) { sendJson(res, 500, { error: e.message }); }
      return;
    }

    // Stats
    if (pathname === '/api/stats') {
      try {
        const [all, today] = await Promise.all([
          supaFetch('/rest/v1/transcriptions?select=id,source,duration_seconds'),
          supaFetch(`/rest/v1/transcriptions?select=id&created_at=gte.${new Date().toISOString().slice(0,10)}`),
        ]);
        const rows = all.data || [];
        const totalMinutes = rows.reduce((s, r) => s + (parseFloat(r.duration_seconds) || 0), 0) / 60;
        const sources = {};
        rows.forEach(r => { sources[r.source] = (sources[r.source] || 0) + 1; });
        sendJson(res, 200, {
          total: rows.length,
          today: (today.data || []).length,
          totalMinutes: Math.round(totalMinutes * 10) / 10,
          sources,
        });
      } catch(e) { sendJson(res, 500, { error: e.message }); }
      return;
    }

    // QR proxy
    if (pathname === '/api/qr')        { proxyUrl(`${VOZCLARA_WA_URL}/qr`, res); return; }
    if (pathname === '/api/qr-status') { proxyUrl(`${VOZCLARA_WA_URL}/status`, res); return; }

    sendJson(res, 404, { error: 'Not found' });
    return;
  }

  // ── Route: /dashboard → public demo, /private → PIN-protected ───────

  if (pathname === '/private' || pathname === '/private/') {
    if (!getSession(req)) { res.writeHead(302, { 'Location': '/login' }); res.end(); return; }
    // Serve private dashboard
    fs.readFile(path.join(__dirname, 'public', 'private.html'), (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // ── Static files ─────────────────────────────────────────────────────

  let filePath = pathname;
  if (filePath === '/' || filePath === '') filePath = '/index.html';
  else if (!path.extname(filePath)) filePath += '.html';

  const fullPath = path.join(__dirname, 'public', filePath);
  const ext = path.extname(fullPath);

  fs.readFile(fullPath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/html' }); res.end('<h1>404</h1>'); return; }
    res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
    res.end(data);
  });

}).listen(PORT, () => console.log(`Rewa on :${PORT} | public demo: /dashboard | private: /private (PIN)`));
