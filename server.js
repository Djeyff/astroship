const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const PORT = process.env.PORT || 3000;

// Config from env (with sandbox defaults)
const DASHBOARD_PIN = process.env.DASHBOARD_PIN || '1313';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://supabase.voz-clara.com';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NzMzNjU4MzksImV4cCI6MjA4ODcyNTgzOX0.2sH9PY8d6MMiT0ab9e3WCdk7hIFC9QqFkMOLfrXpIqY';
const VOZCLARA_WA_URL = process.env.VOZCLARA_WA_URL || 'https://vozclara-wa.zeabur.app';

// In-memory sessions
const sessions = new Map();

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/rewa_session=([a-f0-9]+)/);
  if (!match) return null;
  const s = sessions.get(match[1]);
  if (!s || s.expires < Date.now()) return null;
  return s;
}

// Fetch from Supabase
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
        'Prefer': 'count=exact'
      }
    };
    const req = https.request(opts, (res) => {
      let data = '';
      const count = res.headers['content-range'] || '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try {
          resolve({ data: JSON.parse(data), count });
        } catch(e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

// Proxy a URL and pipe to response
function proxyUrl(targetUrl, res) {
  const u = new URL(targetUrl);
  const proto = u.protocol === 'https:' ? https : http;
  proto.get({ hostname: u.hostname, path: u.pathname + u.search, headers: { 'User-Agent': 'Rewa/1.0' } }, (r) => {
    res.writeHead(r.statusCode, {
      'Content-Type': r.headers['content-type'] || 'image/png',
      'Cache-Control': 'no-cache'
    });
    r.pipe(res);
  }).on('error', () => {
    res.writeHead(502);
    res.end('QR unavailable');
  });
}

const mime = {
  '.html': 'text/html;charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg'
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
  });
}

http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // ── API routes ──────────────────────────────────────────────────────

  if (pathname === '/api/login' && req.method === 'POST') {
    const body = await parseBody(req);
    if (body.pin === DASHBOARD_PIN) {
      const token = genToken();
      sessions.set(token, { expires: Date.now() + 24 * 3600 * 1000 });
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `rewa_session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Lax`
      });
      res.end(JSON.stringify({ ok: true }));
    } else {
      sendJson(res, 401, { error: 'Invalid PIN' });
    }
    return;
  }

  if (pathname === '/logout') {
    res.writeHead(302, {
      'Set-Cookie': 'rewa_session=; Max-Age=0; Path=/',
      'Location': '/login'
    });
    res.end();
    return;
  }

  // Protected API
  if (pathname.startsWith('/api/')) {
    if (!getSession(req)) {
      sendJson(res, 401, { error: 'Unauthorized' });
      return;
    }

    if (pathname === '/api/transcriptions') {
      const limit = parseInt(parsed.query.limit) || 50;
      const offset = parseInt(parsed.query.offset) || 0;
      const search = parsed.query.q || '';
      let endpoint = `/rest/v1/vozclara_transcriptions?select=id,user_identifier,telegram_id,from_number,duration_seconds,created_at,transcription,summary&order=created_at.desc&limit=${limit}&offset=${offset}`;
      if (search) {
        // Basic ilike search
        endpoint += `&transcription=ilike.*${encodeURIComponent(search)}*`;
      }
      try {
        const r = await supaFetch(endpoint);
        sendJson(res, 200, { rows: r.data, count: r.count });
      } catch(e) {
        sendJson(res, 500, { error: e.message });
      }
      return;
    }

    if (pathname === '/api/stats') {
      try {
        const [all, today] = await Promise.all([
          supaFetch('/rest/v1/vozclara_transcriptions?select=id,duration_seconds,telegram_id,from_number,user_identifier'),
          supaFetch(`/rest/v1/vozclara_transcriptions?select=id&created_at=gte.${new Date().toISOString().slice(0,10)}`)
        ]);
        const rows = all.data || [];
        const totalMinutes = rows.reduce((sum, r) => sum + (parseFloat(r.duration_seconds) || 0), 0) / 60;
        const sources = { telegram: 0, whatsapp_business: 0, whatsapp_qr: 0 };
        rows.forEach(r => {
          if (r.telegram_id) sources.telegram++;
          else if (r.from_number) sources.whatsapp_business++;
          else sources.whatsapp_qr++;
        });
        sendJson(res, 200, {
          total: rows.length,
          today: (today.data || []).length,
          totalMinutes: Math.round(totalMinutes * 10) / 10,
          sources
        });
      } catch(e) {
        sendJson(res, 500, { error: e.message });
      }
      return;
    }

    if (pathname === '/api/qr') {
      proxyUrl(`${VOZCLARA_WA_URL}/qr`, res);
      return;
    }

    if (pathname === '/api/qr-status') {
      proxyUrl(`${VOZCLARA_WA_URL}/status`, res);
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
    return;
  }

  // ── Protected page routes ──────────────────────────────────────────

  if (pathname === '/dashboard' || pathname === '/dashboard.html') {
    if (!getSession(req)) {
      res.writeHead(302, { 'Location': '/login' });
      res.end();
      return;
    }
  }

  // ── Static files ───────────────────────────────────────────────────

  let filePath = pathname;
  if (filePath === '/' || filePath === '') filePath = '/index.html';
  else if (!path.extname(filePath)) filePath += '.html';

  const fullPath = path.join(__dirname, 'public', filePath);
  const ext = path.extname(fullPath);

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      fs.readFile(path.join(__dirname, 'public', '404.html'), (e2, d2) => {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end(d2 || '<h1>404 Not found</h1>');
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain' });
    res.end(data);
  });

}).listen(PORT, () => console.log(`Rewa sandbox running on :${PORT}`));
