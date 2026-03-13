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

    // AI Search
    if (pathname === '/api/ai-search' && req.method === 'POST') {
      const body = await parseBody(req);
      const question = (body.q || '').trim();
      if (!question) { sendJson(res, 400, { error: 'Missing q' }); return; }

      try {
        // Step 1: Try vector search first (if embeddings available)
        let vectorRows = [];
        const queryEmbedding = await getEmbedding(question);
        if (queryEmbedding) {
          const vecResults = await supaRpc('match_transcriptions', {
            query_embedding: queryEmbedding,
            match_count: 8,
            min_similarity: 0.3,
          });
          if (Array.isArray(vecResults) && vecResults.length) {
            vectorRows = vecResults.map(decryptRow).filter(r => r.text && r.text !== '[encrypted — key mismatch]');
          }
        }

        // Step 2: Keyword fallback (always run, merge results)
        const terms = question.toLowerCase().split(/\s+/).filter(t => t.length > 3);
        const allR = await supaFetch('/rest/v1/transcriptions?select=id,source,sender_name,chat_name,duration_seconds,language,text_encrypted,summary_encrypted,encryption_iv,encryption_tag,audio_url,created_at&order=created_at.desc&limit=200');
        const decryptedAll = (allR.data || []).map(decryptRow).filter(r => r.text && r.text !== '[encrypted — key mismatch]');
        const keywordRows = decryptedAll
          .map(r => ({ ...r, _score: keywordScore(r, terms) }))
          .filter(r => r._score > 0)
          .sort((a, b) => b._score - a._score)
          .slice(0, 8);

        // Merge: vector results first (higher quality), then keyword, dedup by id
        const seen = new Set();
        const combined = [...vectorRows, ...keywordRows].filter(r => {
          if (seen.has(r.id)) return false;
          seen.add(r.id);
          return true;
        }).slice(0, 10);

        if (!combined.length) {
          sendJson(res, 200, { answer: "No relevant transcriptions found for your query.", sources: [], mode: 'no_results' });
          return;
        }

        // Step 3: Groq synthesis
        const answer = GROQ_API_KEY
          ? await groqAnswer(question, combined)
          : \`Found \${combined.length} relevant transcription(s). Enable AI synthesis by adding GROQ_API_KEY to Zeabur env vars.\`;

        sendJson(res, 200, {
          answer: answer || 'Could not generate answer.',
          sources: combined.map(r => ({ id: r.id, text: r.text?.slice(0, 200), sender_name: r.sender_name, chat_name: r.chat_name, source: r.source, created_at: r.created_at })),
          mode: queryEmbedding ? 'vector+keyword' : 'keyword',
        });
      } catch(e) {
        sendJson(res, 500, { error: e.message });
      }
      return;
    }

    // Trigger manual embedding index
    if (pathname === '/api/index' && req.method === 'POST') {
      indexUnembedded();
      sendJson(res, 200, { ok: true, message: 'Indexing started in background' });
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
    return;
  }

  // ── Route: /dashboard → PIN-protected real dashboard, /private same ──

  if (pathname === '/dashboard' || pathname === '/dashboard/' ||
      pathname === '/private'   || pathname === '/private/') {
    if (!getSession(req)) { res.writeHead(302, { 'Location': '/login' }); res.end(); return; }
    fs.readFile(path.join(__dirname, 'public', 'private.html'), (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // Public demo at /demo
  if (pathname === '/demo' || pathname === '/demo/') {
    fs.readFile(path.join(__dirname, 'public', 'demo.html'), (err, data) => {
      res.writeHead(200, { 'Content-Type': 'text/html;charset=utf-8' });
      res.end(err ? '<h1>Demo coming soon</h1>' : data);
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

// ─── AI Search + Embeddings (appended) ────────────────────────────────
// Jina AI: free multilingual embeddings (768-dim), 100+ languages
// Groq: LLM synthesis of the final answer

const GROQ_API_KEY  = process.env.GROQ_API_KEY  || '';
const JINA_API_KEY  = process.env.JINA_API_KEY  || '';

// Simple HTTPS POST helper
function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const opts = { hostname, path, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers } };
    const req = https.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(d) }); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Generate embedding for a text using Jina AI (multilingual, free tier)
async function getEmbedding(text) {
  if (!text) return null;
  const truncated = text.slice(0, 2000); // Jina limit
  try {
    const headers = JINA_API_KEY ? { 'Authorization': `Bearer ${JINA_API_KEY}` } : {};
    const r = await httpsPost('api.jina.ai', '/v1/embeddings', headers, {
      model: 'jina-embeddings-v3',
      task: 'retrieval.passage',
      dimensions: 768,
      input: [truncated],
    });
    if (r.status === 200 && r.body?.data?.[0]?.embedding) {
      return r.body.data[0].embedding;
    }
    console.warn('[Embedding] Jina error:', r.status, r.body?.detail || '');
    return null;
  } catch(e) {
    console.warn('[Embedding] Error:', e.message);
    return null;
  }
}

// Ask Groq to synthesize an answer from context transcriptions
async function groqAnswer(question, contextRows) {
  if (!GROQ_API_KEY) return null;
  const context = contextRows.map((r, i) =>
    `[${i+1}] ${r.source || 'unknown'} | ${r.sender_name || '?'} in "${r.chat_name || 'DM'}" | ${new Date(r.created_at).toLocaleDateString()}\n${r.text}`
  ).join('\n\n---\n\n');

  const prompt = `You are Rewa, an AI assistant that helps users recall information from their WhatsApp transcriptions.

The user asks: "${question}"

Here are the relevant transcriptions:
${context}

Answer the question directly and concisely based on the transcriptions above. Cite which transcription(s) you're drawing from using [1], [2], etc. If the answer isn't found, say so. Reply in the same language as the question.`;

  try {
    const r = await httpsPost('api.groq.com', '/openai/v1/chat/completions',
      { 'Authorization': `Bearer ${GROQ_API_KEY}` },
      {
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens: 500,
      }
    );
    if (r.status === 200) return r.body?.choices?.[0]?.message?.content?.trim() || null;
    console.warn('[Groq] Error:', r.status);
    return null;
  } catch(e) {
    console.warn('[Groq] Error:', e.message);
    return null;
  }
}

// Keyword scoring — decrypted rows ranked by query term overlap
function keywordScore(row, terms) {
  const haystack = ((row.text || '') + ' ' + (row.summary || '') + ' ' + (row.chat_name || '') + ' ' + (row.sender_name || '')).toLowerCase();
  return terms.reduce((score, t) => score + (haystack.includes(t) ? 1 : 0), 0);
}

// Supabase RPC call (vector search)
function supaRpc(fnName, params) {
  return new Promise((resolve, reject) => {
    const u = new URL(SUPABASE_URL + `/rest/v1/rpc/${fnName}`);
    const body = JSON.stringify(params);
    const opts = {
      hostname: u.hostname,
      path: u.pathname,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'apikey': SUPABASE_KEY,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Store embedding back to DB
function saveEmbedding(id, embedding) {
  if (!embedding || !id) return;
  const vecStr = '[' + embedding.join(',') + ']';
  supaFetch(`/rest/v1/transcriptions?id=eq.${id}`).catch(() => {});
  // Use PATCH via HTTPS
  const u = new URL(SUPABASE_URL + `/rest/v1/transcriptions?id=eq.${id}`);
  const body = JSON.stringify({ embedding: vecStr });
  const opts = {
    hostname: u.hostname,
    path: u.pathname + u.search,
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'apikey': SUPABASE_KEY,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  };
  const req = https.request(opts, () => {});
  req.on('error', () => {});
  req.write(body);
  req.end();
}

// Embed unindexed rows in background (call once on startup + periodically)
let indexingInProgress = false;
async function indexUnembedded() {
  if (indexingInProgress || !JINA_API_KEY) return;
  indexingInProgress = true;
  try {
    // Fetch rows without embeddings
    const r = await supaFetch('/rest/v1/transcriptions?select=id,text_encrypted,encryption_iv,encryption_tag&embedding=is.null&limit=20');
    const rows = r.data || [];
    if (!rows.length) { indexingInProgress = false; return; }
    console.log(`[Index] Embedding ${rows.length} rows…`);
    for (const row of rows) {
      const decrypted = decryptField(row.text_encrypted, row.encryption_iv, row.encryption_tag, OWNER_PHONE);
      if (!decrypted) continue;
      const embedding = await getEmbedding(decrypted);
      if (embedding) {
        saveEmbedding(row.id, embedding);
        await new Promise(r => setTimeout(r, 100)); // rate limit
      }
    }
  } catch(e) { console.warn('[Index] Error:', e.message); }
  indexingInProgress = false;
}

// Run indexer on startup and every 10 minutes
setTimeout(indexUnembedded, 5000);
setInterval(indexUnembedded, 10 * 60 * 1000);

