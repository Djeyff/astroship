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

// Decrypt a row — tries multiple candidate user IDs
// Different VozClara services used different identifiers as PBKDF2 salt:
// - WhatsApp QR: OWNER_PHONE ("18092044903")
// - Telegram bot: telegram_id string ("7707300903")
// - Chrome extension / older: UUID ("e964b1e5-c32d-4809-9fdd-30f4242667b0")
const DECRYPT_USER_IDS = [
  OWNER_PHONE,
  '7707300903',
  'e964b1e5-c32d-4809-9fdd-30f4242667b0',
];

function decryptBest(encB64, ivB64, tagB64) {
  if (!encB64 || !ivB64 || !tagB64) return null;
  for (const uid of DECRYPT_USER_IDS) {
    const r = decryptField(encB64, ivB64, tagB64, uid);
    if (r) return r;
  }
  return null;
}

function decryptRow(row) {
  const text = decryptBest(row.text_encrypted, row.encryption_iv, row.encryption_tag);
  let summary = null, translation = null;

  if (row.audio_url) {
    try {
      const meta = JSON.parse(row.audio_url);
      if (meta.summary_iv) {
        for (const uid of DECRYPT_USER_IDS) {
          const s = decryptField(row.summary_encrypted, meta.summary_iv, meta.summary_tag, uid);
          if (s) { summary = s; break; }
        }
        if (meta.translation_encrypted) {
          for (const uid of DECRYPT_USER_IDS) {
            const t = decryptField(meta.translation_encrypted, meta.translation_iv, meta.translation_tag, uid);
            if (t) { translation = t; break; }
          }
        }
      }
    } catch {}
  }

  return {
    id: row.id,
    text: text || '[key mismatch]',
    summary,
    translation,
    language: row.language,
    source: row.source || 'unknown',
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
      timeout: 15000,
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
    req.on('timeout', () => { req.destroy(new Error('Supabase timeout')); });
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

    // Transcriptions — reads from vozclara_transcriptions (plaintext) as primary source
    if (pathname === '/api/transcriptions') {
      const limit  = Math.min(parseInt(parsed.query.limit) || 50, 100);
      const offset = parseInt(parsed.query.offset) || 0;
      const search = parsed.query.q || '';
      const source = parsed.query.source || '';

      // vozclara_transcriptions has plaintext — use as sole source
      let endpoint = `/rest/v1/vozclara_transcriptions?select=id,transcription,summary,language,created_at,audio_duration_minutes,duration_seconds,telegram_id,from_number,user_identifier&order=created_at.desc&limit=${limit}&offset=${offset}`;

      try {
        const r = await supaFetch(endpoint);
        const contactMap = await buildContactMap();
        let rows = (Array.isArray(r.data) ? r.data : []).map(row => vtRowToUnified(row, contactMap));

        // Source filter
        if (source && source !== 'all') {
          rows = rows.filter(r => r.source === source);
        }

        // Text search
        if (search) {
          const q = search.toLowerCase();
          rows = rows.filter(r => (r.text || '').toLowerCase().includes(q) || (r.summary || '').toLowerCase().includes(q));
        }

        sendJson(res, 200, { rows, count: r.count });
      } catch(e) { sendJson(res, 500, { error: e.message }); }
      return;
    }

    // Stats — query vozclara_transcriptions only (plaintext, no double-counting)
    if (pathname === '/api/stats') {
      try {
        const today = new Date().toISOString().slice(0,10);
        const [all, todayRows] = await Promise.all([
          supaFetch('/rest/v1/vozclara_transcriptions?select=id,audio_duration_minutes,duration_seconds,telegram_id,from_number'),
          supaFetch(`/rest/v1/vozclara_transcriptions?select=id&created_at=gte.${today}`),
        ]);
        const rows = all.data || [];
        const totalMinutes = rows.reduce((s, r) => {
          const mins = r.audio_duration_minutes || (r.duration_seconds ? r.duration_seconds / 60 : 0);
          return s + mins;
        }, 0);
        const sources = { telegram: 0, whatsapp: 0, chrome: 0 };
        rows.forEach(r => {
          if (r.telegram_id) sources.telegram++;
          else if (r.from_number) sources.whatsapp++;
          else sources.chrome++;
        });
        sendJson(res, 200, {
          total: rows.length,
          today: (todayRows.data || []).length,
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
        // Load contact map for sender name resolution
        const contactMap = await buildContactMap();

        // Step 1: Try vector search (if embeddings available in vozclara_transcriptions)
        let vectorRows = [];
        const queryEmbedding = await getEmbedding(question);
        if (queryEmbedding) {
          const vecResults = await supaRpc('match_vt', {
            query_embedding: queryEmbedding,
            match_count: 8,
            min_similarity: 0.3,
          });
          if (Array.isArray(vecResults) && vecResults.length) {
            vectorRows = vecResults.map(r => vtRowToUnified(r, contactMap));
          }
        }

        // Step 2: Expand query with multilingual synonyms (cat → cat, gato, chat, etc.)
        const expandedTerms = await expandQueryMultilingual(question);
        const baseTerms = question.toLowerCase().split(/\s+/).filter(t => t.length > 1);
        const terms = [...new Set([...baseTerms, ...expandedTerms])];
        const allR = await supaFetch('/rest/v1/vozclara_transcriptions?select=id,transcription,summary,language,telegram_id,from_number,user_identifier,created_at,duration_seconds,audio_duration_minutes&order=created_at.desc&limit=300');
        const allRows = (allR.data || []).map(r => vtRowToUnified(r, contactMap));
        const keywordRows = allRows
          .map(r => ({ ...r, _score: keywordScore(r, terms) }))
          .filter(r => r._score > 0)
          .sort((a, b) => b._score - a._score)
          .slice(0, 8);

        // Merge: vector first, then keyword, dedup by id
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
          : 'Found ' + combined.length + ' relevant transcription(s). Add GROQ_API_KEY in Zeabur env vars to enable AI synthesis.';

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


    // Translate a transcription via Groq
    if (pathname === '/api/translate' && req.method === 'POST') {
      const body = await parseBody(req);
      const { text, targetLang } = body;
      if (!text) { sendJson(res, 400, { error: 'Missing text' }); return; }
      if (!GROQ_API_KEY) { sendJson(res, 200, { translation: null, error: 'GROQ_API_KEY not configured' }); return; }
      try {
        const lang = targetLang || 'English';
        const r = await httpsPost('api.groq.com', '/openai/v1/chat/completions',
          { 'Authorization': `Bearer ${GROQ_API_KEY}` },
          {
            model: 'llama-3.3-70b-versatile',
            messages: [{ role: 'user', content: `Translate the following text to ${lang}. Return ONLY the translation, no explanations or prefixes:\n\n${text.slice(0, 3000)}` }],
            temperature: 0.1,
            max_tokens: 1000,
          }
        );
        const translation = r.status === 200 ? r.body?.choices?.[0]?.message?.content?.trim() : null;
        sendJson(res, 200, { translation });
      } catch(e) { sendJson(res, 500, { error: e.message }); }
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
async function expandQueryMultilingual(question) {
  if (!GROQ_API_KEY) return [];
  try {
    const r = await httpsPost('api.groq.com', '/openai/v1/chat/completions',
      { 'Authorization': `Bearer ${GROQ_API_KEY}` },
      {
        model: 'llama-3.3-70b-versatile',
        messages: [{
          role: 'user',
          content: `Given this search query: "${question}"

Extract the key search terms and provide their equivalents in English, Spanish, French, and Portuguese.
Return ONLY a JSON array of strings with all unique terms/synonyms/translations. No explanation.
Example for "cat": ["cat","cats","gato","gatos","chat","chats","gato","felino"]
Example for "meeting tomorrow": ["meeting","meetings","reunion","réunion","reunião","mañana","demain","tomorrow","amanhã"]

Query: "${question}"
JSON array:`
        }],
        temperature: 0.1,
        max_tokens: 150,
      }
    );
    if (r.status === 200) {
      const content = r.body?.choices?.[0]?.message?.content?.trim() || '[]';
      const match = content.match(/\[[\s\S]*\]/);
      if (match) {
        const parsed = JSON.parse(match[0]);
        return parsed.map(t => t.toLowerCase().trim()).filter(t => t.length > 1);
      }
    }
  } catch(e) {
    console.warn('[expandQuery] Error:', e.message);
  }
  return [];
}

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
function saveEmbedding(id, embedding, table) {
  if (!embedding || !id) return;
  const tbl = table || 'vozclara_transcriptions';
  const vecStr = '[' + embedding.join(',') + ']';
  // Use PATCH via HTTPS
  const u = new URL(SUPABASE_URL + `/rest/v1/${tbl}?id=eq.${id}`);
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
// Build contact name lookup map from vozclara_users
let contactMapCache = null;
let contactMapTs = 0;
async function buildContactMap() {
  if (contactMapCache && Date.now() - contactMapTs < 5 * 60 * 1000) return contactMapCache;
  try {
    const r = await supaFetch('/rest/v1/vozclara_users?select=phone_number,display_name,telegram_id,first_name,username');
    const map = {};
    (Array.isArray(r.data) ? r.data : []).forEach(u => {
      const name = u.display_name || u.first_name || u.username || null;
      if (name && u.phone_number) map[u.phone_number] = name;
      if (name && u.telegram_id) map[String(u.telegram_id)] = name;
    });
    contactMapCache = map;
    contactMapTs = Date.now();
    return map;
  } catch(e) { return {}; }
}

// Convert vozclara_transcriptions row to unified format
function vtRowToUnified(row, contactMap) {
  const cm = contactMap || {};
  const telegramName = row.telegram_id ? (cm[String(row.telegram_id)] || null) : null;
  const phoneName = row.from_number ? (cm[row.from_number] || null) : null;
  const senderName = telegramName || phoneName || row.user_identifier || null;
  return {
    id: row.id,
    text: row.transcription || '',
    summary: row.summary || null,
    language: row.language || null,
    source: row.telegram_id ? 'telegram' : row.from_number ? 'whatsapp' : 'chrome',
    sender_name: senderName,
    chat_name: null,
    duration_seconds: row.duration_seconds || (row.audio_duration_minutes ? Math.round(row.audio_duration_minutes * 60) : null),
    created_at: row.created_at,
  };
}

async function indexUnembedded() {
  if (indexingInProgress || !JINA_API_KEY) return;
  indexingInProgress = true;
  try {
    // Fetch plaintext rows without embeddings from vozclara_transcriptions
    const r = await supaFetch('/rest/v1/vozclara_transcriptions?select=id,transcription&embedding=is.null&limit=20');
    const rows = (Array.isArray(r.data) ? r.data : []).filter(row => row.transcription);
    if (!rows.length) { indexingInProgress = false; return; }
    console.log(`[Index] Embedding ${rows.length} rows from vozclara_transcriptions…`);
    for (const row of rows) {
      const embedding = await getEmbedding(row.transcription);
      if (embedding) {
        saveEmbedding(row.id, embedding, 'vozclara_transcriptions');
        await new Promise(r => setTimeout(r, 100));
      }
    }
  } catch(e) { console.warn('[Index] Error:', e.message); }
  indexingInProgress = false;
}

// Run indexer on startup and every 10 minutes
setTimeout(indexUnembedded, 5000);
setInterval(indexUnembedded, 10 * 60 * 1000);

