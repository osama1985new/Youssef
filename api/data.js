// Vercel serverless function. Stores entries in Upstash Redis (Vercel Marketplace) behind a family PIN.
const crypto = require('crypto');

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const PIN = process.env.FAMILY_PIN;
const SUPP_KEYS = ['omega', 'vit'];
const SITE_KEYS = ['ab_r', 'ab_l', 'th_r', 'th_l', 'ar_r', 'ar_l'];
const SLOTS = ['fast','bf_before','bf_after','ln_before','ln_after','dn_before','dn_after','bed','other'];

async function redis(args) {
  const r = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'content-type': 'application/json' },
    body: JSON.stringify(args)
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

function same(x, y) {
  const a = Buffer.from(String(x)), b = Buffer.from(String(y));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function hashPin(pin, saltHex) {
  return crypto.scryptSync(String(pin), Buffer.from(saltHex, 'hex'), 32).toString('hex');
}
let authCache = { at: 0, val: null };
async function loadAuth(force) {
  if (!force && Date.now() - authCache.at < 30000) return authCache.val;
  try {
    const raw = await redis(['GET', 'ysg:auth']);
    authCache = { at: Date.now(), val: raw ? JSON.parse(raw) : null };
  } catch (e) { /* keep the last known value */ }
  return authCache.val;
}
// 'edit' = full access, 'view' = read only, null = rejected. Open (edit) until a PIN is set.
function normPin(x) {
  return String(x || '').replace(/[\u0660-\u0669]/g, c => String(c.charCodeAt(0) - 0x660)).replace(/[\u06F0-\u06F9]/g, c => String(c.charCodeAt(0) - 0x6F0)).trim();
}
function roleFor(given, auth) {
  let raw = String(given || '');
  try { raw = decodeURIComponent(raw); } catch (e) {}
  const cands = Array.from(new Set([raw, normPin(raw)]));
  const hasAuth = !!(auth && auth.editHash && auth.salt);
  for (const g of cands) {
    if (PIN && (same(g, PIN) || same(normPin(g), normPin(PIN)))) return 'edit';
    if (hasAuth) {
      const h = hashPin(g, auth.salt);
      if (same(h, auth.editHash)) return 'edit';
      if (auth.viewHash && same(h, auth.viewHash)) return 'view';
    }
  }
  return (PIN || hasAuth) ? null : 'edit';
}

const numOrNull = (v, max) => {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 && n <= max ? n : undefined;
};

function cleanEntry(e) {
  if (!e || typeof e !== 'object') return null;
  const id = String(e.id || '');
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(id)) return null;
  const ts = new Date(e.ts);
  if (isNaN(ts)) return null;
  if (!SLOTS.includes(e.slot)) return null;
  const glucose = numOrNull(e.glucose, 600);
  const apidra = numOrNull(e.apidra, 50);
  const tresiba = numOrNull(e.tresiba, 100);
  if (glucose === undefined || apidra === undefined || tresiba === undefined) return null;
  const supp = Array.isArray(e.supp) ? e.supp.filter(x => SUPP_KEYS.includes(x)).slice(0, 5) : [];
  let ketT = null, ketV = null;
  if (e.ketT === 'b') {
    const n = Number(e.ketV);
    if (!Number.isFinite(n) || n < 0 || n > 15) return null;
    ketT = 'b'; ketV = String(n);
  } else if (e.ketT === 'u') {
    if (!['neg', 'small', 'mod', 'large'].includes(e.ketV)) return null;
    ketT = 'u'; ketV = e.ketV;
  } else if (e.ketT) return null;
  if (glucose === null && apidra === null && tresiba === null && supp.length === 0 && !ketT && !(Array.isArray(e.meal) && e.meal.length)) return null;
  const carbs = numOrNull(e.carbs, 1000);
  if (carbs === undefined) return null;
  let meal = [];
  if (Array.isArray(e.meal)) {
    for (const m of e.meal.slice(0, 30)) {
      if (!m || typeof m !== 'object') return null;
      const q = numOrNull(m.q, 50), c = numOrNull(m.c, 500);
      if (q === undefined || c === undefined) return null;
      meal.push({ n: String(m.n || '').slice(0, 60), q: q === null ? 1 : q, c: c === null ? 0 : c });
    }
  }
  const needle = e.needle === 'new' || e.needle === 'reuse' ? e.needle : null;
  const site = SITE_KEYS.includes(e.site) ? e.site : null;
  const tresibaTime = tresiba > 0 && /^([01]\d|2[0-3]):[0-5]\d$/.test(String(e.tresibaTime || '')) ? e.tresibaTime : null;
  return { id, ts: ts.toISOString(), slot: e.slot, glucose, apidra, tresiba, carbs, meal, note: String(e.note || '').slice(0, 300), needle, site, supp, tresibaTime, corr: e.corr === true && apidra > 0, ketT, ketV };
}

const SETTING_RANGES = { low: [40, 120], high: [120, 400], plan: [0.5, 100], icr: [1, 150], icrBf: [1, 150], icrLn: [1, 150], icrDn: [1, 150], isf: [5, 400], target: [70, 200], maxd: [0.5, 50], a1cVal: [3, 20], ketHigh: [180, 500], ketHours: [1, 8], wt: [20, 250], ht: [100, 230], bps: [60, 230], bpd: [30, 150] };
function cleanSettings(s) {
  if (!s || typeof s !== 'object') return null;
  const out = {};
  for (const k of Object.keys(SETTING_RANGES)) {
    const v = s[k];
    if (v === null || v === undefined || v === '') {
      if (k === 'low' || k === 'high') return null;
      out[k] = null; continue;
    }
    const n = Number(v);
    if (!Number.isFinite(n) || n < SETTING_RANGES[k][0] || n > SETTING_RANGES[k][1]) return null;
    out[k] = n;
  }
  if (out.low >= out.high) return null;
  const dOk = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) && !isNaN(new Date(String(v)));
  if (out.bps != null && out.bpd != null && out.bps <= out.bpd) return null;
  out.bodyDate = dOk(s.bodyDate) ? String(s.bodyDate) : null;
  const dtOk = v => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(v || '')) && !isNaN(new Date(String(v)));
  out.visitLast = dtOk(s.visitLast) ? String(s.visitLast) : null;
  out.visitNext = dtOk(s.visitNext) ? String(s.visitNext) : null;
  out.visitNote = s.visitNote ? String(s.visitNote).trim().slice(0, 300) || null : null;
  out.ketExp = dOk(s.ketExp) ? String(s.ketExp) : null;
  if (s.checks !== undefined && s.checks !== null) {
    if (!Array.isArray(s.checks) || s.checks.length > 12) return null;
    out.checks = [];
    for (const c of s.checks) {
      const n = String((c && c.n) || '').trim().slice(0, 40), m = Number(c && c.m);
      if (!n || !Number.isInteger(m) || m < 1 || m > 60) return null;
      out.checks.push({ n, d: dOk(c.d) ? String(c.d) : null, m });
    }
  }
  const ad = String(s.a1cDate || '');
  out.a1cDate = /^\d{4}-\d{2}-\d{2}$/.test(ad) && !isNaN(new Date(ad)) ? ad : null;
  out.scale = [];
  if (s.scale !== undefined && s.scale !== null) {
    if (!Array.isArray(s.scale) || s.scale.length > 10) return null;
    for (const r of s.scale) {
      const a = Number(r && r.a), b = Number(r && r.b), u = Number(r && r.u);
      if (![a, b, u].every(Number.isFinite) || a < 40 || b > 600 || a > b || u < 0 || u > 20) return null;
      out.scale.push({ a, b, u });
    }
  }
  return out;
}


const FOOD_PROMPT = 'This is a photo of a meal for a teenager with type 1 diabetes in Egypt. Identify each distinct food item visible. For each item give: name (short Egyptian-Arabic name), portion (short Arabic description of ONE unit, e.g. "رغيف بلدي صغير" or "معلقة كبيرة أرز"), qty (number of units visible, in steps of 0.5), carbs (estimated grams of carbohydrate in ONE unit, a number). Be realistic. If the image has no food return an empty items list and explain in note (Arabic). Reply with JSON only: {"items":[{"name":"","portion":"","qty":1,"carbs":0}],"note":""}. These are rough estimates that a person will review. Never give insulin dose advice.';
async function analyzeFood(b64) {
  const key = process.env.ANTHROPIC_API_KEY || await redis(['GET', 'ysg:aikey']);
  if (!key) { const e = new Error('no_ai_key'); e.code = 'no_ai_key'; throw e; }
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-sonnet-5-5', max_tokens: 900, messages: [{ role: 'user', content: [
      { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: b64 } },
      { type: 'text', text: FOOD_PROMPT } ] }] })
  });
  if (!r.ok) { const e = new Error('ai_failed'); e.code = 'ai_failed'; throw e; }
  const j = await r.json();
  const txt = (j.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
  const m = txt.match(/\{[\s\S]*\}/);
  let o; try { o = JSON.parse(m[0]); } catch (e) { const er = new Error('ai_failed'); er.code = 'ai_failed'; throw er; }
  const items = [];
  for (const x of (Array.isArray(o.items) ? o.items : []).slice(0, 10)) {
    const qty = Number(x.qty), carbs = Number(x.carbs);
    if (!x || !String(x.name || '').trim() || !Number.isFinite(qty) || !Number.isFinite(carbs)) continue;
    items.push({ name: String(x.name).slice(0, 60), portion: String(x.portion || '').slice(0, 60), qty: Math.min(20, Math.max(0.5, Math.round(qty * 2) / 2)), carbs: Math.min(200, Math.max(0, Math.round(carbs))) });
  }
  return { items, note: String(o.note || '').slice(0, 200) };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ error: 'storage_not_configured' });
  try {
    const auth = await loadAuth();
    const role = roleFor(req.headers['x-pin'], auth);
    if (!role) {
      await new Promise(r => setTimeout(r, 800));
      return res.status(401).json({ error: 'bad_pin' });
    }
    const isProtected = !!(PIN || (auth && auth.editHash));
    if (req.method === 'GET') {
      const [flat, settingsRaw] = await Promise.all([redis(['HGETALL', 'ysg:entries']), redis(['GET', 'ysg:settings'])]);
      const entries = [];
      for (let i = 1; i < (flat || []).length; i += 2) {
        try { entries.push(JSON.parse(flat[i])); } catch (e) {}
      }
      let settings = null;
      try { settings = settingsRaw ? JSON.parse(settingsRaw) : null; } catch (e) {}
      return res.status(200).json({ entries, settings, role, protected: isProtected });
    }
    if (req.method === 'POST') {
      const b = req.body || {};
      if (role !== 'edit') return res.status(403).json({ error: 'read_only' });
      if (b.action === 'setauth') {
        const ep = normPin(b.editPin), vp = b.viewPin ? normPin(b.viewPin) : '';
        if (ep.length < 4 || ep.length > 32) return res.status(400).json({ error: 'bad_pin_format' });
        if (vp && (vp.length < 4 || vp.length > 32 || vp === ep)) return res.status(400).json({ error: 'bad_pin_format' });
        const salt = crypto.randomBytes(16).toString('hex');
        const next = { salt, editHash: hashPin(ep, salt), viewHash: vp ? hashPin(vp, salt) : null };
        await redis(['SET', 'ysg:auth', JSON.stringify(next)]);
        authCache = { at: Date.now(), val: next };
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'setaikey') {
        const k = String(b.key || '').trim();
        if (!/^sk-ant-[A-Za-z0-9_\-]{10,300}$/.test(k)) return res.status(400).json({ error: 'bad_key' });
        await redis(['SET', 'ysg:aikey', k]);
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'food') {
        const img = String(b.image || '');
        if (img.length < 100 || img.length > 3000000 || !/^[A-Za-z0-9+/=]+$/.test(img)) return res.status(400).json({ error: 'bad_image' });
        try { return res.status(200).json(await analyzeFood(img)); }
        catch (e) { return res.status(e.code === 'no_ai_key' ? 400 : 502).json({ error: e.code || 'ai_failed' }); }
      }
      if (b.action === 'import') {
        if (!Array.isArray(b.entries) || b.entries.length > 1000) return res.status(400).json({ error: 'bad_import' });
        const args = ['HSET', 'ysg:entries']; let ok = 0, skipped = 0;
        for (const raw of b.entries) {
          const e = cleanEntry(raw);
          if (!e) { skipped++; continue; }
          args.push(e.id, JSON.stringify(e)); ok++;
        }
        if (ok) await redis(args);
        if (b.settings) { const cs = cleanSettings(b.settings); if (cs) await redis(['SET', 'ysg:settings', JSON.stringify(cs)]); }
        return res.status(200).json({ ok: true, imported: ok, skipped });
      }
      if (b.action === 'add') {
        const e = cleanEntry(b.entry);
        if (!e) return res.status(400).json({ error: 'bad_entry' });
        await redis(['HSET', 'ysg:entries', e.id, JSON.stringify(e)]);
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'delete') {
        if (!/^[A-Za-z0-9_-]{4,64}$/.test(String(b.id || ''))) return res.status(400).json({ error: 'bad_id' });
        await redis(['HDEL', 'ysg:entries', String(b.id)]);
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'settings') {
        const clean = cleanSettings(b.settings);
        if (!clean) return res.status(400).json({ error: 'bad_settings' });
        await redis(['SET', 'ysg:settings', JSON.stringify(clean)]);
        return res.status(200).json({ ok: true });
      }
      return res.status(400).json({ error: 'bad_action' });
    }
    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (err) {
    return res.status(500).json({ error: 'server_error' });
  }
};

module.exports.config = { maxDuration: 30 };
