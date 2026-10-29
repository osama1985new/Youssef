// Vercel serverless function. Stores entries in Upstash Redis (Vercel Marketplace) behind a family PIN.
const crypto = require('crypto');

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const PIN = process.env.FAMILY_PIN;
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

function pinOk(given) {
  const a = Buffer.from(String(given || ''));
  const b = Buffer.from(String(PIN));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
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
  if (glucose === null && apidra === null && tresiba === null) return null;
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
  return { id, ts: ts.toISOString(), slot: e.slot, glucose, apidra, tresiba, carbs, meal, note: String(e.note || '').slice(0, 300) };
}

const SETTING_RANGES = { low: [40, 120], high: [120, 400], plan: [0.5, 100], icr: [1, 150], icrBf: [1, 150], icrLn: [1, 150], icrDn: [1, 150], isf: [5, 400], target: [70, 200], maxd: [0.5, 50] };
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

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ error: 'storage_not_configured' });
  if (PIN && !pinOk(req.headers['x-pin'])) {
    await new Promise(r => setTimeout(r, 800));
    return res.status(401).json({ error: 'bad_pin' });
  }
  try {
    if (req.method === 'GET') {
      const [flat, settingsRaw] = await Promise.all([redis(['HGETALL', 'ysg:entries']), redis(['GET', 'ysg:settings'])]);
      const entries = [];
      for (let i = 1; i < (flat || []).length; i += 2) {
        try { entries.push(JSON.parse(flat[i])); } catch (e) {}
      }
      let settings = null;
      try { settings = settingsRaw ? JSON.parse(settingsRaw) : null; } catch (e) {}
      return res.status(200).json({ entries, settings });
    }
    if (req.method === 'POST') {
      const b = req.body || {};
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
