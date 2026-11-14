// Vercel serverless function. Stores entries in Upstash Redis (Vercel Marketplace) behind a family PIN.
const crypto = require('crypto');

const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const PIN = process.env.FAMILY_PIN;
const SUPP_KEYS = ['omega', 'milga', 'calmag', 'd3', 'vit'];
const SITE_KEYS = ['ab_r', 'ab_l', 'th_r', 'th_l', 'ar_r', 'ar_l'];
const SLOTS = ['fast','bf_before','bf_after','ln_before','ln_after','dn_before','dn_after','sn','bed','other'];

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
  const needleT = tresiba > 0 && (e.needleT === 'new' || e.needleT === 'reuse') ? e.needleT : null;
  const site = SITE_KEYS.includes(e.site) ? e.site : null;
  const tresibaTime = tresiba > 0 && /^([01]\d|2[0-3]):[0-5]\d$/.test(String(e.tresibaTime || '')) ? e.tresibaTime : null;
  return { id, ts: ts.toISOString(), slot: e.slot, glucose, apidra, tresiba, carbs, meal, note: String(e.note || '').slice(0, 300), needle, needleT, site, supp, tresibaTime, corr: e.corr === true && apidra > 0, ketT, ketV };
}

const SETTING_RANGES = { low: [40, 120], high: [120, 400], plan: [0.5, 100], icr: [1, 150], icrBf: [1, 150], icrLn: [1, 150], icrDn: [1, 150], isf: [5, 400], target: [70, 200], maxd: [0.5, 50], a1cVal: [3, 20], ketHigh: [180, 500], ketHours: [1, 8], wt: [20, 250], ht: [100, 230], bps: [60, 230], bpd: [30, 150], stripN: [1, 500], needleN: [1, 1000], needleUsed: [0, 1000], stockA: [0, 50], stockT: [0, 50], primeU: [0, 10], stockDays: [1, 60], fixBf: [0.5, 100], fixLn: [0.5, 100], fixDn: [0.5, 100] };
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
  out.myFoods = Array.isArray(s.myFoods) ? s.myFoods.slice(-60).map(m => ({ n: String((m && m.n) || '').slice(0, 40), c: Number(m && m.c) })).filter(m => m.n && Number.isFinite(m.c) && m.c >= 0 && m.c <= 100) : [];
  out.cgm = s.cgm === true;
  out.carbMode = s.carbMode === true;
  out.suppOmega = s.suppOmega === true; out.suppVit = s.suppVit === true;
  out.omegaAt = /^([01]\d|2[0-3]):[0-5]\d$/.test(String(s.omegaAt || '')) ? String(s.omegaAt) : null;
  out.vitAt = /^([01]\d|2[0-3]):[0-5]\d$/.test(String(s.vitAt || '')) ? String(s.vitAt) : null;
  out.birth = dOk(s.birth) ? String(s.birth) : null;
  out.medGot = /^\d{4}-(0[1-9]|1[0-2])$/.test(String(s.medGot || '')) ? String(s.medGot) : null;
  out.penAStart = dOk(s.penAStart) ? String(s.penAStart) : null;
  out.penTStart = dOk(s.penTStart) ? String(s.penTStart) : null;
  const dtOk = v => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(String(v || '')) && !isNaN(new Date(String(v)));
  out.stockAtA = dtOk(s.stockAtA) ? String(s.stockAtA) : null;
  out.stockAtT = dtOk(s.stockAtT) ? String(s.stockAtT) : null;
  out.visitLast = dtOk(s.visitLast) ? String(s.visitLast) : null;
  out.visitNext = dtOk(s.visitNext) ? String(s.visitNext) : null;
  out.visitNote = s.visitNote ? String(s.visitNote).trim().slice(0, 300) || null : null;
  out.ketExp = dOk(s.ketExp) ? String(s.ketExp) : null;
  out.stripStart = (dOk(s.stripStart) || dtOk(s.stripStart)) ? String(s.stripStart) : null;
  out.needleStart = (dOk(s.needleStart) || dtOk(s.needleStart)) ? String(s.needleStart) : null;
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


/* ---------- Web Push (no dependencies): VAPID + payload-less push; the service worker then reads the text from /api/data?inbox= ---------- */
const TZ = 'Africa/Cairo';
const b64u = b => Buffer.from(b).toString('base64url');
const subId = ep => crypto.createHash('sha256').update(String(ep)).digest('hex').slice(0, 32);
const PUSH_HOST_OK = /^https:\/\/([a-z0-9-]+\.)*(push\.apple\.com|googleapis\.com|push\.services\.mozilla\.com|mozilla\.com|notify\.windows\.com)\//i;
async function getVapid() {
  const raw = await redis(['GET', 'ysg:vapid']);
  if (raw) { try { const v = JSON.parse(raw); if (v && v.pub && v.d) return v; } catch (e) {} }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pj = publicKey.export({ format: 'jwk' }), sj = privateKey.export({ format: 'jwk' });
  const v = { pub: b64u(Buffer.concat([Buffer.from([4]), Buffer.from(pj.x, 'base64url'), Buffer.from(pj.y, 'base64url')])), x: pj.x, y: pj.y, d: sj.d };
  await redis(['SET', 'ysg:vapid', JSON.stringify(v), 'NX']);
  const again = await redis(['GET', 'ysg:vapid']);
  try { return JSON.parse(again); } catch (e) { return v; }
}
function vapidAuth(v, endpoint, host) {
  const header = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const body = b64u(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://' + host }));
  const key = crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', x: v.x, y: v.y, d: v.d }, format: 'jwk' });
  const sig = crypto.sign('sha256', Buffer.from(header + '.' + body), { key, dsaEncoding: 'ieee-p1363' });
  return 'vapid t=' + header + '.' + body + '.' + b64u(sig) + ', k=' + v.pub;
}
async function pushTo(sub, msg, v, host) {
  const id = subId(sub.endpoint);
  await redis(['RPUSH', 'ysg:inbox:' + id, JSON.stringify(Object.assign({ at: Date.now() }, msg))]);
  await redis(['EXPIRE', 'ysg:inbox:' + id, '86400']);
  let status = 0;
  try {
    const r = await fetch(sub.endpoint, { method: 'POST', headers: { Authorization: vapidAuth(v, sub.endpoint, host), TTL: '7200', Urgency: 'high', 'Content-Length': '0' } });
    status = r.status;
  } catch (e) { status = 0; }
  try { await redis(['LPUSH', 'ysg:pushlog', new Date().toISOString().slice(0, 16) + ' ' + (msg.tag || msg.t) + ' ' + id.slice(0, 4) + ' ' + status]); await redis(['LTRIM', 'ysg:pushlog', '0', '59']); } catch (x) {}
  if (status === 404 || status === 410) { await redis(['HDEL', 'ysg:subs', id]); await redis(['DEL', 'ysg:inbox:' + id]); }
  return status;
}
function cairo(ms) {
  const p = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(ms));
  const o = {}; p.forEach(x => { o[x.type] = x.value; });
  return { key: o.year + '-' + o.month + '-' + o.day, h: +o.hour, m: +o.minute, stamp: o.year + '-' + o.month + '-' + o.day + 'T' + o.hour + ':' + o.minute };
}
const sday = ms => cairo(ms - 4 * 3600e3).key;
function t12(hhmm) {
  const [h, m] = hhmm.split(':').map(Number); const ap = h >= 12 ? 'م' : 'ص'; const hh = h % 12 === 0 ? 12 : h % 12;
  return hh + ':' + String(m).padStart(2, '0') + ' ' + ap;
}
async function recentEntries(now) {
  let flat = await redis(['HGETALL', 'ysg:recent']);
  if (!flat || !flat.length) {
    const seeded = await redis(['SET', 'ysg:recent:seeded', '1', 'NX']);
    if (seeded === 'OK') {
      const all = await redis(['HGETALL', 'ysg:entries']); const args = ['HSET', 'ysg:recent'];
      for (let i = 1; i < (all || []).length; i += 2) { try { const e = JSON.parse(all[i]); if (now - Date.parse(e.ts) < 72 * 3600e3) args.push(all[i - 1], all[i]); } catch (x) {} }
      if (args.length > 2) await redis(args);
      flat = await redis(['HGETALL', 'ysg:recent']);
    }
  }
  const list = [], stale = [];
  for (let i = 1; i < (flat || []).length; i += 2) {
    try { const e = JSON.parse(flat[i]); if (now - Date.parse(e.ts) > 72 * 3600e3) stale.push(flat[i - 1]); else list.push(e); } catch (x) {}
  }
  if (stale.length) await redis(['HDEL', 'ysg:recent'].concat(stale));
  return list;
}
async function notifyOthers(msgs, srcEp, host) {
  const flat = await redis(['HGETALL', 'ysg:subs']); const subs = [];
  const skip = srcEp ? subId(srcEp) : null;
  for (let i = 0; i < (flat || []).length; i += 2) { try { const sb = JSON.parse(flat[i + 1]); if (sb && (sb.role === 'edit' || sb.role === 'view') && flat[i] !== skip) subs.push(sb); } catch (e) {} }
  if (!subs.length) return;
  const v = await getVapid();
  for (const m of msgs) await Promise.allSettled(subs.map(sb => pushTo(sb, m, v, host)));
}
async function entryAlerts(e, existed, srcEp, host) {
  if (existed || Date.now() - Date.parse(e.ts) > 3 * 3600e3 || Date.parse(e.ts) - Date.now() > 3600e3) return;
  let st = {}; try { st = JSON.parse(await redis(['GET', 'ysg:settings']) || '{}') || {}; } catch (x) {}
  const c = cairo(Date.parse(e.ts)), tm = t12(String(c.h).padStart(2, '0') + ':' + String(c.m).padStart(2, '0')), msgs = [];
  const fm = n => (Number.isInteger(n) ? String(n) : String(n).replace(/\.0+$/, ''));
  if (e.glucose != null && e.glucose < (st.low || 90)) msgs.push({ t: (e.glucose < 70 ? 'عاجل: ' : '') + 'سكر منخفض', b: e.glucose + ' سُجِّل الساعة ' + tm + '. اتبع خطة الطبيب للهبوط وأعد القياس بعد 15 دقيقة', tag: 'g-low' });
  if (e.glucose != null && e.glucose > Math.min(st.high || 200, 200)) {
    const dose = 'قد يلزم جرعة تصحيح بعد الرجوع لخطة الطبيب';
    msgs.push({ t: 'سكر مرتفع', b: e.glucose + ' سُجِّل الساعة ' + tm + '. ' + dose + (e.glucose > 300 ? '، وقِس الكيتونات حسب الخطة' : ''), tag: 'g-high' });
  }
  if (msgs.length) await notifyOthers(msgs, null, host);
}
const zlib = require('zlib');
const BK_DAYS = 30;
async function backupNow(now) {
  const c = cairo(now); if (c.h < 4) return null;
  const key = 'ysg:bk:' + c.key;
  if (Number(await redis(['EXISTS', key]))) return null;
  const flat = await redis(['HGETALL', 'ysg:entries']); let entries = [];
  for (let i = 1; i < (flat || []).length; i += 2) { try { entries.push(JSON.parse(flat[i])); } catch (x) {} }
  entries.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  const st = await redis(['GET', 'ysg:settings']);
  let blob, n = entries.length;
  for (;;) {
    blob = zlib.gzipSync(Buffer.from(JSON.stringify({ at: now, settings: st ? JSON.parse(st) : null, entries }))).toString('base64');
    if (blob.length < 900000 || entries.length < 50) break;
    entries = entries.slice(Math.ceil(entries.length * 0.1));
  }
  const ttl = String(BK_DAYS * 86400);
  await redis(['SET', key, blob, 'EX', ttl]);
  await redis(['SET', 'ysg:bkn:' + c.key, String(entries.length), 'EX', ttl]);
  return { key, n: entries.length };
}
async function runCron(host, force) {
  /* deep night 00:00-06:00 Cairo: check every 10 minutes instead of 5 (saves commands; every alert window is wider than 10 min) */
  if (!force) { const qc = cairo(Date.now()); if (qc.h < 6 && Math.floor(qc.m / 5) % 2 === 1) return { sent: [], note: 'quiet_hours' }; }
  try { await backupNow(force && force.now ? force.now : Date.now()); } catch (e) {}
  const subsFlat = await redis(['HGETALL', 'ysg:subs']); const subs = [];
  for (let i = 1; i < (subsFlat || []).length; i += 2) { try { const sb = JSON.parse(subsFlat[i]); if (sb && sb.role === 'edit') subs.push(sb); } catch (e) {} }
  if (!subs.length) return { sent: [], note: 'no_subscribers' };
  const now = force && force.now ? force.now : Date.now(), c = cairo(now);
  let settings = {}; try { settings = JSON.parse(await redis(['GET', 'ysg:settings']) || '{}') || {}; } catch (e) {}
  const night = c.h >= 22 || c.h < 4, morning = c.h >= 6 && c.h < 11, vn = typeof settings.visitNext === 'string' ? settings.visitNext : '';
  const visitSoon = vn && vn.slice(0, 10) >= c.key && vn.slice(0, 10) <= cairo(now + 24 * 3600e3).key;
  const today = sday(now), recentAll = await recentEntries(now), E = recentAll.filter(e => sday(Date.parse(e.ts)) === today);
  const hasRead = sl => E.some(e => e.slot === sl && e.glucose != null);
  const due = [];
  if (!settings.cgm) {
    if (morning && !hasRead('fast')) due.push(['fast', 'قراءة الصيام', 'لم تُسجَّل اليوم بعد']);
    if (night && !hasRead('bed')) due.push(['bed', 'قبل النوم', 'سجّل قراءة قبل النوم']);
  }
  if (night && !E.some(e => e.tresiba > 0)) due.push(['tres', 'ترسيبا', 'جرعة ترسيبا لم تُسجَّل اليوم بعد']);
  if (vn && vn > c.stamp) {
    const vd = vn.slice(0, 10), vt = t12(vn.slice(11, 16));
    if (vd === c.key && c.h >= 8 && c.h < 11) due.push(['visit:' + vd, 'زيارة الطبيب', 'اليوم الساعة ' + vt]);
    else if (vd === cairo(now + 24 * 3600e3).key && c.h >= 20 && c.h < 22) due.push(['visitp:' + vd, 'زيارة الطبيب', 'غدًا الساعة ' + vt]);
  }
  if (vn && vn <= c.stamp && vn.slice(0, 10) === c.key) {
    const mins = (Date.parse(c.stamp + ':00Z') - Date.parse(vn + ':00Z')) / 60000;
    if (mins >= 30 && mins <= 360) due.push(['visitdone:' + vn.slice(0, 10), 'زيارة الطبيب', 'فات موعد زيارة الطبيب. إن ذهبت، سجّلها واكتب الموعد القادم']);
  }
  /* settings alerts: ketone after high sugar (realtime) */
  const RR = recentAll.filter(e => e.glucose != null).sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts));
  const lastR = RR[RR.length - 1], kHi = settings.ketHigh || 300, kHr = settings.ketHours || 3;
  if (lastR && lastR.glucose > kHi && now - Date.parse(lastR.ts) < 6 * 3600e3) {
    let t0 = Date.parse(lastR.ts);
    for (let i = RR.length - 2; i >= 0 && RR[i].glucose > kHi; i--) t0 = Date.parse(RR[i].ts);
    if (Date.parse(lastR.ts) - t0 >= (kHr - 0.25) * 3600e3 && !recentAll.some(e => e.ketT && Date.parse(e.ts) >= t0))
      due.push(['ket:' + t0, 'كيتون', 'السكر فوق ' + kHi + ' منذ فترة. أجرِ تحليل الكيتون حسب خطة الطبيب']);
  }
  /* before-meal reading logged but no Apidra dose logged afterwards */
  RR.filter(e => ['bf_before', 'ln_before', 'dn_before'].includes(e.slot) && !(e.apidra > 0)).forEach(e => {
    const t = Date.parse(e.ts), dt = now - t;
    if (dt >= 20 * 60e3 && dt < 90 * 60e3 && !recentAll.some(x => x.apidra > 0 && Date.parse(x.ts) >= t - 5 * 60e3 && Date.parse(x.ts) <= t + dt))
      due.push(['nodose:' + t, 'جرعة أبيدرا', 'سجّلت قراءة ' + ({ bf_before: 'قبل الفطور', ln_before: 'قبل الغداء', dn_before: 'قبل العشاء' })[e.slot] + ' ولم تُسجّل الجرعة']);
  });
  /* 2 hours after an Apidra dose: remind to check sugar (unless a reading was logged after the dose) */
  if (!settings.cgm) recentAll.filter(e => e.apidra > 0).forEach(e => {
    const t = Date.parse(e.ts), dt = now - t;
    if (dt >= 2 * 3600e3 && dt < 4 * 3600e3 && !RR.some(r => Date.parse(r.ts) >= t + 30 * 60e3))
      due.push(['apd:' + t, 'قراءة بعد الأكل', 'مضت ساعتان على جرعة أبيدرا (' + (Number.isInteger(e.apidra) ? e.apidra : String(e.apidra)) + ' وحدة). قِس السكر وسجّله']);
  });
  /* omega after breakfast / vitamins after lunch: 1h after the meal's Apidra dose, or a fixed time when no dose was logged; once a day, only if not logged yet */
  [['omega', settings.suppOmega, settings.omegaAt || '10:30', 5, 11, [['omega', 'الأوميجا', ['omega']], ['milga', 'ميلجا أدفانس', ['milga']]], 'بعد الفطور'], ['vit', settings.suppVit, settings.vitAt || '15:30', 12, 17, [['calmag', 'الكال ماج', ['calmag', 'vit']], ['d3', 'فيتامين D3', ['d3', 'vit']]], 'بعد الغداء']].forEach(([k, on, at, h1, h2, items, when]) => {
    if (!on) return;
    const miss = items.filter(([, , keys]) => !recentAll.some(e => (e.supp || []).some(x => keys.includes(x)) && sday(Date.parse(e.ts)) === today)).map(x => x[1]);
    if (!miss.length) return;
    const meal = E.filter(e => e.apidra > 0).map(e => Date.parse(e.ts)).filter(t => { const h = cairo(t).h; return h >= h1 && h < h2; }).sort((a, b) => a - b)[0];
    let ok;
    if (meal) ok = now - meal >= 3600e3 && now - meal < 5 * 3600e3;
    else { const [hh, mm] = at.split(':').map(Number), mins = c.h * 60 + c.m, tgt = hh * 60 + mm; ok = mins >= tgt && mins < tgt + 180; }
    if (ok) due.push(['sp_' + k, 'المكملات', 'حان وقت ' + miss.join(' و') + ' ' + when + '. لم يُسجَّل اليوم بعد']);
  });
  /* yesterday's Tresiba missing */
  if (c.h >= 8 && c.h < 11) {
    const yk = sday(now - 24 * 3600e3), Y = recentAll.filter(e => sday(Date.parse(e.ts)) === yk);
    if (Y.length && !Y.some(e => e.tresiba > 0)) due.push(['trY', 'ترسيبا', 'جرعة ترسيبا أمس لم تُسجَّل']);
  }
  /* monthly medication: every day from the 1st until confirmed */
  if (c.h === 10 && settings.medGot !== c.key.slice(0, 7)) due.push(['med', 'العلاج الشهري', 'لم تحصل عليه بعد. اضغط "حصلت عليه" في التطبيق عند استلامه']);
  /* low reading: remind to re-check 2 hours later if nothing newer was logged */
  if (lastR && !settings.cgm) {
    const dt = now - Date.parse(lastR.ts);
    if (lastR.glucose < (settings.low || 90)) {
      const t = Date.parse(lastR.ts);
      if (dt >= 15 * 60e3 && dt < 30 * 60e3) due.push(['hypo15:' + t, 'أعد قياس السكر', 'مضت 15 دقيقة على قراءة ' + lastR.glucose + '. أعد القياس حسب خطة الطبيب وسجّل القراءة']);
      else if (dt >= 30 * 60e3 && dt < 60 * 60e3) due.push(['hypo30:' + t, 'أعد قياس السكر', 'لم تُسجَّل قراءة جديدة بعد ' + lastR.glucose + '. أعد القياس حسب خطة الطبيب وسجّلها']);
    }
    if (lastR.glucose < (settings.low || 90) && dt >= 2 * 3600e3 && dt < 6 * 3600e3)
      due.push(['low2h:' + Date.parse(lastR.ts), 'قراءة أخرى', 'آخر قراءة كانت ' + lastR.glucose + ' قبل ساعتين. قِس السكر مرة أخرى']);
  }
  /* settings alerts: once a day around 9am (strips, needles, ketone strips, lab checks) */
  if (c.h === 9) {
    const flag = await redis(['SET', 'ysg:flag:daily:' + c.key, '1', 'NX', 'EX', '172800']);
    if (flag === 'OK') {
      const dayNo = k => Math.floor(Date.parse(k + 'T00:00:00Z') / 86400e3), todayN = dayNo(c.key);
      const dueIn = (dateStr, months) => { const d = new Date(dateStr + 'T12:00:00Z'); d.setUTCMonth(d.getUTCMonth() + (months || 0)); return Math.floor(d.getTime() / 86400e3) - todayN; };
      const gentle = l => l === 30 || l === 14 || l === 7 || l === 3 || l === 1 || l === 0 || (l < 0 && (-l - 1) % 7 === 0);
      const all = []; const flat = await redis(['HGETALL', 'ysg:entries']);
      for (let i = 1; i < (flat || []).length; i += 2) { try { all.push(JSON.parse(flat[i])); } catch (x) {} }
      const stamp = e => cairo(Date.parse(e.ts)).stamp;
      if (settings.stripStart) {
        const total = settings.stripN || 50, used = all.filter(e => e.glucose != null && stamp(e) >= settings.stripStart).length, left = total - used;
        if (left <= 2) due.push(['strips', 'شرائط السكر', left <= 0 ? 'انتهت الشرائط. جهّز علبة جديدة' : 'تبقّى ' + left + (left === 1 ? ' شريط' : ' شرائط') + ' فقط. جهّز علبة جديدة']);
      }
      if (settings.needleStart) {
        const total = settings.needleN || 100; let used = settings.needleUsed || 0;
        all.forEach(e => { if (stamp(e) < settings.needleStart) return; if (e.apidra > 0 && e.needle === 'new') used++; if (e.tresiba > 0 && (e.needleT || (e.apidra > 0 ? null : e.needle)) === 'new') used++; });
        const left = total - used;
        if (left <= 3) due.push(['needles', 'أسنان الأقلام', left <= 0 ? 'انتهت الأسنان. جهّز علبة جديدة' : 'تبقّى ' + left + (left > 2 ? ' أسنان' : ' سن') + ' فقط. جهّز علبة جديدة']);
      }
      [['A', 'apidra', 'أبيدرا'], ['T', 'tresiba', 'ترسيبا']].forEach(([k, f, nm]) => {
        const cnt = settings['stock' + k], at = settings['stockAt' + k];
        if (!(cnt > 0) || !at) return;
        let used = 0, sum14 = 0, firstMs = now;
        all.forEach(e => { if (!(e[f] > 0)) return; const t = Date.parse(e.ts); if (t < firstMs) firstMs = t; if (stamp(e) >= at) used += e[f]; if (now - t < 14 * 86400e3) sum14 += e[f]; });
        let daily = k === 'A' ? (settings.fixBf || 0) + (settings.fixLn || 0) + (settings.fixDn || 0) : (settings.plan || 0);
        if (!(daily > 0)) daily = sum14 / Math.max(3, Math.min(14, (now - firstMs) / 86400e3));
        if (!(daily > 0)) return;
        const left = Math.max(0, cnt * 300 - used), days = Math.floor(left / daily), thr = settings.stockDays || 14;
        const lvl = [7, 3, 1, 0].find(x => days <= x);
        if (lvl === undefined) return;
        due.push(['stock' + k + lvl, 'مخزون ' + nm, days <= 0 ? 'المخزون على وشك النفاد. جهّز أقلامًا جديدة' : 'يكفي حوالي ' + days + ' يوم (' + Math.round(left) + ' وحدة). جهّز أقلامًا جديدة']);
      });
    }
  }
  /* dangerous ketone result */
  const lastK = recentAll.filter(e => e.ketT).sort((x, y) => Date.parse(x.ts) - Date.parse(y.ts)).pop();
  if (lastK && now - Date.parse(lastK.ts) < 12 * 3600e3) {
    const kd = lastK.ketT === 'b' ? Number(lastK.ketV) >= 1.5 : !['neg', 'small'].includes(lastK.ketV);
    if (kd) due.push(['ketd:' + lastK.ts, 'كيتون', 'آخر نتيجة كيتون خطرة. كلّم الطبيب فورًا واتبع خطته']);
  }
  const sent = [];
  if (!due.length) return { sent };
  const v = await getVapid();
  for (const [type, title, body] of due) {
    const mark = type.startsWith('stock') ? await redis(['SET', 'ysg:sent:' + type, '1', 'NX', 'EX', '864000']) : await redis(['SET', 'ysg:sent:' + type + ':' + today, '1', 'NX', 'EX', '172800']);
    if (mark !== 'OK') continue;
    for (const sb of subs) await pushTo(sb, { t: title, b: body, tag: type.split(':')[0] }, v, host);
    sent.push(type.split(':')[0]);
  }
  return { sent };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ error: 'storage_not_configured' });
  try {
    if (req.method === 'GET' && req.query && req.query.inbox !== undefined) {
      const id = String(req.query.inbox);
      if (!/^[a-f0-9]{32}$/.test(id)) return res.status(400).json({ error: 'bad_id' });
      const raw = await redis(['LRANGE', 'ysg:inbox:' + id, '0', '-1']);
      if (raw && raw.length) await redis(['DEL', 'ysg:inbox:' + id]);
      const msgs = []; for (const r of raw || []) { try { msgs.push(JSON.parse(r)); } catch (e) {} }
      return res.status(200).json({ msgs });
    }
    if (req.method === 'GET' && req.query && req.query.cron !== undefined) {
      return res.status(200).json(await runCron(req.headers.host || 'localhost'));
    }
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
      if (role !== 'edit' && !['vapid', 'subscribe', 'unsubscribe', 'testpush'].includes(b.action)) return res.status(403).json({ error: 'read_only' });
      if (b.action === 'vapid') { const v = await getVapid(); return res.status(200).json({ key: v.pub }); }
      if (b.action === 'subscribe') {
        const ep = b.sub && String(b.sub.endpoint || '');
        if (!ep || ep.length > 700 || !PUSH_HOST_OK.test(ep)) return res.status(400).json({ error: 'bad_sub' });
        await redis(['HSET', 'ysg:subs', subId(ep), JSON.stringify({ endpoint: ep, role: role === 'edit' ? 'edit' : 'view', t: Date.now() })]);
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'unsubscribe') {
        const ep = String(b.endpoint || ''); if (!ep) return res.status(400).json({ error: 'bad_sub' });
        await redis(['HDEL', 'ysg:subs', subId(ep)]); await redis(['DEL', 'ysg:inbox:' + subId(ep)]);
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'testpush') {
        const ep = String(b.endpoint || ''); if (!PUSH_HOST_OK.test(ep)) return res.status(400).json({ error: 'bad_sub' });
        const st = await pushTo({ endpoint: ep }, { t: 'الإشعارات تعمل', b: 'ستصلك التذكيرات على هذا الهاتف', tag: 'test' }, await getVapid(), req.headers.host || 'localhost');
        return res.status(200).json({ ok: st >= 200 && st < 300, status: st });
      }
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
      if (b.action === 'backups') {
        const ks = (await redis(['KEYS', 'ysg:bk:*'])) || [];
        const days = ks.map(k => k.slice(7)).filter(d => /^\d{4}-\d\d-\d\d$/.test(d)).sort().reverse();
        const out = [];
        for (const d of days) out.push({ d, n: Number(await redis(['GET', 'ysg:bkn:' + d])) || 0 });
        return res.status(200).json({ backups: out });
      }
      if (b.action === 'restorebk') {
        const d = String(b.d || ''); if (!/^\d{4}-\d\d-\d\d$/.test(d)) return res.status(400).json({ error: 'bad_date' });
        const raw = await redis(['GET', 'ysg:bk:' + d]); if (!raw) return res.status(404).json({ error: 'no_backup' });
        let data; try { data = JSON.parse(zlib.gunzipSync(Buffer.from(raw, 'base64')).toString('utf8')); } catch (x) { return res.status(500).json({ error: 'bad_backup' }); }
        let ok = 0; const recent72 = Date.now() - 72 * 3600e3;
        const list = Array.isArray(data.entries) ? data.entries : [];
        for (let i = 0; i < list.length; i += 300) {
          const a = ['HSET', 'ysg:entries'], r = ['HSET', 'ysg:recent'];
          list.slice(i, i + 300).forEach(x => { const e = cleanEntry(x); if (!e) return; a.push(e.id, JSON.stringify(e)); ok++; if (Date.parse(e.ts) > recent72) r.push(e.id, JSON.stringify(e)); });
          if (a.length > 2) await redis(a);
          if (r.length > 2) await redis(r);
        }
        let restoredSettings = false;
        if (data.settings) { const cs = cleanSettings(data.settings); if (cs) { const prevRaw = await redis(['GET', 'ysg:settings']); if (prevRaw) await redis(['SET', 'ysg:settings:prev', prevRaw]); await redis(['SET', 'ysg:settings', JSON.stringify(cs)]); restoredSettings = true; } }
        return res.status(200).json({ ok: true, restored: ok, settings: restoredSettings });
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
        const prevRaw = await redis(['HGET', 'ysg:entries', e.id]); let prevG = null; try { prevG = prevRaw ? JSON.parse(prevRaw).glucose : null; } catch (x) {}
        const existed = !!prevRaw && prevG === e.glucose;
        await redis(['HSET', 'ysg:entries', e.id, JSON.stringify(e)]);
        try { await redis(['HSET', 'ysg:recent', e.id, JSON.stringify(e)]); } catch (x) {}
        try { await entryAlerts(e, existed, String(b.src || ''), req.headers.host || 'localhost'); } catch (x) {}
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'delete') {
        if (!/^[A-Za-z0-9_-]{4,64}$/.test(String(b.id || ''))) return res.status(400).json({ error: 'bad_id' });
        await redis(['HDEL', 'ysg:entries', String(b.id)]);
        try { await redis(['HDEL', 'ysg:recent', String(b.id)]); } catch (x) {}
        return res.status(200).json({ ok: true });
      }
      if (b.action === 'settings') {
        const clean = cleanSettings(b.settings);
        if (!clean) return res.status(400).json({ error: 'bad_settings' });
        const prevRaw = await redis(['GET', 'ysg:settings']);
        let prev = null; try { prev = JSON.parse(prevRaw || 'null'); } catch (x) {}
        const real = o => Object.keys(o || {}).filter(k => !['low', 'high', 'scale'].includes(k) && o[k] != null && o[k] !== '' && o[k] !== false && !(Array.isArray(o[k]) && !o[k].length)).length;
        if (prev && real(prev) >= 4 && real(clean) === 0 && !b.force) return res.status(409).json({ error: 'looks_empty' });
        if (prevRaw) await redis(['SET', 'ysg:settings:prev', prevRaw]);
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
module.exports.runCron = runCron;
