/* Service worker: offline shell + push reminders */
const CACHE = 'ysg-shell-v2';
const SHELL = ['/', '/apple-touch-icon.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).catch(() => {}).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

function timeout(ms) { return new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms)); }

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return; // never cache data
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      try {
        const res = await Promise.race([fetch(req, { cache: 'no-cache' }), timeout(4000)]);
        if (res && res.ok) cache.put('/', res.clone());
        return res;
      } catch (err) {
        return (await cache.match('/')) || (await cache.match(req)) || Response.error();
      }
    })());
    return;
  }
  const sameOrFont = url.origin === location.origin || /fonts\.(googleapis|gstatic)\.com$/.test(url.hostname);
  if (!sameOrFont) return;
  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(req);
    const net = fetch(req).then(res => { if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone()); return res; }).catch(() => null);
    return hit || (await net) || Response.error();
  })());
});

async function subId(endpoint) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint));
  return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let msgs = [];
    try {
      const sub = await self.registration.pushManager.getSubscription();
      if (sub) {
        const r = await fetch('/api/data?inbox=' + await subId(sub.endpoint), { cache: 'no-store' });
        if (r.ok) msgs = (await r.json()).msgs || [];
      }
    } catch (err) {}
    const ICON = { 'g-low': '🔻', 'g-high': '🔺', fast: '🌅', bed: '🌙', tres: '💉', trY: '💉', med: '💊', visit: '🩺', visitp: '🩺', visitdone: '🩺', ket: '🧪', ketd: '🧪', nodose: '💉', apd: '⏱️', hypo15: '⏱️', hypo30: '⏱️', low2h: '⏱️', strips: '📦', needles: '📦', stock: '📦', test: '✅' };
    const iconFor = tag => { const b = String(tag || '').split(':')[0]; if (ICON[b]) return ICON[b]; if (b.indexOf('sp_') === 0) return '💊'; if (b.indexOf('stock') === 0) return '📦'; return '🔔'; };
    if (!msgs.length) {
      /* several pushes can arrive for one batch: the first one already showed everything. Never show an empty "open the app" notice. */
      const shown = await self.registration.getNotifications();
      if (shown.length) return;
      const n = await self.registration.showNotification('🔔 تذكير', { tag: 'generic', silent: true, icon: '/apple-touch-icon.png', lang: 'ar', dir: 'rtl' });
      setTimeout(async () => { (await self.registration.getNotifications({ tag: 'generic' })).forEach(x => x.close()); }, 800);
      return;
    }
    for (const m of msgs) {
      let body = m.b; const old = m.at && Date.now() - m.at > 45 * 60e3;
      if (old) { const t = new Date(m.at).toLocaleTimeString('ar-EG', { hour: 'numeric', minute: '2-digit', timeZone: 'Africa/Cairo' }); body = m.b + ' (موعده ' + t + ')'; }
      const title = iconFor(m.tag) + ' ' + m.t;
      await self.registration.showNotification(title, { body, tag: (m.tag || 'ysg') + (m.at ? ':' + m.at : ''), timestamp: m.at || Date.now(), icon: '/apple-touch-icon.png', lang: 'ar', dir: 'rtl' });
    }
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const tag = e.notification.tag || '';
    const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of all) { if ('focus' in c) { try { c.postMessage({ ntf: tag }); } catch (err) {} return c.focus(); } }
    return clients.openWindow('/?n=' + encodeURIComponent(tag));
  })());
});
