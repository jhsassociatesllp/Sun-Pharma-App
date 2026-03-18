/**
 * JHS Tree Plantation — Service Worker
 *
 * HTML pages (.html, /)  → Network-first, NO caching
 * API calls (/api/*)     → Network-only, never cache
 * Static assets          → Cache-first
 */

const CACHE = 'jhs-tree-assets-v1';

const PRECACHE = [
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/manifest.json',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.allSettled(PRECACHE.map(url => c.add(url).catch(() => {}))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  if (url.pathname.startsWith('/api/')) {
    return;
  }

  if (
    e.request.mode === 'navigate' ||
    url.pathname.endsWith('.html') ||
    url.pathname === '/'
  ) {
    e.respondWith(
      fetch(e.request)
        .catch(() => new Response(offlinePage(), {
          headers: { 'Content-Type': 'text/html' }
        }))
    );
    return;
  }

  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res.ok && url.origin === location.origin) {
          const resClone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, resClone));
        }
        return res;
      });
    })
  );
});

function offlinePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Offline — JHS Tree Plantation</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'DM Sans',sans-serif;background:#f5f3ee;min-height:100vh;
         display:flex;align-items:center;justify-content:center;padding:2rem;text-align:center}
    .wrap{max-width:320px}
    .icon{font-size:3rem;margin-bottom:1.25rem}
    h1{font-size:1.4rem;color:#0f1525;margin-bottom:.6rem;font-weight:700}
    p{color:#6b7280;font-size:.9rem;line-height:1.6;margin-bottom:1.5rem}
    button{background:#0f1525;color:#fff;border:none;padding:11px 24px;border-radius:10px;
           font-size:.9rem;font-weight:600;cursor:pointer}
    button:hover{background:#1a2240}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="icon">🌳</div>
    <h1>You're offline</h1>
    <p>No internet connection. Any data you've filled is safely saved locally and will sync automatically when you're back online.</p>
    <button onclick="location.reload()">Try again</button>
  </div>
</body>
</html>`;
}