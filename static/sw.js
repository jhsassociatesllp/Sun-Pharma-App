/**
 * Service Worker Strategy:
 *
 * HTML pages (.html, /)  → Network-first, NO caching
 *   Always fetched fresh. If offline, show a fallback.
 *
 * API calls (/api/*)     → Network-only, never cache
 *
 * Static assets (fonts, icons, images) → Cache-first
 *   These rarely change. Cached indefinitely.
 */

const CACHE = 'tree-assets-v1';

// Only cache true static assets — NOT html files
const PRECACHE = [
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/manifest.json',
];

// ── Install: pre-cache only static assets ──────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.allSettled(PRECACHE.map(url => c.add(url).catch(() => {}))))
      .then(() => self.skipWaiting())   // activate immediately, don't wait
  );
});

// ── Activate: delete old caches ────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())  // take control of all open tabs
  );
});

// ── Fetch: different strategy per resource type ─────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // 1. API calls — always go to network, never intercept
  if (url.pathname.startsWith('/api/')) {
    return; // let browser handle normally
  }

  // 2. HTML pages — NETWORK FIRST, no caching
  //    If network fails (offline), show inline offline page
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

  // 3. Static assets — cache first, network fallback
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        // Only cache successful same-origin responses
        if (res.ok && url.origin === location.origin) {
          caches.open(CACHE).then(c => c.put(e.request, res.clone()));
        }
        return res;
      });
    })
  );
});

// ── Offline fallback page (shown when HTML fetch fails) ─────
function offlinePage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Offline — Tree Plantation</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'DM Sans',sans-serif;background:#f8f6f1;min-height:100vh;
         display:flex;align-items:center;justify-content:center;padding:2rem;text-align:center}
    .wrap{max-width:320px}
    .icon{font-size:3rem;margin-bottom:1.25rem}
    h1{font-size:1.4rem;color:#1a3a2a;margin-bottom:.6rem;font-weight:700}
    p{color:#6b7280;font-size:.9rem;line-height:1.6;margin-bottom:1.5rem}
    button{background:#2d6a4f;color:#fff;border:none;padding:11px 24px;border-radius:10px;
           font-size:.9rem;font-weight:600;cursor:pointer}
    button:hover{background:#52b788}
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