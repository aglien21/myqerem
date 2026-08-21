/* Familja Chat — service worker: cache + njoftimet push në background */
'use strict';
const CACHE = 'familja-chat-v1';
const SHELL = ['/', '/styles.css', '/app.js', '/manifest.webmanifest', '/icon-192.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => Promise.allSettled(SHELL.map((u) => c.add(u))))
      .then(() => self.skipWaiting())
  );
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* rrjeti i pari, cache si rezervë (që përditësimet të vinë menjëherë) */
self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET' || !e.request.url.startsWith(self.location.origin)) return;
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(e.request).then((m) => m || caches.match('/')))
  );
});

/* ---------- njoftimet push (kur aplikacioni është i mbyllur) ---------- */
self.addEventListener('push', (e) => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch (err) {
    try { data = { title: 'Familja Chat', body: e.data ? e.data.text() : '' }; } catch (err2) {}
  }
  const isCall = !!data.tag && data.tag.startsWith('call-');
  const opts = {
    body: isCall ? ((data.body || 'Thirrje') + ' — prek Përgjigju') : (data.body || 'Ke një mesazh të ri'),
    tag: data.tag || 'familja',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: data,
    vibrate: isCall ? [900, 400, 900, 400, 900, 400, 900] : [200, 100, 200, 100, 200],
    requireInteraction: isCall
  };
  if (isCall) {
    opts.sound = '/ring.wav';
    opts.actions = [
      { action: 'accept', title: 'Pergjigju' },
      { action: 'decline', title: 'Refuzo' }
    ];
  } else {
    opts.sound = 'default';
  }
  e.waitUntil(self.registration.showNotification(data.title || 'Familja Chat', opts).then(() => {
    // shenja e kuqe ne ikona (ku mbështetet)
    try {
      if (data.badge && self.navigator && self.navigator.setAppBadge) {
        self.navigator.setAppBadge(data.badge).catch(() => {});
      }
    } catch (err) {}
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const act = e.action || '';
  const url = act === 'accept' ? '/?call=accept' : (act === 'decline' ? '/?call=decline' : '/');
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const w of list) {
        if ('focus' in w && 'postMessage' in w) {
          if (act === 'accept' || act === 'decline') w.postMessage({ cmd: 'call-action', action: act });
          return w.focus();
        }
      }
      return self.clients.openWindow(url);
    })
  );
});
function dataUrl(n) {
  try { return (n.data && n.data.url) || '/'; } catch (e) { return '/'; }
}
