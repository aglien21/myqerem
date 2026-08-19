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
  e.waitUntil(self.registration.showNotification(data.title || 'Familja Chat', {
    body: data.body || 'Ke një mesazh të ri',
    tag: data.tag || 'familja',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: data,
    vibrate: [200, 100, 200],
    requireInteraction: !!data.tag && data.tag.startsWith('call-')
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const w of list) {
        if ('focus' in w) return w.focus();
      }
      return self.clients.openWindow(dataUrl(e.notification));
    })
  );
});
function dataUrl(n) {
  try { return (n.data && n.data.url) || '/'; } catch (e) { return '/'; }
}
