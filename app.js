/* ============ Familja Chat — aplikacioni (klient) v1.1 ============ */
(function () {
'use strict';

/* ---------- ruajtje e sigurt (localStorage mund të jetë i bllokuar në iframe) ---------- */
const mem = {};
const storage = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return (k in mem) ? mem[k] : null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { mem[k] = v; } },
  del(k) { try { localStorage.removeItem(k); } catch (e) { delete mem[k]; } }
};

/* ---------- gjendja ---------- */
const state = {
  token: storage.get('fc-token'),
  me: null,
  users: new Map(),
  msgs: new Map(),
  unread: new Map(),
  last: new Map(),
  typing: new Map(),
  activeChat: null,
  ws: null,
  wsOk: false,
  reconnect: 1000,
  config: {
    vapidPublicKey: null,
    iceServers: [
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
      {
        urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:80?transport=tcp', 'turn:openrelay.metered.ca:443', 'turn:openrelay.metered.ca:443?transport=tcp'],
        username: 'openrelayproject',
        credential: 'openrelayproject'
      }
    ]
  },
  call: null,
  pendingOffer: null,
  iceQueue: [],
  audio: null,
  backgroundPaused: false,
  iceTypes: { host: 0, srflx: 0, relay: 0 },
  autoAccept: false,
  autoDecline: false
};
const settings = { sound: true };
try { Object.assign(settings, JSON.parse(storage.get('fc-settings') || '{}')); } catch (e) {}

/* ---------- histori lokale e pavdekshme (IndexedDB) ---------- */
let idb = null;
try {
  const rq = indexedDB.open('familja-chat', 1);
  rq.onupgradeneeded = (e) => { e.target.result.createObjectStore('msgs', { keyPath: 'id' }); };
  rq.onsuccess = (e) => { idb = e.target.result; };
  rq.onerror = () => {};
} catch (e) {}

function peerOf(m) { return state.me && m.from === state.me.id ? m.to : m.from; }
function cacheMsg(m) {
  if (!m || !m.id || !idb || !state.me) return;
  try {
    idb.transaction('msgs', 'readwrite').objectStore('msgs')
      .put({ id: m.id, owner: state.me.id, peer: peerOf(m), msg: m });
  } catch (e) {}
}
function loadCached(peer) {
  return new Promise((res) => {
    if (!idb || !state.me) return res([]);
    const out = [];
    try {
      const rq = idb.transaction('msgs', 'readonly').objectStore('msgs').openCursor();
      rq.onsuccess = (e) => {
        const c = e.target.result;
        if (c) {
          const v = c.value;
          if (v && v.owner === state.me.id && v.peer === peer) out.push(v.msg);
          c.continue();
        } else res(out);
      };
      rq.onerror = () => res(out);
    } catch (e) { res([]); }
  });
}
function mergeInto(peer, incoming) {
  const arr = ensureMsgs(peer);
  const byId = new Map();
  const noId = [];
  for (const x of arr) { if (x.id) byId.set(x.id, x); else noId.push(x); }
  for (const x of (incoming || [])) {
    if (!x || !x.id) continue;
    const cur = byId.get(x.id);
    byId.set(x.id, cur ? Object.assign(cur, x) : x);
  }
  const out = noId.concat([...byId.values()]).sort((a, b) => (a.ts || 0) - (b.ts || 0));
  state.msgs.set(peer, out);
  return out;
}

/* ============ FSHEHTËZI SKAJ-PËR-SKAJ (E2EE, si WhatsApp) ============
   Çelësat mbeten VETËM në pajisjet e folësve. Serveri sheh vetëm "gegenshkrime". */
function b64uBytes(u8) { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function ub64Bytes(b64) { const pad = '='.repeat((4 - b64.length % 4) % 4); const s = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
const E2EE = {
  ready: false, priv: null, pubB64: null, cache: new Map(),
  async init() {
    try {
      const saved = storage.get('fc-ekey');
      if (saved) {
        const j = JSON.parse(saved);
        this.priv = await crypto.subtle.importKey('jwk', j.priv, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        this.pubB64 = j.pub;
      } else {
        const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
        const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
        const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
        this.priv = kp.privateKey;
        this.pubB64 = b64uBytes(raw);
        storage.set('fc-ekey', JSON.stringify({ priv: privJwk, pub: this.pubB64 }));
      }
      this.ready = true;
    } catch (e) { this.ready = false; }
    return this.ready;
  },
  sendKey() {
    if (this.ready && state.wsOk && state.ws && state.ws.readyState === 1 && this.pubB64) {
      state.ws.send(JSON.stringify({ type: 'pubkey', key: this.pubB64 }));
    }
  },
  async keyFor(peerId) {
    if (this.cache.has(peerId)) return this.cache.get(peerId);
    const u = state.users.get(peerId);
    if (!u || !u.pubKey || !this.ready || !this.priv) return null;
    try {
      const peerKey = await crypto.subtle.importKey('raw', ub64Bytes(u.pubKey), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
      const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, this.priv, 256);
      const aes = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
      this.cache.set(peerId, aes);
      return aes;
    } catch (e) { return null; }
  },
  async seal(peerId, obj) {
    try {
      const k = await this.keyFor(peerId);
      if (!k) return null;
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(JSON.stringify(obj))));
      const out = new Uint8Array(iv.length + ct.length);
      out.set(iv); out.set(ct, iv.length);
      return b64uBytes(out);
    } catch (e) { return null; }
  },
  async open(peerId, b64) {
    try {
      const k = await this.keyFor(peerId);
      if (!k) return null;
      const buf = ub64Bytes(b64);
      const iv = new Uint8Array(buf.slice(0, 12));
      const ct = new Uint8Array(buf.slice(12));
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, ct);
      return JSON.parse(new TextDecoder().decode(pt));
    } catch (e) { return null; }
  }
};
async function hydrateMsg(m) {
  if (m && m.enc && !m.deleted) {
    const o = await E2EE.open(peerOf(m), m.enc);
    if (o) {
      m.text = o.t || '';
      if (o.i) m.img = o.i;
      if (o.v) m.voc = o.v;
      if (o.d) m.dur = o.d;
      m._dec = true;
    } else {
      m._fail = true;
    }
    delete m.enc;
  }
  return m;
}

/* ---------- shkurtesa ---------- */
const $ = (s) => document.querySelector(s);
const on = (el, ev, fn) => el.addEventListener(ev, fn);
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function fmtTime(ts) {
  try { return new Date(ts).toLocaleTimeString('sq-AL', { hour: '2-digit', minute: '2-digit' }); }
  catch (e) { return ''; }
}
function fmtDay(ts) {
  const d = new Date(ts), now = new Date();
  const sameDay = (a, b) => a.toDateString() === b.toDateString();
  const yest = new Date(now); yest.setDate(now.getDate() - 1);
  if (sameDay(d, now)) return 'Sot';
  if (sameDay(d, yest)) return 'Dje';
  try { return d.toLocaleDateString('sq-AL', { day: 'numeric', month: 'long', year: 'numeric' }); }
  catch (e) { return d.toDateString(); }
}
function fmtLastSeen(ts) {
  if (!ts) return 'offline';
  if (Date.now() - ts < 90e3) return 'ishte tani';
  try { return 'ishte online ' + new Date(ts).toLocaleString('sq-AL', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); }
  catch (e) { return 'offline'; }
}

/* ---------- diagnostika e thirrjes (për gjetjen e problemeve) ---------- */
const diag = [];
function dlog(msg) {
  try {
    diag.push(new Date().toLocaleTimeString('sq-AL') + ' · ' + msg);
    if (diag.length > 150) diag.shift();
  } catch (e) {}
}
let iceSent = 0, iceGot = 0;
function resetIceCounters() { iceSent = 0; iceGot = 0; state.iceTypes = { host: 0, srflx: 0, relay: 0 }; }

/* ---------- tingujt ---------- */
function audioCtx() {
  if (!state.audio) {
    try { state.audio = new (window.AudioContext || window.webkitAudioContext)(); } catch (e) { state.audio = null; }
  }
  if (state.audio && state.audio.state === 'suspended') state.audio.resume().catch(() => {});
  return state.audio;
}
function beep(freq, dur, when, vol) {
  const ctx = audioCtx(); if (!ctx) return;
  const o = ctx.createOscillator(), g = ctx.createGain();
  o.frequency.value = freq; o.type = 'sine';
  g.gain.setValueAtTime(vol || 0.12, ctx.currentTime + (when || 0));
  g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (when || 0) + dur);
  o.connect(g); g.connect(ctx.destination);
  o.start(ctx.currentTime + (when || 0)); o.stop(ctx.currentTime + (when || 0) + dur + 0.02);
}
function msgSound() { if (!settings.sound) return; try { beep(880, 0.09, 0); beep(1180, 0.12, 0.09); } catch (e) {} }
let ringTimer = null;
function startRing() {
  if (!settings.sound) return;
  stopRing();
  const pattern = () => { try { beep(780, 0.35, 0, 0.18); beep(780, 0.35, 0.6, 0.18); } catch (e) {} };
  pattern();
  ringTimer = setInterval(pattern, 2000);
  try { if (navigator.vibrate) navigator.vibrate([400, 200, 400]); } catch (e) {}
}
function stopRing() {
  if (ringTimer) { clearInterval(ringTimer); ringTimer = null; }
  try { if (navigator.vibrate) navigator.vibrate(0); } catch (e) {}
}

/* ---------- toast + banneri i gjendjes ---------- */
function toast(text) {
  const t = el('div', 'toast', text);
  $('#toasts').appendChild(t);
  setTimeout(() => t.remove(), 3200);
}
function checkServerAlive() {
  const b = $('#offline-banner');
  if (!b) return;
  fetch('/api/health').then((r) => { if (r.ok) b.classList.add('hidden'); }).catch(() => {
    b.classList.remove('hidden');
  });
}
setInterval(checkServerAlive, 15000);
checkServerAlive();

/* ---------- njoftimet në-app ---------- */
function canNotify() {
  return typeof Notification !== 'undefined' && Notification.permission === 'granted';
}
function notify(peer, text) {
  if (!canNotify()) return;
  try {
    const n = new Notification(peer.name, { body: text, tag: 'chat-' + peer.id, icon: '/icon-192.png' });
    n.onclick = () => { window.focus(); openChat(peer.id); n.close(); };
  } catch (e) {}
}

/* ================== HYRJA / REGJISTRIMI ================== */
async function api(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Gabim i panjohur');
  return data;
}
function authError(msg) {
  const box = $('#auth-error');
  box.textContent = msg; box.classList.remove('hidden');
}
function handleAuth(data) {
  storage.set('fc-token', data.token);
  state.token = data.token;
  state.me = data.user;
  state.inviteCode = data.inviteCode || '';
  enterApp();
}
on($('#form-login'), 'submit', async (e) => {
  e.preventDefault();
  $('#auth-error').classList.add('hidden');
  const f = e.target;
  try { handleAuth(await api('/api/login', { name: f.name.value, password: f.password.value })); }
  catch (err) { authError(err.message); }
});
on($('#form-register'), 'submit', async (e) => {
  e.preventDefault();
  $('#auth-error').classList.add('hidden');
  const f = e.target;
  try { handleAuth(await api('/api/register', { name: f.name.value, password: f.password.value, inviteCode: f.inviteCode.value })); }
  catch (err) { authError(err.message); }
});
document.querySelectorAll('.tab').forEach(t => on(t, 'click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  $('#form-login').classList.toggle('hidden', t.dataset.tab !== 'login');
  $('#form-register').classList.toggle('hidden', t.dataset.tab !== 'register');
  $('#auth-error').classList.add('hidden');
}));

/* ================== HYRJA NË APLIKACION ================== */
function enterApp() {
  $('#screen-auth').classList.add('hidden');
  $('#screen-list').classList.remove('hidden');
  $('#screen-chat').classList.toggle('hidden', window.innerWidth < 900 ? true : !state.activeChat);
  wsConnect();
  E2EE.init().then((ok) => { if (ok) E2EE.sendKey(); dlog('E2EE: ' + (ok ? 'gati' : 'jo aktiv')); });
  loadConfig().then(healSubscription);
  registerSW();
}
/* rivendos abonimin push nëse ka humbur (p.sh. pas një rinisjeje të serverit) */
async function healSubscription() {
  try {
    if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
    if (!state.config.vapidPublicKey || !('serviceWorker' in navigator) || !state.token) return;
    const reg = await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    if (!sub) {
      sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8(state.config.vapidPublicKey) });
    }
    await fetch('/api/push-sub', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: state.token, subscription: sub.toJSON() })
    });
  } catch (e) {}
}
function logout() {
  try { if (state.ws) state.ws.close(); } catch (e) {}
  storage.del('fc-token');
  location.reload();
}
async function loadConfig() {
  try {
    const r = await fetch('/api/config');
    state.config = await r.json();
    const hasTurn = (state.config.iceServers || []).some(x => String(x.urls).includes('turn:'));
    dlog('Konfigurimi: TURN ' + (hasTurn ? 'AKTIV ✓' : 'MOSS'));
  } catch (e) { dlog('Konfigurimi s\'u lexua'); }
}
function registerSW() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

/* ================== WEBSOCKET ================== */
function wsConnect() {
  if (!state.token) return;
  const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  let ws;
  try { ws = new WebSocket(proto + location.host + '/ws?token=' + encodeURIComponent(state.token)); }
  catch (e) { scheduleReconnect(); return; }
  state.ws = ws;

  ws.onopen = () => {
    state.wsOk = true;
    state.reconnect = 1000;
    updateConnStatus();
    ws.send(JSON.stringify({ type: 'hello' }));
    E2EE.sendKey();
  };
  ws.onmessage = (e) => { try { handleWs(JSON.parse(e.data)); } catch (err) {} };
  ws.onclose = () => {
    state.wsOk = false;
    updateConnStatus();
    scheduleReconnect();
  };
  ws.onerror = () => { try { ws.close(); } catch (e) {} };
}
function scheduleReconnect() {
  if (state.backgroundPaused) return; // në sfond: mos u rilidh — lër push-in të punojë
  setTimeout(() => { if (!state.wsOk) wsConnect(); }, state.reconnect);
  state.reconnect = Math.min(state.reconnect * 2, 15000);
}
setInterval(() => {
  if (state.wsOk && state.ws && state.ws.readyState === 1) {
    state.ws.send(JSON.stringify({ type: 'ping', t: Date.now() }));
  }
}, 10000);

function updateConnStatus() {
  const s = $('#conn-status');
  if (s) s.textContent = state.wsOk ? 'i lidhur' : 'po lidhet…';
}

function handleWs(m) {
  switch (m.type) {
    case 'ready': {
      state.me = m.me;
      state.inviteCode = m.inviteCode || state.inviteCode;
      state.users = new Map(m.users.filter(u => u.id !== m.me.id).map(u => [u.id, u]));
      state.unread = new Map(Object.entries(m.unread || {}).map(([k, v]) => [k, v]));
      state.last = new Map(Object.entries(m.last || {}));
      updateConnStatus();
      renderMe();
      renderList();
      // mbushi bisedat me mesazhet që mund të humbën gjatë kohës offline
      if (state.wsOk && state.ws) {
        const peers = new Set([...state.unread.keys()]);
        if (state.activeChat) peers.add(state.activeChat);
        for (const pid of peers) state.ws.send(JSON.stringify({ type: 'history', peer: pid }));
      }
      break;
    }
    case 'presence': {
      for (const u of m.users) {
        if (state.me && u.id !== state.me.id) state.users.set(u.id, Object.assign(state.users.get(u.id) || {}, u));
      }
      renderList();
      renderAdminMembers();
      if (state.activeChat && !state.users.has(state.activeChat)) {
        state.activeChat = null;
        $('#screen-chat').classList.add('hidden');
        $('#screen-list').classList.remove('hidden');
      }
      if (state.activeChat) updatePeerHeader();
      break;
    }
    case 'msg': {
      hydrateMsg(m.msg).then((mm) => { onIncomingMsg(mm); cacheMsg(mm); });
      break;
    }
    case 'msg-sent': {
      const peer = state.me && m.msg.to === state.me.id ? m.msg.from : m.msg.to;
      const arr = ensureMsgs(peer);
      const idx = m.clientId ? arr.findIndex(x => x.clientId === m.clientId) : arr.findIndex(x => x.id === m.msg.id);
      if (idx >= 0) {
        arr[idx] = Object.assign({}, arr[idx], { id: m.msg.id, ts: m.msg.ts, d: m.msg.d, r: m.msg.r });
        cacheMsg(arr[idx]);
      } else if (!arr.some(x => x.id === m.msg.id)) {
        hydrateMsg(m.msg).then((mm) => { ensureMsgs(peer).push(mm); if (state.activeChat === peer) renderChat(); });
      }
      const src = idx >= 0 ? arr[idx] : m.msg;
      const lt = src.deleted ? 'Mesazhi u fshi' : (src._fail ? '🔒 Mesazh' : (src.voc && !src.text) ? '🎤 Zanore' : (src.img && !src.text) ? '📷 Foto' : (src.text || '🔒 Mesazh'));
      state.last.set(peer, { text: lt, ts: m.msg.ts, from: m.msg.from });
      if (state.activeChat === peer) renderChat();
      renderList();
      break;
    }
    case 'msg-status': {
      const arr = state.msgs.get(m.peer);
      if (arr) {
        for (const id of m.ids) {
          const x = arr.find(y => y.id === id);
          if (x) { if (m.status === 'delivered') x.d = x.d || Date.now(); if (m.status === 'read') x.r = Date.now(); }
        }
      }
      if (state.activeChat === m.peer) renderChat();
      break;
    }
    case 'typing': {
      if (m.on) state.typing.set(m.from, Date.now() + 4000);
      else state.typing.delete(m.from);
      if (state.activeChat === m.from) updatePeerHeader();
      renderList();
      break;
    }
    case 'history': {
      (async () => {
        for (const x of m.messages) await hydrateMsg(x);
        mergeInto(m.peer, m.messages);
        for (const x of m.messages) cacheMsg(x);
        if (state.activeChat === m.peer) { renderChat(); markRead(m.peer); }
      })();
      break;
    }
    case 'msg-deleted': {
      for (const arr of state.msgs.values()) {
        const x = arr.find(y => y.id === m.id);
        if (x) { x.deleted = true; delete x.text; delete x.img; delete x.voc; delete x.enc; cacheMsg(x); }
      }
      renderChat();
      break;
    }
    case 'call-offer': onCallOffer(m); break;
    case 'call-answer': onCallAnswer(m); break;
    case 'ice': onRemoteIce(m); break;
    case 'call-decline': endCallUi('Thirrja u refuzua'); break;
    case 'call-busy': endCallUi('Është i zënë tani'); break;
    case 'call-hangup': endCallUi('Thirrja përfundoi'); break;
    case 'call-unreachable': endCallUi('S\'gjendet online — do t\'i vijë njoftim'); break;
  }
}

/* ================== LISTA ================== */
function ensureMsgs(peer) {
  if (!state.msgs.has(peer)) state.msgs.set(peer, []);
  return state.msgs.get(peer);
}
function renderMe() {
  if (!state.me) return;
  const a = $('#me-avatar');
  a.textContent = state.me.name.charAt(0).toUpperCase();
  a.style.background = state.me.color;
  $('#me-name').textContent = state.me.name;
  $('#set-name').textContent = state.me.name;
  if (state.inviteCode) $('#set-code').textContent = state.inviteCode;
}
/* shenja e kuqe me numrin e paleksuarish ne ikonë (ku mbështetet) */
function updateBadge() {
  try {
    if (!('setAppBadge' in navigator)) return;
    let total = 0;
    for (const n of state.unread.values()) total += n;
    if (total > 0) navigator.setAppBadge(total).catch(() => {});
    else navigator.clearAppBadge().catch(() => {});
  } catch (e) {}
}

function renderList() {
  const ul = $('#member-list');
  ul.textContent = '';
  const users = [...state.users.values()];
  $('#list-meta').textContent = 'Anëtarë: ' + (users.length + 1);
  $('#list-empty').classList.toggle('hidden', users.length > 0);
  users.sort((a, b) => {
    const la = state.last.get(a.id), lb = state.last.get(b.id);
    return (lb ? lb.ts : 0) - (la ? la.ts : 0);
  });
  for (const u of users) {
    const li = el('li');
    const av = el('div', 'avatar', u.name.charAt(0).toUpperCase());
    av.style.background = u.color;
    av.appendChild(el('span', 'dot' + (u.online ? ' on' : '')));
    const main = el('div', 'member-main');
    main.appendChild(el('div', 'member-name', u.name));
    const last = state.last.get(u.id);
    const prev = state.typing.has(u.id)
      ? 'po shkruan…'
      : (last ? ((last.from === (state.me && state.me.id) ? 'Ti: ' : '') + last.text) : 'S\'ka mesazhe');
    main.appendChild(el('div', 'member-preview', prev));
    const side = el('div', 'member-side');
    side.appendChild(el('div', 'member-time', last ? fmtTime(last.ts) : ''));
    const n = state.unread.get(u.id) || 0;
    if (n > 0) side.appendChild(el('span', 'badge', String(n)));
    li.appendChild(av); li.appendChild(main); li.appendChild(side);
    on(li, 'click', () => openChat(u.id));
    ul.appendChild(li);
  }
  updateBadge();
}

/* ================== BISEDA ================== */
function openChat(peerId) {
  const u = state.users.get(peerId);
  if (!u) return;
  state.activeChat = peerId;
  $('#screen-chat').classList.remove('hidden');
  $('#screen-list').classList.toggle('hidden', window.innerWidth < 900);
  $('#peer-name').textContent = u.name;
  const av = $('#peer-avatar');
  av.textContent = u.name.charAt(0).toUpperCase();
  av.style.background = u.color;
  updatePeerHeader();
  renderChat();
  // historia lokale (në telefon) bashkohet me atë të serverit
  loadCached(peerId).then((list) => {
    if (list.length && state.activeChat === peerId) { mergeInto(peerId, list); renderChat(); }
  });
  if (state.wsOk) state.ws.send(JSON.stringify({ type: 'history', peer: peerId }));
  markRead(peerId);
  $('#input').focus({ preventScroll: true });
}
function updatePeerHeader() {
  const u = state.users.get(state.activeChat);
  if (!u) return;
  let status = u.online ? 'online' : fmtLastSeen(u.lastSeen);
  if (state.typing.has(state.activeChat)) status = 'po shkruan…';
  $('#peer-status').textContent = status;
}
function markRead(peerId) {
  const arr = state.msgs.get(peerId);
  let changed = false;
  if (arr) for (const x of arr) if (x.to === (state.me && state.me.id) && !x.r) { x.r = Date.now(); changed = true; }
  if (state.unread.has(peerId)) { state.unread.delete(peerId); renderList(); }
  if (state.wsOk && state.ws) state.ws.send(JSON.stringify({ type: 'read', from: peerId }));
  if (changed) renderChat();
}
function renderChat() {
  const box = $('#messages');
  box.textContent = '';
  const arr = state.msgs.get(state.activeChat) || [];
  let lastDay = '';
  for (const m of arr) {
    const day = fmtDay(m.ts);
    if (day !== lastDay) {
      const chip = el('div', 'day-chip');
      chip.appendChild(el('span', null, day));
      box.appendChild(chip);
      lastDay = day;
    }
    box.appendChild(renderMsg(m));
  }
  box.scrollTop = box.scrollHeight;
}
function renderMsg(m) {
  const mine = m.from === (state.me && state.me.id);
  const row = el('div', 'msg-row ' + (mine ? 'out' : 'in'));
  const b = el('div', 'msg');
  if (m.deleted) {
    b.appendChild(el('div', 'deleted-msg', '🚫 Mesazhi u fshi'));
  } else if (m._fail) {
    b.appendChild(el('div', 'fail-msg', '🔒 Mesazh i fshehtëzuar (s\'lexohet në këtë pajisje)'));
  } else {
    if (m.voc) {
      const au = el('audio');
      au.controls = true;
      au.preload = 'metadata';
      au.src = m.voc;
      b.appendChild(au);
    }
    if (m.img) {
      const im = el('img', 'msg-img');
      im.src = m.img;
      im.alt = 'Foto';
      on(im, 'click', (ev) => {
        ev.stopPropagation();
        $('#lightbox-img').src = m.img;
        $('#lightbox').classList.remove('hidden');
      });
      b.appendChild(im);
    }
    if (m.text) b.appendChild(document.createTextNode(m.text));
  }
  const meta = el('div', 'meta');
  meta.appendChild(el('span', null, fmtTime(m.ts)));
  if (mine) {
    const ticks = el('span', 'ticks', m.r ? '✓✓' : (m.d ? '✓✓' : '✓'));
    if (m.clientId && !m.id) ticks.classList.add('pending');
    if (m.r) ticks.classList.add('dd');
    meta.appendChild(ticks);
    if (m.id && !m.deleted) {
      const del = el('span', 'del-btn');
      del.textContent = '🗑';
      del.title = 'Fshije';
      on(del, 'click', (ev) => {
        ev.stopPropagation();
        if (!confirm('Fshije mesazhin për të gjithë?')) return;
        if (state.wsOk && state.ws) state.ws.send(JSON.stringify({ type: 'msg-delete', id: m.id }));
        m.deleted = true;
        delete m.text; delete m.img; delete m.voc; delete m.enc;
        cacheMsg(m);
        renderChat();
      });
      meta.appendChild(del);
    }
  }
  b.appendChild(meta);
  row.appendChild(b);
  return row;
}
function onIncomingMsg(m) {
  const peerId = m.from;
  mergeInto(peerId, [m]);
  const prev = m.deleted ? 'Mesazhi u fshi' : (m._fail ? '🔒 Mesazh' : (m.voc && !m.text) ? '🎤 Zanore' : (m.img && !m.text) ? '📷 Foto' : m.text);
  state.last.set(peerId, { text: prev, ts: m.ts, from: m.from });
  const u = state.users.get(peerId);
  if (state.activeChat === peerId && !document.hidden) {
    renderChat();
    markRead(peerId);
  } else {
    state.unread.set(peerId, (state.unread.get(peerId) || 0) + 1);
    msgSound();
    if (u) notify(u, prev);
  }
  renderList();
}

/* ---------- dërgimi ---------- */
let typingSent = 0, typingTimer = null;
function sendMsg() {
  const input = $('#input');
  const text = input.value.trim();
  if (!text || !state.wsOk || !state.activeChat) return;
  const clientId = 'c' + Date.now() + Math.random().toString(36).slice(2, 7);
  const optimistic = { clientId, id: null, from: state.me.id, to: state.activeChat, text, ts: Date.now() };
  ensureMsgs(state.activeChat).push(optimistic);
  state.last.set(state.activeChat, { text, ts: optimistic.ts, from: state.me.id });
  renderChat();
  renderList();
  input.value = '';
  (async () => {
    const enc = await E2EE.seal(state.activeChat, { t: text });
    if (enc) state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, enc, clientId }));
    else state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, text, clientId }));
  })();
  sendTyping(false);
}
on($('#btn-send'), 'click', sendMsg);
on($('#input'), 'keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); sendMsg(); } });
on($('#input'), 'input', () => {
  if (!state.activeChat || !state.wsOk) return;
  const now = Date.now();
  if (now - typingSent > 2000) {
    typingSent = now;
    state.ws.send(JSON.stringify({ type: 'typing', to: state.activeChat, on: true }));
  }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => sendTyping(false), 2500);
});
function sendTyping(onOff) {
  if (state.wsOk && state.activeChat) {
    state.ws.send(JSON.stringify({ type: 'typing', to: state.activeChat, on: onOff }));
    typingSent = 0;
  }
}
on($('#btn-emoji'), 'click', () => { $('#input').value += '🙂'; $('#input').focus(); });
on($('#btn-back'), 'click', () => {
  state.activeChat = null;
  if (window.innerWidth < 900) $('#screen-chat').classList.add('hidden');
  $('#screen-list').classList.remove('hidden');
});

/* ---------- fotot ---------- */
on($('#lightbox'), 'click', () => $('#lightbox').classList.add('hidden'));
on($('#btn-photo'), 'click', () => $('#photo-input').click());
on($('#photo-input'), 'change', (e) => {
  const f = e.target.files && e.target.files[0];
  e.target.value = '';
  if (!f) return;
  if (!String(f.type).startsWith('image/')) { toast('Zgjidh një foto.'); return; }
  compressImage(f).then(async (dataUrl) => {
    if (!dataUrl) { toast('Foto s\'u përpunua.'); return; }
    if (!state.wsOk || !state.activeChat) { toast('S\'ka lidhje me serverin.'); return; }
    const clientId = 'c' + Date.now() + Math.random().toString(36).slice(2, 7);
    const optimistic = { clientId, id: null, from: state.me.id, to: state.activeChat, text: '', img: dataUrl, ts: Date.now() };
    ensureMsgs(state.activeChat).push(optimistic);
    renderChat();
    state.last.set(state.activeChat, { text: '📷 Foto', ts: optimistic.ts, from: state.me.id });
    renderList();
    const encP = await E2EE.seal(state.activeChat, { t: '', i: dataUrl });
    if (encP) state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, enc: encP, clientId }));
    else state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, text: '', img: dataUrl, clientId }));
  });
});
function compressImage(file) {
  return new Promise((resolve) => {
    try {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const MAX = 1280;
        let w = img.naturalWidth || MAX, h = img.naturalHeight || MAX;
        if (w > MAX || h > MAX) {
          const k = Math.min(MAX / w, MAX / h);
          w = Math.round(w * k); h = Math.round(h * k);
        }
        const c = document.createElement('canvas');
        c.width = w; c.height = h;
        c.getContext('2d').drawImage(img, 0, 0, w, h);
        resolve(c.toDataURL('image/jpeg', 0.75));
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(null); };
      img.src = url;
    } catch (e) { resolve(null); }
  });
}

/* ================== MESAZHET ZANORE ================== */
let rec = null, recOK = false, recStart = 0, recTimer = null;
on($('#btn-mic'), 'click', () => {
  if (rec) return;
  if (!state.wsOk || !state.activeChat) { toast('S' + String.fromCharCode(39) + 'ka lidhje.'); return; }
  navigator.mediaDevices.getUserMedia({ audio: true }).then((stream) => {
    const mime = ['audio/webm;codecs=opus', 'audio/webm', 'audio/mp4'].find(t => window.MediaRecorder && MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(t));
    try { rec = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined); }
    catch (e) { rec = new MediaRecorder(stream); }
    const chunks = [];
    recOK = true;
    recStart = Date.now();
    rec.ondataavailable = (e) => { if (e.data && e.data.size) chunks.push(e.data); };
    rec.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      const dur = Math.round((Date.now() - recStart) / 1000);
      const blob = new Blob(chunks, { type: rec.mimeType || 'audio/webm' });
      const ok = recOK;
      rec = null;
      clearInterval(recTimer);
      $('#rec-bar').classList.add('hidden');
      $('.composer').style.display = '';
      if (!ok || dur < 1 || blob.size < 800) return;
      const fr = new FileReader();
      fr.onload = async () => {
        const dataUrl = fr.result;
        const clientId = 'c' + Date.now() + Math.random().toString(36).slice(2, 7);
        ensureMsgs(state.activeChat).push({ clientId, id: null, from: state.me.id, to: state.activeChat, text: '', voc: dataUrl, dur, ts: Date.now() });
        renderChat();
        state.last.set(state.activeChat, { text: '🎤 Zanore', ts: Date.now(), from: state.me.id });
        renderList();
        const enc = await E2EE.seal(state.activeChat, { t: '', v: dataUrl, d: dur });
        if (enc) state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, enc, clientId }));
        else state.ws.send(JSON.stringify({ type: 'msg', to: state.activeChat, text: '', voc: dataUrl, clientId }));
      };
      fr.readAsDataURL(blob);
    };
    rec.start();
    $('#rec-bar').classList.remove('hidden');
    $('.composer').style.display = 'none';
    const t0 = Date.now();
    const upd = () => {
      const s = Math.floor((Date.now() - t0) / 1000);
      $('#rec-time').textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
      if (s >= 120 && rec && rec.state === 'recording') { recOK = true; rec.stop(); } // maksimumi 2 min
    };
    upd();
    recTimer = setInterval(upd, 500);
  }).catch(() => toast('Mikrofoni nuk u lejua.'));
});
on($('#btn-rec-cancel'), 'click', () => { recOK = false; if (rec) rec.stop(); });
on($('#btn-rec-send'), 'click', () => { recOK = true; if (rec) rec.stop(); });

/* ================== THIRRJET (WebRTC) ================== */
function callBtnBusy() { return !!(state.call || state.pendingOffer); }
/* iOS: videoja duhet "çkyçur" gjatë prekjes — pastaj luan edhe pa prekje */
function attemptPlay(n) {
  const v = $('#remote-video');
  let p = null;
  try { p = v.play(); } catch (e) { dlog('play: perjashtim ' + (e && e.name)); }
  if (p && p.then) {
    p.then(() => {
      dlog('Po luan PROVA-OK ' + n);
      $('#btn-unmute').classList.add('hidden');
    }).catch((err) => {
      dlog('play u bllokua: ' + (err && err.name) + ' (prova ' + n + ')');
      if (n < 8) setTimeout(() => attemptPlay(n + 1), 1200);
      else $('#btn-unmute').classList.remove('hidden');
    });
  }
}
function unlockVideo() {
  try {
    const v = $('#remote-video');
    v.muted = false;
    const p = v.play();
    if (p && p.catch) p.catch(() => {});
  } catch (e) {}
}

on($('#btn-call'), 'click', () => {
  unlockVideo();
  if (!state.activeChat) return;
  if (callBtnBusy()) { toast('Je tashmë në thirrje.'); return; }
  startCall(state.activeChat, 'video');
});
on($('#btn-voice'), 'click', () => {
  unlockVideo();
  if (!state.activeChat) return;
  if (callBtnBusy()) { toast('Je tashmë në thirrje.'); return; }
  startCall(state.activeChat, 'audio');
});

/* pritje e mençur: dërgo SAPASI del kandidati i parë i URËS (relay),
   ose kur mbaron mbledhja — max 3s. Zero vonesë kur ura punon. */
function gatherComplete(pc, timeoutMs) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve();
    let done = false;
    const fin = () => {
      if (done) return;
      done = true;
      clearTimeout(t);
      pc.removeEventListener('icecandidate', onCand);
      pc.removeEventListener('icegatheringstatechange', onChange);
      resolve();
    };
    const onCand = (e) => {
      if (e.candidate && String(e.candidate.candidate || '').indexOf('typ relay') !== -1) fin();
    };
    const onChange = () => { if (pc.iceGatheringState === 'complete') fin(); };
    const t = setTimeout(fin, timeoutMs);
    pc.addEventListener('icecandidate', onCand);
    pc.addEventListener('icegatheringstatechange', onChange);
  });
}

async function getMediaFor(media) {
  if (media === 'audio') return navigator.mediaDevices.getUserMedia({ audio: true });
  return navigator.mediaDevices.getUserMedia({
    audio: true,
    video: { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } }
  });
}
function newPc(callId, peerId) {
  const pc = new RTCPeerConnection({ iceServers: state.config.iceServers || [] });
  pc.onicecandidate = (e) => {
    if (e.candidate) {
      iceSent++;
      const c = e.candidate.candidate || '';
      if (c.indexOf('typ relay') !== -1) state.iceTypes.relay++;
      else if (c.indexOf('typ srflx') !== -1) state.iceTypes.srflx++;
      else state.iceTypes.host++;
    }
    if (e.candidate && state.wsOk) {
      state.ws.send(JSON.stringify({ type: 'ice', to: peerId, callId, candidate: e.candidate.toJSON() }));
    }
  };
  pc.ontrack = (e) => {
    dlog('Media e ardhur (pista: ' + e.track.kind + ')');
    state.remoteStream = e.streams[0]; // ruaje — ekrani i thirrjes s'e fshin dot më
    const v = $('#remote-video');
    if (v.srcObject !== e.streams[0]) v.srcObject = e.streams[0];
    attemptPlay(1);
  };
  pc.onconnectionstatechange = () => {
    if (!state.call) return;
    if (pc.connectionState === 'connected') {
      dlog('LIDHUR ✓ (ICE: dërguar ' + iceSent + ', marrë ' + iceGot + ')');
      clearTimeout(state.call.timer); // lidhja u krye — hiq pritësin, thirrja QËNDRON
      setCallStatus('Lidhur');
      attemptPlay(1);
    }
    if (pc.connectionState === 'failed') { dlog('LIDHJA DËSHTOI'); hangup('failed'); }
  };
  return pc;
}
async function startCall(peerId, media) {
  const u = state.users.get(peerId);
  media = media === 'audio' ? 'audio' : 'video';
  try {
    try { await loadConfig(); } catch (e) {}
    const local = await getMediaFor(media);
    resetIceCounters();
    dlog('Kamera/mikro morën leje (' + media + ')');
    const callId = 'k' + Date.now() + Math.random().toString(36).slice(2, 7);
    const pc = newPc(callId, peerId);
    local.getTracks().forEach(t => pc.addTrack(t, local));
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await gatherComplete(pc, 3000); // dërgo sapas del ura (ose max 3s)
    dlog('Oferta gati: ' + state.iceTypes.host + ' host, ' + state.iceTypes.srflx + ' srflx, ' + state.iceTypes.relay + ' RELAY');
    state.call = { callId, peerId, pc, local, role: 'caller', status: 'calling', media };
    showCallOverlay('Po thirret…' + (u ? ' ' + u.name : ''), local, media);
    state.ws.send(JSON.stringify({ type: 'call-offer', to: peerId, callId, sdp: offer.sdp, media }));
    state.call.timer = setTimeout(() => hangup('no-answer'), 45000);
  } catch (e) {
    toast('Mikrofoni/kamera s\'u aksesua: ' + (e.message || 'lejo qasjen në shfletues'));
  }
}
function onCallOffer(m) {
  if (state.call || state.pendingOffer) {
    if (state.wsOk) state.ws.send(JSON.stringify({ type: 'call-busy', to: m.from, callId: m.callId }));
    return;
  }
  if (state.autoDecline) {
    state.autoDecline = false;
    if (state.wsOk) state.ws.send(JSON.stringify({ type: 'call-decline', to: m.from, callId: m.callId }));
    return;
  }
  const u = state.users.get(m.from);
  m.media = m.media === 'audio' ? 'audio' : 'video';
  state.pendingOffer = m;
  state.iceQueue = [];
  $('#incoming-name').textContent = m.media === 'audio' ? 'Thirrje zanore' : 'Thirrje video';
  $('#incoming-sub').textContent = u ? u.name : 'Anonim';
  const av = $('#incoming-avatar');
  av.textContent = u ? u.name.charAt(0).toUpperCase() : '?';
  av.style.background = u ? u.color : '#999';
  $('#modal-incoming').classList.remove('hidden');
  startRing();
  if (state.autoAccept) {
    state.autoAccept = false;
    setTimeout(doAccept, 800); // nje prekje = thirrja lidhet vete
  }
}
on($('#btn-accept'), 'click', doAccept);
async function doAccept() {
  unlockVideo();
  const m = state.pendingOffer;
  if (!m) return;
  stopRing();
  $('#modal-incoming').classList.add('hidden');
  const media = m.media === 'audio' ? 'audio' : 'video';
  try {
    try { await loadConfig(); } catch (e) {}
    const local = await getMediaFor(media);
    const pc = newPc(m.callId, m.from);
    local.getTracks().forEach(t => pc.addTrack(t, local));
    await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
    dlog('Oferta u pranua, po përgjigjem…');
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await gatherComplete(pc, 3000);
    dlog('Përgjigja gati: ' + state.iceTypes.host + ' host, ' + state.iceTypes.srflx + ' srflx, ' + state.iceTypes.relay + ' RELAY');
    state.call = { callId: m.callId, peerId: m.from, pc, local, role: 'callee', status: 'connecting', media };
    state.pendingOffer = null;
    showCallOverlay('Duke u lidhur…', local, media);
    flushIce();
    state.ws.send(JSON.stringify({ type: 'call-answer', to: m.from, callId: m.callId, sdp: answer.sdp }));
    state.call.timer = setTimeout(() => hangup('timeout'), 45000);
  } catch (e) {
    toast('Kamera s\'u aksesua: ' + (e.message || ''));
    try { state.ws.send(JSON.stringify({ type: 'call-decline', to: m.from, callId: m.callId })); } catch (x) {}
    cleanupCall();
    hideIncoming();
  }
}
on($('#btn-decline'), 'click', () => {
  const m = state.pendingOffer;
  stopRing();
  hideIncoming();
  if (m && state.wsOk) state.ws.send(JSON.stringify({ type: 'call-decline', to: m.from, callId: m.callId }));
  state.pendingOffer = null;
  state.iceQueue = [];
});
function hideIncoming() { $('#modal-incoming').classList.add('hidden'); }

async function onCallAnswer(m) {
  const c = state.call;
  if (!c || c.callId !== m.callId) return;
  clearTimeout(c.timer);
  try {
    await c.pc.setRemoteDescription({ type: 'answer', sdp: m.sdp });
    dlog('Përgjigja u mor, ICE: ' + iceGot + ' marrë');
    flushIce();
    setCallStatus('Lidhur');
  } catch (e) { hangup('error'); }
}
function onRemoteIce(m) {
  if (m && m.candidate) iceGot++;
  if (state.call && state.call.callId === m.callId) {
    if (state.call.pc.remoteDescription) {
      state.call.pc.addIceCandidate(m.candidate).catch(() => {});
    } else {
      state.iceQueue.push(m.candidate); // mbaji deri sa remoteDescription të vendoset
    }
  } else if (state.pendingOffer && state.pendingOffer.callId === m.callId) {
    state.iceQueue.push(m.candidate); // GJATË ZILES: ruaji — hidheshin poshtë! (bug i thirrjes një-drejtimore)
  }
}
function flushIce() {
  if (!state.call) return;
  for (const c of state.iceQueue) {
    state.call.pc.addIceCandidate(c).catch(() => {});
  }
  state.iceQueue = [];
}
function showCallOverlay(status, localStream, media) {
  const audio = media === 'audio';
  $('#call-overlay').classList.remove('hidden');
  setCallStatus(status);
  $('#local-video').srcObject = localStream;
  $('#remote-video').srcObject = state.remoteStream || null; // kurrë mos fshih video-në e ardhur!
  $('#local-video').style.display = audio ? 'none' : '';
  $('#remote-video').classList.toggle('audio-only', audio);
  $('#btn-cam').style.display = audio ? 'none' : '';
  $('#call-audio').classList.toggle('hidden', !audio);
  if (audio && state.call) {
    const u = state.users.get(state.call.peerId);
    const av = $('#audio-avatar');
    av.textContent = u ? u.name.charAt(0).toUpperCase() : '?';
    av.style.background = u ? u.color : '#999';
    $('#audio-name').textContent = u ? u.name : '…';
  }
  updateCallButtons();
}
function setCallStatus(s) {
  if (state.call) state.call.status = s;
  $('#call-status').textContent = s;
}
let muted = false, camOff = false;
function updateCallButtons() {
  $('#btn-mute').classList.toggle('off', muted);
  $('#btn-cam').classList.toggle('off', camOff);
}
on($('#btn-mute'), 'click', () => {
  if (!state.call) return;
  muted = !muted;
  state.call.local.getAudioTracks().forEach(t => t.enabled = !muted);
  updateCallButtons();
});
on($('#btn-cam'), 'click', () => {
  if (!state.call) return;
  camOff = !camOff;
  state.call.local.getVideoTracks().forEach(t => t.enabled = !camOff);
  updateCallButtons();
});
on($('#btn-end'), 'click', () => hangup('local'));
on($('#btn-unmute'), 'click', () => {
  unlockVideo();
  attemptPlay(9);
});
function hangup(reason) {
  const c = state.call;
  if (!c) { endCallUi(null); return; }
  if (state.wsOk) {
    try { state.ws.send(JSON.stringify({ type: 'call-hangup', to: c.peerId, callId: c.callId })); } catch (e) {}
  }
  cleanupCall();
  const msgs = {
    'no-answer': 'S\'përgjigjet',
    'failed': 'Lidhja dështoi (rrjeti)',
    'local': 'Thirrja përfundoi',
    'timeout': 'Lidhja vonoi'
  };
  endCallUi(msgs[reason] || 'Thirrja përfundoi');
}
function cleanupCall() {
  const c = state.call;
  if (c) {
    clearTimeout(c.timer);
    try { c.pc.close(); } catch (e) {}
    try { c.local.getTracks().forEach(t => t.stop()); } catch (e) {}
  }
  state.call = null;
  state.pendingOffer = null;
  state.remoteStream = null;
  state.iceQueue = [];
  muted = false; camOff = false;
  stopRing();
}
function endCallUi(text) {
  cleanupCall();
  hideIncoming();
  if (text) {
    $('#call-overlay').classList.remove('hidden');
    setCallStatus(text);
    setTimeout(() => $('#call-overlay').classList.add('hidden'), 1600);
  } else {
    $('#call-overlay').classList.add('hidden');
  }
  $('#local-video').srcObject = null;
  $('#remote-video').srcObject = null;
  $('#local-video').style.display = '';
  $('#btn-cam').style.display = '';
  $('#remote-video').classList.remove('audio-only');
  $('#call-audio').classList.add('hidden');
  $('#btn-unmute').classList.add('hidden');
}

/* ================== CILËSIME ================== */
on($('#btn-settings'), 'click', () => {
  $('#modal-settings').classList.remove('hidden');
  renderAdminMembers();
});
/* vetëm admini: lista e anëtarëve me butonin Fshi */
function renderAdminMembers() {
  const block = $('#admin-block');
  if (!block) return;
  if (!state.me || !state.me.isAdmin) { block.style.display = 'none'; return; }
  block.style.display = '';
  const box = $('#admin-members');
  box.textContent = '';
  for (const u of state.users.values()) {
    const row = el('div', 'settings-row');
    row.appendChild(el('span', null, u.name));
    const del = el('button', 'btn btn-danger');
    del.textContent = 'Fshi';
    del.style.padding = '6px 12px';
    del.style.fontSize = '13px';
    on(del, 'click', () => {
      if (confirm('Të fshihet ' + u.name + '? Fshihet edhe biseda me te.')) {
        if (state.wsOk && state.ws) state.ws.send(JSON.stringify({ type: 'remove-member', userId: u.id }));
        renderAdminMembers();
      }
    });
    row.appendChild(del);
    box.appendChild(row);
  }
  if (!state.users.size) box.appendChild(el('p', 'muted small', 'S ka anëtarë tjerë.'));
}
on($('#btn-close-settings'), 'click', () => $('#modal-settings').classList.add('hidden'));
$('#modal-settings').addEventListener('click', (e) => {
  if (e.target === $('#modal-settings')) $('#modal-settings').classList.add('hidden');
});
on($('#btn-logout'), 'click', logout);
on($('#set-sound'), 'change', (e) => {
  settings.sound = e.target.checked;
  storage.set('fc-settings', JSON.stringify(settings));
});
$('#set-sound').checked = settings.sound;
if (storage.get('fc-dark') === '1') document.body.classList.add('dark');
$('#set-dark').checked = storage.get('fc-dark') === '1';
on($('#set-dark'), 'change', (e) => {
  document.body.classList.toggle('dark', e.target.checked);
  storage.set('fc-dark', e.target.checked ? '1' : '0');
});

on($('#set-code'), 'click', async () => {
  const code = $('#set-code').textContent;
  try { await navigator.clipboard.writeText(code); toast('Kodi u kopjua: ' + code); }
  catch (e) { toast('Kodi i ftesës: ' + code); }
});

async function enableNotifications() {
  if (typeof Notification === 'undefined') { $('#notif-status').textContent = 'Shfletuesi s\'i mbështet njoftimet.'; return; }
  let perm = Notification.permission;
  if (perm === 'default') {
    try { perm = await Notification.requestPermission(); } catch (e) {}
  }
  if (perm !== 'granted') { $('#notif-status').textContent = 'Leja s\'u dha.'; return; }
  $('#notif-status').textContent = 'Njoftimet në-aplikacion: ON.';
  try {
    if (!state.config.vapidPublicKey) { $('#notif-status').textContent += ' (Push do të aktivizohet pas vendosjes në server.)'; return; }
    const reg = await navigator.serviceWorker.ready;
    const key = urlB64ToUint8(state.config.vapidPublicKey);
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
    await fetch('/api/push-sub', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: state.token, subscription: sub.toJSON() })
    });
    $('#notif-status').textContent = 'Njoftimet push: AKTIVE ✓';
  } catch (e) {
    $('#notif-status').textContent += ' (Push s\'u aktivizua në këtë mjedis.)';
  }
}
on($('#btn-notif'), 'click', enableNotifications);
on($('#btn-diag'), 'click', async () => {
  const txt = diag.length ? diag.join('\n') : '( ende pa thirrje te regjistruara )';
  try { await navigator.clipboard.writeText(txt); $('#diag-status').textContent = 'U kopjua — dërgoje në bisedën tonë 💬'; }
  catch (e) { $('#diag-status').textContent = txt.slice(0, 200); }
});
function urlB64ToUint8(b64) {
  const pad = '='.repeat((4 - b64.length % 4) % 4);
  const base64 = (b64 + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

/* në sfond: mbyll lidhjen pas 15s që njoftimet push të vijnë GJITHMONË;
   në hapje: rilidhu menjëherë */
let hideTimer = null;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hideTimer = setTimeout(() => {
      if (document.hidden && state.ws && state.ws.readyState === 1) {
        state.backgroundPaused = true;
        try { state.ws.close(); } catch (e) {}
      }
    }, 8000);
  } else {
    clearTimeout(hideTimer);
    state.backgroundPaused = false;
    if (!state.wsOk) wsConnect();
    if (state.activeChat) markRead(state.activeChat);
    updateBadge();
  }
});
window.addEventListener('resize', () => {
  if (window.innerWidth >= 900) $('#screen-list').classList.remove('hidden');
});

/* ================== NISJA ================== */
try {
  const qp = new URLSearchParams(location.search);
  if (qp.get('call') === 'accept') state.autoAccept = true;
  if (qp.get('call') === 'decline') state.autoDecline = true;
  if (qp.has('call')) history.replaceState({}, '', location.pathname);
} catch (e) {}
try {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (ev) => {
      const d = ev && ev.data;
      if (!d || d.cmd !== 'call-action') return;
      if (d.action === 'accept') state.autoAccept = true;
      if (d.action === 'decline') {
        state.autoDecline = true;
        if (state.pendingOffer) {
          const m0 = state.pendingOffer;
          state.pendingOffer = null;
          stopRing();
          hideIncoming();
          if (state.wsOk) state.ws.send(JSON.stringify({ type: 'call-decline', to: m0.from, callId: m0.callId }));
        }
      }
    });
  }
} catch (e) {}
if (state.token) {
  enterApp();
} else {
  $('#screen-auth').classList.remove('hidden');
}
})();