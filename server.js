#!/usr/bin/env node
'use strict';
/*
 * ============================================================
 *  FAMILJA CHAT — server
 *  - Pa varësi të detyrueshme: mjafton Node.js për ta nisur.
 *  - Opsional: npm install web-push  +  çelësat VAPID
 *    -> aktivizon njoftimet push kur aplikacioni është i mbyllur.
 * ============================================================
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WSConn, acceptKey } = require('./ws-lib');

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = __dirname;
const STATIC_OK = new Set(['index.html','app.js','styles.css','sw.js','manifest.webmanifest','icon-192.png','icon-512.png']);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const MAX_MESSAGE_LEN = 4000;
const MAX_MESSAGES = 30000; // kufiri i historikut (prunohet automatikisht)
const TOKEN_DAYS = 90;
const PALETTE = ['#e53935','#d81b60','#8e24aa','#5e35b1','#3949ab','#1e88e5','#039be5','#00acc1','#00897b','#43a047','#7cb342','#fb8c00','#f4511e','#6d4c41','#546e7a','#ad1457'];
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/* ---------------------------------------------------------- depo (JSON + Postgres opsional)
   Me variablën DATABASE_URL (p.sh. Neon falas) llogaritë & mesazhet
   ruhen në re PËRGJITHMONË — i mbijetojnë çdo rindezjeje të Render-it.
   Pa të, përdoret skedari lokal db.json (zhduket në rindezje të Render free). */
let db = {
  meta: { secret: null },
  family: { name: 'Familja Jonë', inviteCode: null, adminId: null },
  users: [],
  messages: [],
  subs: []
};

let pgPool = null;
async function initDb() {
  if (!process.env.DATABASE_URL) return;
  try {
    const pg = require('pg');
    const cs = process.env.DATABASE_URL;
    const local = /localhost|127\.0\.0\.1/.test(cs);
    pgPool = new pg.Pool({ connectionString: cs, max: 3, ssl: local ? undefined : { rejectUnauthorized: false } });
    await pgPool.query('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v JSONB)');
    const r = await pgPool.query("SELECT v FROM kv WHERE k = 'db'");
    if (r.rows.length && r.rows[0].v && Array.isArray(r.rows[0].v.users)) {
      db = Object.assign(db, r.rows[0].v);
      console.log('[depo] Postgres: u ngarkua — ' + db.users.length + ' anëtarë, ' + db.messages.length + ' mesazhe ✓');
    } else {
      console.log('[depo] Postgres: bosh — fillojmë të reja dhe ruhen atje.');
      markDirty();
    }
  } catch (e) {
    console.log('[depo] Postgres s\'u lidh (' + e.message + ') — vazhdoj me skedarin lokal.');
    pgPool = null;
  }
}

function loadDb() {
  try {
    const raw = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (raw && Array.isArray(raw.users)) db = Object.assign(db, raw);
  } catch (e) { /* fillimi i parë */ }
  if (!db.meta) db.meta = {};
  if (!db.meta.secret) { db.meta.secret = crypto.randomBytes(32).toString('hex'); markDirty(); }
  if (!db.family) db.family = { name: 'Familja Jonë', inviteCode: null, adminId: null };
}

let dirty = false, saveTimer = null;
function markDirty() {
  dirty = true;
  if (!saveTimer) saveTimer = setTimeout(saveNow, 3000);
}
function saveNow() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  if (!dirty) return;
  dirty = false;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) { console.error('[depo] ruajtja lokale dështoi:', e.message); }
  if (pgPool) {
    pgPool.query(
      "INSERT INTO kv (k, v) VALUES ('db', $1) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
      [JSON.stringify(db)]
    ).catch((e) => console.error('[depo] ruajtja në Postgres dështoi:', e.message));
  }
}
let exiting = false;
async function shutdown() {
  if (exiting) return;
  exiting = true;
  saveNow();
  if (pgPool) { try { await pgPool.end(); } catch (e) {} }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

/* ---------------------------------------------------------- ndihmës */
const uid = () => crypto.randomBytes(9).toString('base64url');
const b64u = (buf) => Buffer.from(String(buf)).toString('base64url');

function hashPassword(pw, salt) {
  return crypto.scryptSync(String(pw), salt, 64).toString('hex');
}
function signToken(userId) {
  const payload = b64u(JSON.stringify({ uid: userId, exp: Date.now() + TOKEN_DAYS * 864e5 }));
  const sig = crypto.createHmac('sha256', db.meta.secret).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(token) {
  if (typeof token !== 'string') return null;
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i), sig = token.slice(i + 1);
  const want = crypto.createHmac('sha256', db.meta.secret).update(payload).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const obj = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!obj || typeof obj.uid !== 'string' || Date.now() > obj.exp) return null;
    return obj.uid;
  } catch (e) { return null; }
}
function findUser(id) { return db.users.find(u => u.id === id) || null; }
function findUserByName(name) {
  const n = String(name || '').trim().toLowerCase();
  return db.users.find(u => u.nameLower === n) || null;
}
function publicUser(u, online) {
  return { id: u.id, name: u.name, color: u.color, isAdmin: !!u.isAdmin, lastSeen: u.lastSeen || 0, online: !!online };
}
function newInviteCode() {
  let s = '';
  for (let i = 0; i < 6; i++) s += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  return s;
}

/* ---------------------------------------------------------- push (opsional) */
let webpush = null, pushReady = false;
try {
  webpush = require('web-push');
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    webpush.setVapidDetails(
      'mailto:' + (process.env.VAPID_CONTACT || 'familja@shembull.com'),
      process.env.VAPID_PUBLIC_KEY,
      process.env.VAPID_PRIVATE_KEY
    );
    pushReady = true;
    console.log('[push] Njoftimet push janë AKTIVE.');
  } else {
    console.log('[push] Mungojnë VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY -> njoftimet push janë të ç\'aktivizuara (chat & thirrje punojnë normalisht).');
  }
} catch (e) {
  console.log('[push] Moduli "web-push" nuk është instaluar -> njoftimet push janë të ç\'aktivizuara (chat & thirrje punojnë normalisht).');
}

function pushNotify(userId, title, body, tag, urgency, badge) {
  if (!pushReady) return;
  const subs = db.subs.filter(s => s.userId === userId);
  for (const s of subs) {
    webpush.sendNotification(s, JSON.stringify({ title, body, tag, url: '/', badge: badge || 1 }), {
      urgency: urgency || 'normal',
      TTL: urgency === 'high' ? 30 : 3600
    }).catch(err => {
      if (err.statusCode === 404 || err.statusCode === 410) {
        db.subs = db.subs.filter(x => x.endpoint !== s.endpoint);
        markDirty();
      }
    });
  }
}

/* ---------------------------------------------------------- HTTP */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8',
  '.woff2': 'font/woff2', '.mp3': 'audio/mpeg'
};

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 200 * 1024) { reject(new Error('trup i madh')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { reject(new Error('JSON i pavlefshëm')); }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  if (p === '/api/health') return json(res, 200, { ok: true });

  if (p === '/api/config') {
    const iceServers = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
    // Cloudflare Calls TURN (1 TB/muaj falas) — kredenciale të përkohshme nënë çelësin CF_TURN_SECRET
    if (process.env.CF_TURN_SECRET) {
      const ttl = 86400; // vlefshme 24h
      const username = String(Math.floor(Date.now() / 1000) + ttl);
      const password = crypto.createHmac('sha1', process.env.CF_TURN_SECRET).update(username).digest('base64');
      iceServers.push({
        username,
        credential: password,
        urls: ['turn:turn.cloudflare.com:3478?transport=udp', 'turn:turn.cloudflare.com:3478?transport=tcp']
      });
    }
    if (process.env.TURN_URL) {
      // TURN privat (metered.ca) — i besueshëm
      const entry = { urls: process.env.TURN_URL.split(',').map(x => x.trim()).filter(Boolean) };
      if (process.env.TURN_USERNAME) entry.username = process.env.TURN_USERNAME;
      if (process.env.TURN_CREDENTIAL) entry.credential = process.env.TURN_CREDENTIAL;
      iceServers.push(entry);
    }
    // OpenRelay publik gjithmonë si rezervë
    iceServers.push({
      urls: [
        'turn:openrelay.metered.ca:80',
        'turn:openrelay.metered.ca:80?transport=tcp',
        'turn:openrelay.metered.ca:443',
        'turn:openrelay.metered.ca:443?transport=tcp'
      ],
      username: 'openrelayproject',
      credential: 'openrelayproject'
    });
    return json(res, 200, {
      name: 'Familja Chat',
      vapidPublicKey: pushReady ? process.env.VAPID_PUBLIC_KEY : null,
      iceServers
    });
  }

  if (p === '/api/register' && req.method === 'POST') {
    let b;
    try { b = await readBody(req); } catch (e) { return json(res, 400, { error: 'Kërkesë e pavlefshme' }); }
    const name = String(b.name || '').trim();
    const password = String(b.password || '');
    const code = String(b.inviteCode || '').trim().toUpperCase();
    if (name.length < 2 || name.length > 24) return json(res, 400, { error: 'Emri duhet 2–24 shkronja.' });
    if (password.length < 4) return json(res, 400, { error: 'Fjalëkalimi duhet të paktën 4 shenja.' });
    if (findUserByName(name)) return json(res, 409, { error: 'Ky emër ekziston tashmë.' });

    const isFirst = db.users.length === 0;
    if (!isFirst) {
      if (!db.family.inviteCode || code !== db.family.inviteCode) {
        return json(res, 403, { error: 'Kodi i ftesës është i gabuar.' });
      }
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const user = {
      id: uid(),
      name,
      nameLower: name.toLowerCase(),
      passHash: hashPassword(password, salt),
      salt,
      color: PALETTE[db.users.length % PALETTE.length],
      isAdmin: isFirst,
      createdAt: Date.now(),
      lastSeen: 0
    };
    db.users.push(user);
    if (isFirst) { db.family.adminId = user.id; db.family.inviteCode = newInviteCode(); }
    markDirty();
    return json(res, 200, { token: signToken(user.id), user: publicUser(user, true), inviteCode: db.family.inviteCode });
  }

  if (p === '/api/login' && req.method === 'POST') {
    let b;
    try { b = await readBody(req); } catch (e) { return json(res, 400, { error: 'Kërkesë e pavlefshme' }); }
    const user = findUserByName(b.name || '');
    if (!user) return json(res, 401, { error: 'Emër ose fjalëkalim i gabuar.' });
    const hash = hashPassword(String(b.password || ''), user.salt);
    const ok = Buffer.from(hash).length === Buffer.from(user.passHash).length &&
      crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.passHash));
    if (!ok) return json(res, 401, { error: 'Emër ose fjalëkalim i gabuar.' });
    user.lastSeen = Date.now();
    markDirty();
    return json(res, 200, { token: signToken(user.id), user: publicUser(user, true), inviteCode: db.family.inviteCode });
  }

  if (p === '/api/push-sub' && req.method === 'POST') {
    let b;
    try { b = await readBody(req); } catch (e) { return json(res, 400, { error: 'Kërkesë e pavlefshme' }); }
    const userId = verifyToken(b.token);
    if (!userId) return json(res, 401, { error: 'I paautorizuar' });
    const sub = b.subscription;
    if (!sub || typeof sub.endpoint !== 'string' || !sub.keys || !sub.keys.p256dh) {
      return json(res, 400, { error: 'Abonim i pavlefshëm' });
    }
    db.subs = db.subs.filter(s => s.endpoint !== sub.endpoint);
    db.subs.push({ userId, endpoint: sub.endpoint, keys: sub.keys });
    markDirty();
    return json(res, 200, { ok: true });
  }

  /* ------------------------------------------------- statike */
  let rel = decodeURIComponent(p);
  if (rel === '/') rel = '/index.html';
  if (!STATIC_OK.has(rel.slice(1))) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('S\'gjendet'); }
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Ndaluar'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('S\'gjendet: ' + rel); }
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': (ext === '.html' || ext === '.js' || ext === '.css' || ext === '.webmanifest') ? 'no-cache' : 'public, max-age=86400'
    });
    res.end(data);
  });
});

/* ---------------------------------------------------------- WebSocket */
/** userId -> Set<WSConn> */
const online = new Map();
/** thirrje pezulluar për marrës offline/të ngrirë: userId -> {from, callId, sdp, media, ts} */
const pendingCalls = new Map();
/** të gjitha lidhjet e autentikuara */
const allConns = new Set();

function sendTo(userId, obj) {
  const set = online.get(userId);
  if (!set || set.size === 0) return false;
  const s = JSON.stringify(obj);
  let sent = 0;
  for (const c of set) { if (!c.closed) { c.send(s); sent++; } }
  return sent > 0;
}
function broadcast(obj) {
  const s = JSON.stringify(obj);
  for (const c of allConns) if (!c.closed) c.send(s);
}
function isOnline(id) { const s = online.get(id); return !!s && s.size > 0; }
/* "online DHE i zgjuar" — pajisja e ngrirë në sfond s'përgjigjet dot (s'ka heartbeat) */
function isResponsive(id) {
  const set = online.get(id);
  if (!set || set.size === 0) return false;
  let last = 0;
  for (const c of set) last = Math.max(last, c.lastActivity || 0);
  return Date.now() - last < 40000;
}

function presenceSnapshot() {
  return db.users.map(u => publicUser(u, isOnline(u.id)));
}
function unreadFor(meId) {
  const out = {};
  for (const m of db.messages) {
    if (m.to === meId && !m.r) out[m.from] = (out[m.from] || 0) + 1;
  }
  return out;
}
function lastMessagesFor(meId) {
  const out = {};
  for (const m of db.messages) {
    if (m.from === meId || m.to === meId) {
      const peer = m.from === meId ? m.to : m.from;
      if (!out[peer] || m.ts >= out[peer].ts) out[peer] = { text: m.text, ts: m.ts, from: m.from };
    }
  }
  return out;
}

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== '/ws' || !req.headers['sec-websocket-key']) { socket.destroy(); return; }
  const token = url.searchParams.get('token') || '';
  const userId = verifyToken(token);
  if (!userId) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const key = req.headers['sec-websocket-key'];
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey(key) + '\r\n\r\n'
  );
  socket.setNoDelay(true);

  const conn = new WSConn(socket);
  conn.user = findUser(userId);
  if (!conn.user) { socket.destroy(); return; }
  allConns.add(conn);
  if (!online.has(userId)) online.set(userId, new Set());
  online.get(userId).add(conn);
  const fresh = online.get(userId).size === 1;

  // nëse ka një thirrje që pret (deri 50 s), bjeri zilen menjëherë
  const pend = pendingCalls.get(userId);
  if (pend && Date.now() - pend.ts < 50000) {
    setTimeout(() => conn.sendObj({ type: 'call-offer', from: pend.from, callId: pend.callId, sdp: pend.sdp, media: pend.media }), 600);
  }

  const reply = (obj) => conn.sendObj(obj);

  conn.onmessage = (text) => {
    let m;
    try { m = JSON.parse(text); } catch (e) { return; }
    if (!m || typeof m !== 'object') return;
    const me = conn.user;

    switch (m.type) {
      case 'ping':
        reply({ type: 'pong', t: m.t });
        return;

      case 'hello': {
        reply({
          type: 'ready',
          me: publicUser(me, true),
          familyName: db.family.name,
          inviteCode: db.family.inviteCode,
          users: presenceSnapshot(),
          unread: unreadFor(me.id),
          last: lastMessagesFor(me.id)
        });
        if (fresh) broadcast({ type: 'presence', users: presenceSnapshot() });
        return;
      }

      case 'msg': {
        const peer = findUser(m.to);
        const body = String(m.text || '').trim().slice(0, MAX_MESSAGE_LEN);
        const img = (typeof m.img === 'string' && m.img.startsWith('data:image/') && m.img.length < 500000) ? m.img : null;
        if (!peer || peer.id === me.id || (!body && !img)) return;
        const msg = { id: uid(), from: me.id, to: peer.id, text: body, ts: Date.now() };
        if (img) msg.img = img;
        db.messages.push(msg);
        if (db.messages.length > MAX_MESSAGES) db.messages.splice(0, db.messages.length - MAX_MESSAGES);
        markDirty();
        const delivered = sendTo(peer.id, { type: 'msg', msg });
        if (delivered) {
          msg.d = Date.now();
          markDirty();
        }
        // konfirmim te dërguesi (të gjitha pajisjet e tij)
        const set = online.get(me.id);
        if (set) for (const c of set) c.sendObj({ type: 'msg-sent', msg, clientId: m.clientId || null });
        if (delivered) sendTo(me.id, { type: 'msg-status', peer: peer.id, status: 'delivered', ids: [msg.id] });
        else { const unreadNow = (unreadFor(peer.id)[me.id] || 0) + 1; pushNotify(peer.id, me.name, img ? '📷 Foto' : (body.length > 80 ? body.slice(0, 77) + '…' : body), 'chat-' + me.id, 'normal', unreadNow); }
        return;
      }

      case 'typing': {
        const peer = findUser(m.to);
        if (peer && typeof m.on === 'boolean') sendTo(peer.id, { type: 'typing', from: me.id, on: m.on });
        return;
      }

      case 'read': {
        const peer = findUser(m.from);
        if (!peer) return;
        const ids = [];
        for (const msg of db.messages) {
          if (msg.from === peer.id && msg.to === me.id && !msg.r) { msg.r = Date.now(); ids.push(msg.id); }
        }
        if (ids.length) { markDirty(); sendTo(peer.id, { type: 'msg-status', peer: me.id, status: 'read', ids }); }
        return;
      }

      case 'history': {
        const peer = findUser(m.peer);
        if (!peer) return;
        const list = db.messages
          .filter(x => (x.from === me.id && x.to === peer.id) || (x.from === peer.id && x.to === me.id))
          .sort((a, b) => a.ts - b.ts)
          .slice(-200);
        reply({ type: 'history', peer: peer.id, messages: list });
        return;
      }

      /* ---------- signalizimi i thirrjeve (WebRTC) ---------- */
      case 'call-offer': {
        const peer = findUser(m.to);
        const media = m.media === 'audio' ? 'audio' : 'video';
        if (!peer || !m.sdp || !m.callId) return;
        // ruaje thirrjen — dorëzohet sapo marrësi të rikthehet (deri 50 s)
        pendingCalls.set(peer.id, { from: me.id, callId: m.callId, sdp: m.sdp, media, ts: Date.now() });
        const awake = isResponsive(peer.id);
        if (!awake) {
          pushNotify(peer.id, '📞 ' + me.name, media === 'audio' ? 'Thirrje… hap aplikacionin.' : 'Thirrje video… hap aplikacionin.', 'call-' + me.id, 'high');
        }
        sendTo(peer.id, { type: 'call-offer', from: me.id, callId: m.callId, sdp: m.sdp, media });
        return;
      }
      case 'call-answer': {
        const peer = findUser(m.to);
        pendingCalls.delete(me.id);
        if (peer && m.sdp && m.callId) sendTo(peer.id, { type: 'call-answer', from: me.id, callId: m.callId, sdp: m.sdp });
        return;
      }
      case 'ice': {
        const peer = findUser(m.to);
        if (peer && m.candidate && m.callId) sendTo(peer.id, { type: 'ice', from: me.id, callId: m.callId, candidate: m.candidate });
        return;
      }
      case 'call-decline':
      case 'call-busy':
      case 'call-hangup': {
        const peer = findUser(m.to);
        pendingCalls.delete(me.id);
        if (peer) { pendingCalls.delete(peer.id); sendTo(peer.id, { type: m.type, from: me.id, callId: m.callId }); }
        return;
      }
    }
  };

  conn.onclose = () => {
    allConns.delete(conn);
    const set = online.get(userId);
    if (set) { set.delete(conn); if (set.size === 0) online.delete(userId); }
    if (!isOnline(userId)) {
      const u = findUser(userId);
      if (u) { u.lastSeen = Date.now(); markDirty(); }
      broadcast({ type: 'presence', users: presenceSnapshot() });
    }
  };
});

/* pastrim i lidhjeve të vdekura */
setInterval(() => {
  const now = Date.now();
  for (const c of allConns) {
    if (now - c.lastActivity > 80000) c.close(1001);
  }
}, 30000);

/* ---------- roboti demo (opsional: nise me DEMO_BOT=1) ---------- */
if (process.env.DEMO_BOT === '1' && fs.existsSync(path.join(__dirname, 'tools', 'demo-bot.js'))) {
  const { spawn } = require('child_process');
  const spawnBot = () => {
    console.log('[demo-bot] Po nis robotin demo (Beni)…');
    const bot = spawn(process.execPath, [path.join(__dirname, 'tools', 'demo-bot.js')], {
      stdio: ['ignore', 'inherit', 'inherit'],
      env: process.env
    });
    bot.on('exit', () => setTimeout(spawnBot, 3000)); // rigjidh automatikisht
  };
  setTimeout(spawnBot, 1200); // lër serverin të ngrihet pari
}

/* ---------------------------------------------------------- nisja */
(async () => {
loadDb();
await initDb();
server.listen(PORT, HOST, () => {
  console.log('┌─────────────────────────────────────────────┐');
  console.log('│  FAMILJA CHAT                               │');
  console.log('│  http://localhost:' + String(PORT).padEnd(25).slice(0, 25) + ' │');
  console.log('│  Anëtarë: ' + String(db.users.length).padStart(3) + '   Kodi i ftesës: ' + (db.family.inviteCode || '(do të krijohet nga i pari)') + ' │');
  console.log('└─────────────────────────────────────────────┘');
});
})();
