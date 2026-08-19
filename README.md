# 👨‍👩‍👧‍👦 Familja Chat

Chat privat **vetëm për familjen tënde** — mesazhe në kohë reale dhe **telefonata video 1-me-1**, në stilin e WhatsApp, si aplikacion web (PWA) që instalohet në telefon.

## ✨ Çfarë ka

| Funksion | Gjendja |
|---|---|
| Biseda tekst në kohë reale (WebSocket) | ✅ gati |
| Thirrje video 1-me-1 (WebRTC, video shkon direkt pajisje-pajisje) | ✅ gati |
| Kodi i ftesës — hyjnë vetëm ata që e kanë | ✅ gati |
| Online / "po shkruan…" / "ishte online…" | ✅ gati |
| ✓ dërguar / ✓✓ dorëzuar / ✓✓ blu = lexuar | ✅ gati |
| Historik bisedash + numëruesi i palexuarave | ✅ gati |
| Tinguj mesazhi + zile thirrjeje + dridhje | ✅ gati |
| Njoftime **push në background** | ⚙️ aktivizohet pas vendosjes në server (shih më poshtë) |
| Instalim si aplikacion (Shto në Ekranin Bazë/Kryesor) | ✅ gati |

**Siguria:** fjalëkalimet ruhen të hash-uar (scrypt), lidhja është HTTPS/WSS, dhe regjistrimi funksionon **vetëm me kodin e ftesës**. Mesazhet kalojnë nga serveri yt (s'janë fshehtësi-skaj-për-skaj si në WhatsApp — mund t'i shtojmë në një version të ardhshëm).

## 🚀 Si ta provoj tani (pa asgjë)

```bash
node server.js
```

Hap `http://localhost:8080` në dy tabe (ose dy pajisje në rrjetin lokal):
1. **Anëtari i parë** regjistrohet pa kod — bëhet administrator dhe krijohet automatikisht **kodi i ftesës** (Cilësime → Kodi i ftesës).
2. **Anëtarët e tjerë** regjistrohen me atë kod.
3. Shkruani mesazhe, provoni "po shkruan…", tikat ✓✓ dhe thirrjen video 📞.

> S'ka nevojë për `npm install` për chat & thirrje — serveri është i shkruar në Node të pastër. `npm install` duhet vetëm për njoftimet push.

## 📲 Si ta vendos në internet (falas për fillim)

### Render.com (më e thjeshta)
1. Hidh kodin në një repositorium GitHub.
2. Te [render.com](https://render.com) → **New → Web Service** → lidhe repositoriumin.
3. Build Command: `npm install` · Start Command: `npm start` · Region: Frankfurt.
4. Për njoftimet push, shto variablat e mjedisit (shih seksionin vijues) dhe krijon URL-në: `https://familja-ta.render.com`.

Alternativa: [railway.app](https://railway.app), [koyeb.com](https://koyeb.com), ose çdo VPS (3–5 €/muaj).

### ⚙️ Aktivizimi i njoftimeve push (background)
```bash
npm install          # instalon web-push
npm run generate-vapid   # gjeneron dy çelësa
```
Vendosi te Render → Environment:
```
VAPID_PUBLIC_KEY=...
VAPID_PRIVATE_KEY=...
```
Pastaj te aplikacioni (në URL-në reale me HTTPS): **Cilësime → Aktivizo njoftimet** — prej këtej, çdo mesazh/thirrje vjen si njoftim edhe kur aplikacioni është i mbyllur.

> **iPhone:** njoftimet push punojnë që nga iOS 16.4 dhe **vetëm** pasi aplikacioni të shtohet në Ekranin Bazë (Shto në Ekranin Bazë). **Android:** "Shto në ekranin kryesor" në Chrome.

> **Shënim për planet falas:** disa shërbime falas "flen" pas paaktivitetit (hera e parë hapet ngadalë ~30 sek) dhe disku mund të pastrohet në rindezje (historiku fillon nga e para). Për qëndrueshmëri të plotë: planet me pagesë të vogla ose VPS.

### 🎥 Nëse ndonjë thirrje video nuk lidhet
Thirrjet shkojnë direkt mes pajisjeve (P2P) me STUN publik. Në rrjete shumë të mbyllura (disa operatorë/zyra) duhet një server TURN — shto variablat:
```
TURN_URL=turn:serveri-yt:3478
TURN_USERNAME=...
TURN_CREDENTIAL=...
```
(shërbime TURN: Open Relay Project falas, ose `coturn` i vetë-hostuar në VPS.)

## 🗂 Struktura

```
familja-chat/
├── server.js            # serveri: HTTP + WebSocket + auth + signalizim + push
├── lib/ws.js            # WebSocket i implementuar në Node të pastër (RFC 6455)
├── generate-vapid.js    # gjeneron çelësat për push
├── public/              # aplikacioni (frontend)
│   ├── index.html       # ndërfaqja (shqip)
│   ├── app.js           # logjika: biseda, thirrje WebRTC, njoftime
│   ├── styles.css       # stili në stil WhatsApp
│   ├── sw.js            # service worker: njoftime push + cache
│   ├── manifest.webmanifest
│   └── icons/           # ikonat e aplikacionit
├── test/                # 22 teste automatike (node test/run-tests.js)
└── data/db.json         # të dhënat (krijuhet vetë) — kopjoje për backup
```

## 🧪 Testet

```bash
npm test   # 22 teste: regjistrim, kod ftese, mesazhe, lexuar, typing, signalizim thirrjesh
```

## 🔭 Ide për versionin e ardhshëm
- Foto/video/dokumenta në mesazhe · mesazhe zanore
- Fshehtësi skaj-për-skaj (E2EE) · thirrje grupi
- Avatarë me foto · kërkim në mesazhe · backup automatik
