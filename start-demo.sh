#!/bin/sh
# ============================================================
#  FAMILJA CHAT — nisja e demo-së (server + robot + tunel)
#  Një komandë i nis të gjitha:
#    sh start-demo.sh
#  Adresa publike: https://familja-chat.loca.lt
# ============================================================
set -u

cd "$(dirname "$0")"

# 1) serveri + roboti demo (Beni)
DEMO_BOT=1 node server.js &
SERVER_PID=$!

# 2) prit pak që porti 8080 të ngrihet
i=0
while [ $i -lt 30 ]; do
  if curl -s -m 1 http://127.0.0.1:8080/api/health >/dev/null 2>&1; then break; fi
  sleep 1; i=$((i+1))
done
echo "[demo] Serveri u ngrit (porti 8080)."

# 3) tuneli publik me adrese te fiksuar
if [ ! -x /home/user/lt/node_modules/.bin/lt ]; then
  echo "[demo] localtunnel mungon — po e instaloj…"
  mkdir -p /home/user/lt
  cd /home/user/lt
  npm install localtunnel --no-audit --no-fund >/dev/null 2>&1 || true
  cd - >/dev/null
fi
if [ -x /home/user/lt/node_modules/.bin/lt ]; then
  cd /home/user/lt
  ./node_modules/.bin/lt --port 8080 --subdomain familja-chat &
  LT_PID=$!
  echo "[demo] Tuneli: https://familja-chat.loca.lt"
  cd - >/dev/null
else
  echo "[demo] (localtunnel s'u instalua — vetëm serveri lokal është aktiv)"
  LT_PID=""
fi

# mbyll gjithçka pastër kur ndalet skripti
trap 'kill $SERVER_PID ${LT_PID:-0} 2>/dev/null; exit 0' TERM INT
wait
