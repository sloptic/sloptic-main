#!/usr/bin/env bash
# One-time DB init after `docker compose up -d`. DVWA and bWAPP ship empty and only serve vulnerable
# surface once their database exists; VAmPI needs its users populated. Juice Shop needs nothing. Safe to
# re-run (it just resets the DBs). Everything talks to 127.0.0.1 only.
set -u

echo "waiting for containers to answer (up to ~90s each)..."
for url in 8081 8082 8083 8084; do
  for _ in $(seq 1 45); do curl -sf -o /dev/null "http://127.0.0.1:$url/" && break; sleep 2; done
done

echo "== DVWA (8081): create/reset the database =="
jar="$(mktemp)"
tok="$(curl -s -c "$jar" http://127.0.0.1:8081/setup.php \
       | grep -oiE "user_token'? *value='?[0-9a-f]{32}" | grep -oiE '[0-9a-f]{32}' | head -1)"
curl -s -b "$jar" -c "$jar" --data "create_db=Create+%2F+Reset+Database&user_token=${tok}" \
     http://127.0.0.1:8081/setup.php -o /dev/null
echo "   login admin / password. For max vulnerable surface, grade with the 'security=low' cookie set."

echo "== bWAPP (8082): install the database =="
curl -s "http://127.0.0.1:8082/install.php?install=yes" -o /dev/null
echo "   login bee / bug."

echo "== VAmPI (8084): populate users =="
curl -s http://127.0.0.1:8084/createdb -o /dev/null
echo "   users name1/pass1, name2/pass2. OpenAPI at /openapi.json."

echo "== Juice Shop (8083): no setup needed =="
echo "done. Verify with: curl -sI http://127.0.0.1:808{1,2,3,4}/"
