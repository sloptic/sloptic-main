#!/usr/bin/env bash
# serve-anchors.sh — bring up ALL local vuln-corpus anchor apps on fixed loopback ports, for manual poking
# AND recall calibration. The ports are FIXED (not OS-random) on purpose: the fuzzer's anchors.txt points at
# these exact ports, so an ephemeral/random port would break calibration. Idempotent — safe to re-run any
# time, including after a reboot. The apps persist across restart via compose `restart: unless-stopped`, as
# long as the Docker daemon starts on boot (sudo systemctl enable docker).
#
# SAFETY: these apps are BUILT TO BE HACKED. Every port binds to 127.0.0.1 ONLY — never expose to a network.
#
# usage:  ./serve-anchors.sh          bring up + seed + health-check + print the map
#         ./serve-anchors.sh down     stop + remove the containers
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")"   # -> validation/vuln-corpus

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found — install Docker to serve the local anchors."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' (Compose v2) unavailable."; exit 1; }

if [ "${1:-}" = "down" ]; then
  echo "== stopping the vuln-corpus anchors =="
  docker compose down
  exit 0
fi

echo "== bringing up the vuln-corpus anchors (docker compose up -d) =="
docker compose up -d

if [ -f setup.sh ]; then
  echo "== seeding DVWA/bWAPP/VAmPI databases (setup.sh, idempotent) =="
  bash setup.sh || echo "  (setup.sh reported issues — if DVWA/bWAPP misbehave: ./serve-anchors.sh down && ./serve-anchors.sh)"
fi

# name | url | login | what it exercises   (OopsSec self-seeds; no setup.sh step needed)
apps=(
  "DVWA|http://127.0.0.1:8081|admin / password|PHP SQLi/XSS/CSRF/LFI/upload/cmdi"
  "bWAPP|http://127.0.0.1:8082|bee / bug|wide PHP bug surface"
  "JuiceShop|http://127.0.0.1:8083|(self-register)|Angular SPA, JS-bundle-mined"
  "VAmPI|http://127.0.0.1:8084|name1 / pass1|REST API (BOLA/SQLi) — primary canary"
  "OopsSec|http://localhost:3000|(self-register)|Next.js store (authed IDOR/XSS/JWT)"
)

wait_up() {   # poll a url until it returns any HTTP status (containers take a bit to boot); ~60s cap
  local url="$1" code i
  for i in $(seq 1 30); do
    code=$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$url" 2>/dev/null || true)
    [ -n "$code" ] && [ "$code" != "000" ] && return 0
    sleep 2
  done
  return 1
}

echo "== waiting for each app to answer (they boot concurrently; ~60s cap each) =="
printf '\n  %-6s %-10s %-26s %-17s %s\n' STATUS APP URL LOGIN EXERCISES
printf '  %s\n' "---------------------------------------------------------------------------------------------------"
for row in "${apps[@]}"; do
  IFS='|' read -r name url login exer <<<"$row"
  if wait_up "$url"; then st=" UP "; else st="DOWN"; fi
  printf '  [%s] %-10s %-26s %-17s %s\n' "$st" "$name" "$url" "$login" "$exer"
done

# GapBench is REMOTE (hosted, not served locally) — just report reachability of its ground-truth manifest
gb=$(curl -s -o /dev/null -m 8 -w '%{http_code}' 'https://gapbench.vibe-eval.com/__manifest' 2>/dev/null || true)
echo
if [ "$gb" = "200" ]; then
  echo "  GapBench (remote, not served here): reachable ✓ — 104 scenarios in gapbench.txt"
else
  echo "  GapBench (remote): manifest NOT reachable (HTTP ${gb:-none}) — check connectivity before a recall run"
fi

cat <<'EOF'

  poke around:  open the URLs above in a browser (all loopback-only).
  calibrate (from the fuzz-runner ROOT dir):
      uv run python scripts/run_batch.py --urls validation/vuln-corpus/anchors.txt  --url-only --tldr \
          --results anchors-recall.jsonl  --limit 50
      uv run python scripts/run_batch.py --urls validation/vuln-corpus/gapbench.txt --url-only --tldr \
          --concurrency 3 --results gapbench-recall.jsonl --limit 200
  stop:         ./serve-anchors.sh down
  persist:      containers auto-return after reboot (restart: unless-stopped) IF docker starts on boot:
                sudo systemctl enable docker
EOF
