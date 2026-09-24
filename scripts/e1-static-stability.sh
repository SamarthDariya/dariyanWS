#!/bin/sh
# BREAK.md E1 — does the data plane outlive the control plane?
#
# Three measurements of the same request against the same data plane, holding the same capability:
#
#   phase 1  everything running
#   phase 2  front door killed, Postgres stopped — only the data plane remains
#   phase 3  the capability has expired
#
# The question is binary and phase 2 answers it. The latency comparison between 1 and 2 is the
# part that could surprise: a dependency that exists but is fast still moves the mean.
set -e
cd "$(dirname "$0")/.."

REQUESTS=${REQUESTS:-200}
TTL=${TTL:-10s}          # shorter than the 30s default so phase 3 does not dominate the run
FUNCTION=${FUNCTION:-resize}

say() { printf '\n=== %s ===\n' "$1"; }

# measure sends REQUESTS requests and prints count of each status plus mean/p50 latency in ms.
measure() {
  label="$1"; header="$2"
  tmp=$(mktemp)
  for _ in $(seq "$REQUESTS"); do
    curl -sS -o /dev/null -w '%{http_code} %{time_total}\n' \
      -X POST -H "X-Dariya-Capability: $header" \
      "http://127.0.0.1:8081/f/$FUNCTION/invocations" >> "$tmp" 2>/dev/null || echo "000 0" >> "$tmp"
  done

  printf '%s\n' "$label"
  printf '  statuses: '
  awk '{c[$1]++} END {for (s in c) printf "%s=%d ", s, c[s]; print ""}' "$tmp"
  sort -k2 -n "$tmp" | awk -v n="$REQUESTS" '
    {t[NR]=$2; sum+=$2}
    END {printf "  mean %.3f ms   p50 %.3f ms   p99 %.3f ms\n",
                sum/NR*1000, t[int(NR*0.5)]*1000, t[int(NR*0.99)]*1000}'
  rm -f "$tmp"
}

eval "$(make -s dev-keys)"
eval "$(make -s dev-token | grep '^export')"
go build -o bin/ ./cmd/...

DARIYA_TOKEN_PUBLIC_KEYS="$DARIYA_TOKEN_PUBLIC_KEYS" \
  ./bin/echo --addr 127.0.0.1:8081 --mode guarded --service func >/tmp/e1-echo.log 2>&1 &
ECHO_PID=$!
DARIYA_MASTER_KEYS="$DARIYA_MASTER_KEYS" DARIYA_TOKEN_SIGNING_KEY="$DARIYA_TOKEN_SIGNING_KEY" \
  ./bin/frontdoor --addr 127.0.0.1:8080 --func-upstream http://127.0.0.1:8081 >/tmp/e1-fd.log 2>&1 &
FD_PID=$!
trap 'kill $ECHO_PID $FD_PID 2>/dev/null || true; docker start dariya-postgres >/dev/null 2>&1 || true' EXIT

until curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1; do sleep 0.3; done
until curl -sf http://127.0.0.1:8081/healthz >/dev/null 2>&1; do sleep 0.3; done

RESOURCE="arn:dariya:func:hind-1:$DARIYA_ACCOUNT_ID:function/$FUNCTION"
CAP=$(DARIYA_TOKEN_SIGNING_KEY="$DARIYA_TOKEN_SIGNING_KEY" \
      ./bin/dariyactl mint-capability --action func:Invoke --resource "$RESOURCE" \
        --account "$DARIYA_ACCOUNT_ID" --ttl "$TTL" 2>/dev/null)

say "control plane alive: a normal request through the front door"
./bin/dariyactl sign --service func --method POST \
  --url "http://127.0.0.1:8080/f/$FUNCTION/invocations" 2>/dev/null > /tmp/e1-inv.sh
sh /tmp/e1-inv.sh; echo

say "phase 1 — everything running"
measure "data plane, direct, control plane UP" "$CAP"

say "killing the control plane"
kill -9 "$FD_PID" 2>/dev/null || true
docker stop dariya-postgres >/dev/null
echo "front door killed, Postgres stopped"
curl -sS --max-time 2 http://127.0.0.1:8080/healthz 2>&1 | head -1 || echo "front door is gone (connection refused)"

say "phase 2 — only the data plane remains"
measure "data plane, direct, control plane DOWN" "$CAP"

say "phase 3 — after the capability expires"
sleep 12
measure "data plane, direct, capability EXPIRED" "$CAP"
echo "  last refusal from the data plane's log:"
grep refused /tmp/e1-echo.log | tail -1 | sed 's/^/  /'

say "restoring"
docker start dariya-postgres >/dev/null
echo "postgres restarted"
