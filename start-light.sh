#!/usr/bin/env bash
# start-light.sh — one command at the venue: bridge + tunnel + publish the URL.
#
#   ./start-light.sh            METERED (default): sats buy seconds of light
#   ./start-light.sh --blink    fallback: one 3-pulse blink on board A per payment
#
# Plug ONLY board A (the injector) into the Mac; B and C run on power packs.
#
# 1. Starts the x402 light bridge on :4021 against board A (/dev/cu.usbmodem11201),
#    taking REAL payments (cap 500 sats). The phone's wallet broadcasts its own tx.
#    Metanet Desktop must approve one dialog at startup (the receive key).
# 2. Starts a cloudflared quick tunnel and reads its https://*.trycloudflare.com URL.
# 3. Publishes that URL to the claim service on rbs, so todriguez.com/cfb/light
#    redirects phones to it.
# Ctrl-C kills both children and removes the published URL, so /cfb/light goes
# back to "not on yet".
#
# METERED: A broadcasts a payment channel; B and C (mesh_demo, on power packs)
# each meter it themselves at ~1.2 sats/s and switch their LEDs off when the
# paid sats run out. Everyone's payments add up. The channel id lives in
# ~/.semantos-light-channel.json so a restart can close it cleanly.
# BLINK: A acks each injected cell with a 3-pulse blink; no other board needed.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=4021
BOARD=/dev/cu.usbmodem11201
LOGDIR="${TMPDIR:-/tmp}/start-light.$$"
BRIDGE_LOG="$LOGDIR/bridge.log"
TUNNEL_LOG="$LOGDIR/cloudflared.log"
CLAIM_DIR=/etc/semantos/meetup-claims

# The quick-tunnel URL from a cloudflared log. Skips api.trycloudflare.com,
# which appears in cloudflared's own error lines.
parse_url() {
  grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$1" 2>/dev/null | grep -v '^https://api\.' | head -n 1
}

# Test hook: ./start-light.sh --parse-url-from <cloudflared log>
if [ "${1:-}" = "--parse-url-from" ]; then
  parse_url "$2"
  exit 0
fi

MODE=metered
case "${1:-}" in
  --blink) MODE=blink ;;
  "") ;;
  *) echo "usage: $0 [--blink]" >&2; exit 2 ;;
esac

loud() { printf '\n\033[1;33m%s\033[0m\n\n' "$*"; }
die() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }

BRIDGE_PID=""
TUNNEL_PID=""
TAIL_PID=""
PUBLISHED=0
CLEANED=0
cleanup() {
  [ "$CLEANED" = 1 ] && return
  CLEANED=1
  echo
  echo "stopping…"
  [ -n "$TAIL_PID" ] && kill "$TAIL_PID" 2>/dev/null
  [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null && echo "  tunnel stopped (pid $TUNNEL_PID)"
  [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null && echo "  bridge stopped (pid $BRIDGE_PID)"
  if [ "$PUBLISHED" = 1 ]; then
    if ssh rbs "rm -f $CLAIM_DIR/light-url" </dev/null; then
      echo "  URL unpublished — /cfb/light is back to \"not on yet\""
    else
      echo "  !! could not unpublish; run: ssh rbs \"rm -f $CLAIM_DIR/light-url\""
    fi
  fi
  echo "  logs: $LOGDIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ── preflight ────────────────────────────────────────────────────────
command -v bun >/dev/null || die "bun not found"
command -v cloudflared >/dev/null || die "cloudflared not found"
[ -e "$BOARD" ] || die "board A not found at $BOARD — is it plugged in?"
if lsof "$BOARD" >/dev/null 2>&1; then
  lsof "$BOARD"
  die "$BOARD is in use by the process above — stop it first"
fi
if lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  lsof -iTCP:"$PORT" -sTCP:LISTEN
  die "port $PORT is already taken"
fi
mkdir -p "$LOGDIR"

# ── 1. the bridge ────────────────────────────────────────────────────
cd "$HERE" || die "cannot cd to $HERE"
echo "mode: $MODE"
if [ "$MODE" = metered ]; then
  bun tools/x402-bridge/server.ts --port "$PORT" \
    --real-payment --max-sats 500 --no-bridge-broadcast \
    --metered --inject-port "$BOARD" \
    >"$BRIDGE_LOG" 2>&1 &
else
  bun tools/x402-bridge/server.ts --port "$PORT" \
    --real-payment --max-sats 500 --no-bridge-broadcast \
    --inject-port "$BOARD" --ack-port "$BOARD" --ack-match "CELL INJECTED" \
    >"$BRIDGE_LOG" 2>&1 &
fi
BRIDGE_PID=$!
loud ">>> APPROVE THE METANET DESKTOP DIALOG NOW (the bridge needs its receive key) <<<"

waited=0
until grep -q "listening on" "$BRIDGE_LOG" 2>/dev/null; do
  kill -0 "$BRIDGE_PID" 2>/dev/null || { cat "$BRIDGE_LOG"; die "bridge exited — see above"; }
  sleep 1
  waited=$((waited + 1))
  [ $((waited % 15)) = 0 ] && loud ">>> still waiting on Metanet Desktop — approve its dialog (${waited}s) <<<"
  [ "$waited" -ge 300 ] && { cat "$BRIDGE_LOG"; die "bridge did not start in 5 min"; }
done
cat "$BRIDGE_LOG"
grep -q "payment: MAINNET" "$BRIDGE_LOG" || die "bridge is not in real-payment mode — refusing to publish"
if [ "$MODE" = metered ] && grep -q "WARNING: the injector did not broadcast" "$BRIDGE_LOG"; then
  die "board A did not broadcast the channel_open — replug A and retry (or ./start-light.sh --blink)"
fi

# ── 2. the tunnel ────────────────────────────────────────────────────
cloudflared tunnel --url "http://localhost:$PORT" >"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
URL=""
waited=0
while [ -z "$URL" ]; do
  kill -0 "$TUNNEL_PID" 2>/dev/null || { cat "$TUNNEL_LOG"; die "cloudflared exited — see above"; }
  sleep 1
  waited=$((waited + 1))
  [ "$waited" -ge 60 ] && { cat "$TUNNEL_LOG"; die "no trycloudflare URL after 60 s"; }
  URL="$(parse_url "$TUNNEL_LOG")"
done
echo "tunnel: $URL"

# Never resolve the fresh tunnel name through the local resolver. A venue
# router that asks before cloudflare has published the name caches
# NXDOMAIN, and every phone on that Wi-Fi then gets "no such host" for
# minutes. So wait, then probe only via 1.1.1.1 with curl --resolve.
HOST="${URL#https://}"
DNS_WAIT="${LIGHT_DNS_WAIT:-15}"
echo "waiting ${DNS_WAIT}s before probing $HOST (via 1.1.1.1 only)…"
sleep "$DNS_WAIT"
IP=""
for _ in $(seq 1 20); do
  IP="$(dig +short "$HOST" @1.1.1.1 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | head -n 1)"
  if [ -n "$IP" ] && curl -fsS -o /dev/null --max-time 5 --resolve "$HOST:443:$IP" "$URL/"; then
    echo "tunnel answers at $IP (resolved via 1.1.1.1)"
    break
  fi
  IP=""
  sleep 3
done
[ -n "$IP" ] || loud ">>> WARNING: the tunnel did not answer via 1.1.1.1 yet — publishing anyway <<<"

# ── 3. publish ───────────────────────────────────────────────────────
printf '%s\n' "$URL" | ssh rbs "umask 077; cat > $CLAIM_DIR/light-url.tmp && chown semantos-meetup-claims: $CLAIM_DIR/light-url.tmp && mv $CLAIM_DIR/light-url.tmp $CLAIM_DIR/light-url" \
  || die "publishing the URL to rbs failed"
PUBLISHED=1
# Read the redirect only — never follow it to the fresh tunnel name.
LOCATION="$(curl -sI --max-time 10 https://todriguez.com/cfb/light | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')"
echo "todriguez.com/cfb/light → ${LOCATION:-<no Location header>}"
case "$LOCATION" in
  "$URL"*) loud ">>> LIVE: phones open https://todriguez.com/cfb/light in BSV Browser <<<"
          loud ">>> phones: give it a minute before the first scan <<<" ;;
  *) loud ">>> WARNING: /cfb/light does not point at $URL yet — phones can use $URL directly <<<" ;;
esac
echo "queue: curl localhost:$PORT/queue     stop: Ctrl-C"
echo

# ── run until Ctrl-C (or a child dies) ───────────────────────────────
tail -n 0 -f "$BRIDGE_LOG" &
TAIL_PID=$!
while kill -0 "$BRIDGE_PID" 2>/dev/null && kill -0 "$TUNNEL_PID" 2>/dev/null; do
  sleep 2
done
loud ">>> a child exited — shutting down <<<"
tail -n 20 "$TUNNEL_LOG"
