#!/bin/bash
# Bounded, fully-reversible LIVE Halo: Reach FSB5 crash harness (local/offline).
#
# This is the harness that produced evidence/reach-LIVE-crash-*.log: it backs up
# the shipped haloreach/fmod/pc/sfx.fsb by RENAME (byte-exact restore), swaps in
# the crafted FSB5 bank, launches a bounded offline Reach match with FMOD guard
# pages on, captures the loader log, then ALWAYS restores sfx.fsb (trap on every
# exit path). The crash lands at haloreach.dll+0x6028d8 (the FSB5 sample-table
# builder OOB read), the Reach analogue of Halo 3's halo3.dll+0x4e93e8.
set -u
MCC="$HOME/Library/Application Support/ReclaimerMac/prefix/drive_c/Program Files/Steam/steamapps/common/Halo The Master Chief Collection"
SFX="$MCC/haloreach/fmod/pc/sfx.fsb"
BAK="$SFX.E2EBAK"
GW="$HOME/Desktop/HaloReclaimerMac"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRAFT="${CRAFT:-$HERE/../poc_v2_numsamples_oob.fsb}"
LOG="/tmp/reach_play.log"
ORIG_SIZE=""   # captured from the real bank at backup time (install-specific)

restore(){
  pkill -f "host-probe" 2>/dev/null
  pkill -f "Reach Renaissance" 2>/dev/null
  if [ -e "$BAK" ]; then
    mv -f "$BAK" "$SFX" && echo "[restore] sfx.fsb restored from E2EBAK"
  fi
  if [ -f "$SFX" ]; then
    sz=$(stat -f%z "$SFX")
    echo "[restore] sfx.fsb size now $sz (expected ${ORIG_SIZE:-unknown})"
    [ -n "$ORIG_SIZE" ] && { [ "$sz" = "$ORIG_SIZE" ] && echo "[restore] OK byte-size matches original" || echo "[restore] WARNING size mismatch"; }
  else
    echo "[restore] ERROR sfx.fsb MISSING"
  fi
}
trap restore EXIT INT TERM

echo "=== preconditions ==="
if ps aux | grep -iE "host-probe|Reach Renaissance|haloreach" | grep -v grep >/dev/null; then
  echo "a Reach game process is already running — aborting"; exit 1; fi
[ -e "$BAK" ] && { echo "backup $BAK already exists — aborting (will not clobber)"; exit 1; }
[ -f "$CRAFT" ] || { echo "crafted bank missing: $CRAFT"; exit 1; }
[ -f "$SFX" ]   || { echo "real sfx.fsb missing: $SFX"; exit 1; }
[ -x "$GW/shim/build/peload" ] || { echo "peload (Reclaimer loader) not built at $GW/shim/build/peload"; exit 1; }
ORIG_SIZE=$(stat -f%z "$SFX")
echo "[info] real sfx.fsb is $ORIG_SIZE bytes; crafted bank is $(stat -f%z "$CRAFT") bytes"

echo "=== swap (reversible) ==="
mv "$SFX" "$BAK" || { echo "backup rename failed"; exit 1; }
cp "$CRAFT" "$SFX" || { echo "swap-in failed"; exit 1; }
echo "[swap] crafted sfx.fsb in place: $(stat -f%z "$SFX") bytes (orig preserved at E2EBAK)"

echo "=== bounded launch: reach.sh match (guard pages on, ~1-min match, 240s outer cap) ==="
: > "$LOG" 2>/dev/null || true
cd "$GW" || exit 1
PELOAD_ALLOC_GUARD=1 PELOAD_HEAP_GUARD=1 PELOAD_AUDIO=1 \
  timeout 240 bash shim/reach.sh match >/tmp/reach_e2e_wrap.log 2>&1
rc=$?
echo "[launch] wrapper exit rc=$rc (124 = timed out, which is fine)"
sleep 2
pkill -f "host-probe" 2>/dev/null; pkill -f "Reach Renaissance" 2>/dev/null
sleep 1

echo "=== crash indicators in loader log ($LOG) ==="
if [ -f "$LOG" ]; then
  grep -inE "exception|access viol|segmentation|SIGSEGV|EXCEPTION_|c0000005|guard|unhandled|fatal|crash|0x6028|0x6029|FSB|createStream|FMOD_ERR|sample" "$LOG" | head -40
  echo "--- tail of $LOG ---"; tail -25 "$LOG"
else
  echo "no $LOG produced"
fi
echo "=== wrapper stderr/stdout tail ==="; tail -15 /tmp/reach_e2e_wrap.log 2>/dev/null
# restore runs via trap on exit
