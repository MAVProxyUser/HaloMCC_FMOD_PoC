#!/bin/bash
# Reach Renaissance served-FSB E2E staging (Reach-native, not Reclaimer/Halo3).
# Stages a crafted Reach Workshop mod (ModInfo names a workshop id; rides stock
# forge_halo; overrides haloreach/fmod/pc/sfx.fsb with a numSamples*4 overflow bank)
# into the Workshop content dir, as a locally-provisioned (simulated-published)
# item. A Reach host then plays WITH this mod; a joining guest loads it and faults
# in FMOD at haloreach.dll+0x6028d8.
#
#   bash reach_served_setup.sh stage   # copy the mod into the Workshop content dir
#   bash reach_served_setup.sh clean   # remove it
# Then run the 3 commands this prints (local master, Reach host, guest join).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PFX="$HOME/Library/Application Support/ReclaimerMac/prefix/drive_c"
WS="$PFX/Program Files/Steam/steamapps/workshop/content/976730"
FAKEID=9000000001
SRC="$HERE/../reach-workshop-mod/$FAKEID"

case "${1:-}" in
stage)
  [ -d "$SRC" ] || { echo "mod payload missing: $SRC"; exit 1; }
  mkdir -p "$WS"
  [ -e "$WS/$FAKEID" ] && { echo "already staged at $WS/$FAKEID (run clean first)"; exit 1; }
  cp -R "$SRC" "$WS/$FAKEID"
  echo "[stage] crafted Reach mod -> $WS/$FAKEID (workshop id $FAKEID)"
  cat <<EOF

=== RUN IT (Reach Renaissance) ===
RR=~/Desktop/HaloReclaimerMac ; PRE="\$HOME/Library/Application Support/ReclaimerMac/prefix/drive_c/ReachRenaissance"

1) Local master (listings/leases/rendezvous), in its own terminal:
   arch -x86_64 \$RR/shim/build/peload "\$PRE/bin/rr-master.exe" --port 11700 --allow-insecure-http

2) Reach HOST that plays WITH the crafted mod, in its own terminal (guard pages on):
   cd "\$HOME/Library/Application Support/ReclaimerMac/prefix/drive_c/ReclaimerCache/ReachRenaissance/runs/mac" ; mkdir -p host
   PELOAD_ALLOC_GUARD=1 PELOAD_PRESENT=1 PELOAD_HOLD_WINDOW=1 PELOAD_D3DGL=1 \\
     arch -x86_64 \$RR/shim/build/peload "\$PRE/bin/host-probe.exe" \\
       'C:\\ReclaimerCache\\ReachRenaissance\\runs\\mac\\host' \\
       --mcc 'C:\\Program Files (x86)\\Steam\\steamapps\\common\\Halo The Master Chief Collection' \\
       --strings '\\\\?\\C:\\ReachRenaissance\\data\\strings_en.json' \\
       --announce http://127.0.0.1:11700 --server-name "FSB PoC" --net-lan --allow-insecure-http \\
       --port 40011 --mod $FAKEID --map forge_halo --mode slayer_054 --time-limit 5 \\
       --user-name Host --players-table 32 --max-players 32 --max-machines 32 --seconds 3600 > /tmp/reach_host.log 2>&1 &

3) Guest JOINS (clean client; FMOD guard pages on):
   PELOAD_ALLOC_GUARD=1 bash \$RR/shim/reach.sh join 127.0.0.1:40011

4) Confirm the served crash:
   grep -nE "Workshop mod|mod |download|sound bank|\\.fsb|0x6028d8|0x6029|c0000005|CRASH|FAULT|path request" /tmp/reach_play.log /tmp/reach_host.log

Expected: host logs "the server plays with the Workshop mod $FAKEID"; guest loads it and
faults 0xc0000005 at haloreach.dll+0x6028d8.
Cleanup: kill the master/host terminals, then: bash reach_served_setup.sh clean
EOF
  ;;
clean)
  pkill -f "rr-master" 2>/dev/null; pkill -f "host-probe" 2>/dev/null
  [ -e "$WS/$FAKEID" ] && { rm -rf "$WS/$FAKEID"; echo "[clean] removed $WS/$FAKEID"; } || echo "[clean] nothing staged"
  ;;
*) echo "usage: bash reach_served_setup.sh [stage|clean]"; exit 1;;
esac
