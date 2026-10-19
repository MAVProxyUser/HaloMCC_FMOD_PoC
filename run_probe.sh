#!/usr/bin/env bash
# run_probe.sh <libfmod.dylib> <bank.fsb> [mode_hex] [ver_hex]
# Runs fsb5_probe and classifies the outcome:
#   VULNERABLE  -> died from SIGSEGV/SIGBUS/SIGABRT/SIGILL/SIGTRAP (128+signo)
#   CLEAN       -> returned an FMOD_RESULT without crashing (exit 0)
#   HARNESS_ERR -> setup problem (dlopen/create/init), exit 90-99
# On a crash it also captures an lldb backtrace to prove the fault site.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/fsb5_probe"
LIB="${1:?lib}"; BANK="${2:?bank}"; MODE="${3:-0x2080}"; VER="${4:-0}"

"$PROBE" "$LIB" "$BANK" "$MODE" "$VER"
rc=$?

verdict="UNKNOWN"
if   [ $rc -eq 0 ];   then verdict="CLEAN"
elif [ $rc -ge 90 ] && [ $rc -le 99 ]; then verdict="HARNESS_ERR(exit=$rc)"
elif [ $rc -gt 128 ]; then
    sig=$((rc-128))
    nm=$(kill -l $sig 2>/dev/null || echo "?")
    verdict="VULNERABLE(SIG$nm)"
else verdict="NONZERO(exit=$rc)"
fi
echo "RUN_VERDICT=$verdict  lib=$(basename "$(dirname "$(dirname "$LIB")")")/$(basename "$LIB")  bank=$(basename "$BANK")  rc=$rc"
exit $rc
