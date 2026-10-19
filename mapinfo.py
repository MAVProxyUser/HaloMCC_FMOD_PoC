#!/usr/bin/env python3
# Parse a Halo 3 .mapinfo (BLF container) to learn its layout, and (with --gen)
# emit a compatible .mapinfo for a renamed custom map. Pure metadata authoring
# for a local test map; no game code or integrity control is modified.
import sys, struct, argparse

def chunks(data):
    """Yield (magic, start, hdrlen, total, major, minor) for each BLF chunk."""
    off = 0
    while off + 12 <= len(data):
        magic = data[off:off+4]
        length = struct.unpack_from(">I", data, off+4)[0]   # big-endian length (incl header)
        major, minor = struct.unpack_from(">HH", data, off+8)
        yield magic, off, length, major, minor
        if length == 0:
            break
        off += length

def find_utf16_runs(blob, base):
    """Find UTF-16BE printable string runs (title fields are UTF-16BE)."""
    out = []
    i = 0
    while i + 2 <= len(blob):
        # a run of 00 XX where XX is printable ascii
        if blob[i] == 0 and 32 <= blob[i+1] < 127:
            j = i
            s = []
            while j + 2 <= len(blob) and blob[j] == 0 and 32 <= blob[j+1] < 127:
                s.append(chr(blob[j+1])); j += 2
            if len(s) >= 3:
                out.append((base+i, "".join(s)))
            i = j
        else:
            i += 1
    return out

def ascii_runs(blob, base, minlen=4):
    out = []; i = 0
    while i < len(blob):
        if 32 <= blob[i] < 127:
            j = i; s = []
            while j < len(blob) and 32 <= blob[j] < 127:
                s.append(chr(blob[j])); j += 1
            if j - i >= minlen:
                out.append((base+i, "".join(s)))
            i = j
        else:
            i += 1
    return out

def parse(path):
    data = open(path, "rb").read()
    print("file %s  (%d bytes)" % (path, len(data)))
    print("== BLF chunks ==")
    levl = None
    for magic, off, length, maj, minr in chunks(data):
        print("  @0x%06x  %-5r len=0x%x (%d)  ver %d.%d" % (off, magic, length, length, maj, minr))
        if magic == b"levl":
            levl = (off, length)
    if not levl:
        return data, None
    loff, llen = levl
    body = data[loff+12: loff+llen]      # after the 12-byte chunk header
    print("\n== levl body first 16 bytes (id/flags region) ==")
    print("  " + " ".join("%02x" % b for b in body[:16]))
    # map id candidates: first few 32-bit BE/LE values
    print("  u32@0 BE=%d LE=%d | u32@4 BE=%d LE=%d" % (
        struct.unpack_from(">I", body, 0)[0], struct.unpack_from("<I", body, 0)[0],
        struct.unpack_from(">I", body, 4)[0], struct.unpack_from("<I", body, 4)[0]))
    print("\n== UTF-16BE title/string runs in levl (offset from file start) ==")
    for o, s in find_utf16_runs(body, loff+12)[:12]:
        print("  @0x%06x  %r" % (o, s))
    print("\n== ASCII runs near end of file (scenario stem / path, fixed fields) ==")
    for o, s in ascii_runs(data[-400:], len(data)-400):
        print("  @0x%06x  %r" % (o, s))
    return data, levl

def gen(tmpl_path, out_path, new_stem, new_path_stem, new_title, old_stem, old_path_stem, old_title):
    data = bytearray(open(tmpl_path, "rb").read())
    def repl_ascii(old, new):
        # replace a null-terminated ascii field in place; must fit the original field
        b = old.encode("latin1"); nb = new.encode("latin1")
        idx = data.find(b + b"\x00")
        n = 0
        while idx != -1:
            # field extends until next non-null... we overwrite old bytes then pad with \0
            if len(nb) > len(b):
                raise SystemExit("new ascii %r longer than field %r" % (new, old))
            data[idx:idx+len(b)] = nb + b"\x00" * (len(b)-len(nb))
            n += 1; idx = data.find(b + b"\x00", idx+1)
        return n
    def repl_utf16(old, new):
        b = old.encode("utf-16-be"); nb = new.encode("utf-16-be")
        idx = data.find(b); n = 0
        while idx != -1:
            if len(nb) > len(b):
                raise SystemExit("new title %r longer than %r" % (new, old))
            data[idx:idx+len(b)] = nb + b"\x00" * (len(b)-len(nb))
            n += 1; idx = data.find(b, idx+1)
        return n
    na = repl_ascii(old_path_stem, new_path_stem) + repl_ascii(old_stem, new_stem)
    nt = repl_utf16(old_title, new_title)
    open(out_path, "wb").write(data)
    print("wrote %s  (ascii fields replaced=%d, title fields replaced=%d)" % (out_path, na, nt))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("--gen")
    ap.add_argument("--new-stem"); ap.add_argument("--new-path-stem"); ap.add_argument("--new-title")
    ap.add_argument("--old-stem"); ap.add_argument("--old-path-stem"); ap.add_argument("--old-title")
    a = ap.parse_args()
    if a.gen:
        gen(a.template, a.gen, a.new_stem, a.new_path_stem, a.new_title,
            a.old_stem, a.old_path_stem, a.old_title)
    else:
        parse(a.template)
