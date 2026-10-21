#!/usr/bin/env python3
"""Minimal PE64 parser + helpers for halo2.dll static triage.
Stdlib only (no pefile needed). Provides section mapping, RVA<->file offset,
byte search, and a capstone disassembler at an RVA.
"""
import struct, sys

class PE:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        d = self.data
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e_lfanew:e_lfanew+4] == b"PE\0\0", "not PE"
        coff = e_lfanew + 4
        (self.machine, self.nsec, _ts, _p1, _p2, self.opt_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", d, coff)
        opt = coff + 20
        self.magic = struct.unpack_from("<H", d, opt)[0]  # 0x20b = PE32+
        assert self.magic == 0x20b, "not PE32+"
        self.image_base = struct.unpack_from("<Q", d, opt+24)[0]
        self.section_align = struct.unpack_from("<I", d, opt+32)[0]
        self.file_align = struct.unpack_from("<I", d, opt+36)[0]
        self.entry = struct.unpack_from("<I", d, opt+16)[0]
        sec_off = opt + self.opt_size
        self.sections = []
        for i in range(self.nsec):
            o = sec_off + i*40
            name = d[o:o+8].rstrip(b"\0").decode("latin1")
            (vsize, vaddr, rawsize, rawptr) = struct.unpack_from("<IIII", d, o+8)
            flags = struct.unpack_from("<I", d, o+36)[0]
            self.sections.append(dict(name=name, vsize=vsize, vaddr=vaddr,
                                      rawsize=rawsize, rawptr=rawptr, flags=flags))

    def sec_for_rva(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s
        return None

    def rva2off(self, rva):
        s = self.sec_for_rva(rva)
        if not s: return None
        return s["rawptr"] + (rva - s["vaddr"])

    def off2rva(self, off):
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return s["vaddr"] + (off - s["rawptr"])
        return None

    def read_rva(self, rva, n):
        o = self.rva2off(rva)
        if o is None: return None
        return self.data[o:o+n]

    def find_all(self, needle, sec_name=None):
        """yield file offsets of needle (optionally restricted to a section)."""
        if sec_name:
            secs = [s for s in self.sections if s["name"] == sec_name]
        else:
            secs = self.sections
        for s in secs:
            blob = self.data[s["rawptr"]:s["rawptr"]+s["rawsize"]]
            start = 0
            while True:
                i = blob.find(needle, start)
                if i < 0: break
                yield s["rawptr"] + i
                start = i + 1

    def disasm(self, rva, count=60, md=None):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        if md is None:
            md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
        o = self.rva2off(rva)
        code = self.data[o:o+count*15]
        out = []
        for ins in md.disasm(code, self.image_base + rva):
            out.append(ins)
            if len(out) >= count: break
        return out

if __name__ == "__main__":
    pe = PE(sys.argv[1])
    print(f"machine={pe.machine:#x} base={pe.image_base:#x} entry rva={pe.entry:#x}")
    print(f"sections ({pe.nsec}):")
    for s in pe.sections:
        print(f"  {s['name']:8} vaddr={s['vaddr']:#010x} vsize={s['vsize']:#010x} "
              f"rawptr={s['rawptr']:#010x} rawsize={s['rawsize']:#010x} flags={s['flags']:#010x}")
