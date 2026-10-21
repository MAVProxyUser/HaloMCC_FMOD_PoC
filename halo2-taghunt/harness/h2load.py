#!/usr/bin/env python3
"""
h2load.py - from-scratch Unicorn loader + harness for the Halo 2 (classic) Blam
cache/tag loader inside halo2.dll (Halo: MCC).  Mirrors the methodology of
poc-fsb5/harness/rawload.py (map the PE ourselves, drive one real parser
function on crafted bytes, stub only the OS/alloc boundary, observe faults).

Target: the tag-index loader  halo2 + 0x6c9970  (pdata body 0x6c9977).
It validates the 0x380-byte cache header (magic 'head'/version 13/footer 'foot'/
name), then:
    A    = align128([hdr+0x14])
    V    = sx([hdr+0x2d0])                 ; "virtual base" offset
    alloc_size = V + A                       ; g_tagmem = alloc(alloc_size)
    dst1 = g_tagmem + V
    sz1  = align128([hdr+0x2d4])
    read(off=[hdr+0x10], size=sz1, dst=dst1)
The allocation is sized from (+0x14,+0x2d0) but the read is sized from (+0x2d4);
nothing cross-checks sz1 <= A.  We drive the REAL code on a mutated header and
watch what dst/size the loader hands the section-reader, with g_tagmem backed by
a guard page so an over-long read faults for real.

Usage: h2load.py <halo2.dll> <headerfile(0x380)> [--trace]
The headerfile is the crafted 0x380 cache header (see mk_header.py).
"""
import sys, struct, argparse, os
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMAGE_BASE = 0x180000000
STACK_BASE = 0x7f0000000
STACK_SIZE = 0x200000
TEB_BASE   = 0x7f8000000
TEB_SIZE   = 0x4000
HDR_BUF    = 0x200000000          # the 0x380 header buffer (g_cache_hdr -> here)
HDR_SIZE   = 0x1000
SCRATCH    = 0x210000000          # scratch returned by misc stubs
SCRATCH_SZ = 0x100000
FILEIMG    = 0x220000000          # in-memory "map file" bytes (what reads pull from)
FILEIMG_SZ = 0x1000000            # 16MB
ARENA_BASE = 0x300000000          # g_tagmem allocation lives here; guard page after
RET_SENTINEL = 0x4444444444440000

FN_ENTRY   = 0x6c9970
FN_END     = 0x6c9d4a

# global pointer slots (RVAs in .data)
G_CACHE_HDR = 0x15e4b50
G_TAGMEM    = 0x15e4b48

ALIGN = lambda v: ((v | 0x7f) + 1) & 0xffffffff if (v & 0x7f) else (v & 0xffffffff)

class H2:
    def __init__(self, dll, hdr, trace=False, fileimg=None):
        self.trace=trace
        with open(dll,"rb") as f: self.img=f.read()
        with open(hdr,"rb") as f: self.hdr=f.read()
        # optional full crafted file image the section reads pull real bytes from
        self.fileimg_bytes=None
        if fileimg:
            with open(fileimg,"rb") as f: self.fileimg_bytes=f.read()
        elif len(self.hdr)>0x380:
            self.fileimg_bytes=self.hdr   # the map file itself
        assert len(self.hdr)>=0x380, "header must be >=0x380 bytes"
        self.uc=Uc(UC_ARCH_X86, UC_MODE_64)
        self.md=Cs(CS_ARCH_X86,CS_MODE_64); self.md.detail=True
        self.allocs=[]            # (base, size)
        self.reads=[]             # (off, size, dst)
        self.fault=None
        self.events=[]
        self._map_pe()
        self._map_misc()
        self._hook()

    def log(self,*a):
        s=" ".join(str(x) for x in a); self.events.append(s); print(s)

    # ---- PE mapping -----------------------------------------------------
    def _map_pe(self):
        d=self.img
        e=struct.unpack_from("<I",d,0x3C)[0]
        nsec=struct.unpack_from("<H",d,e+6)[0]
        optsz=struct.unpack_from("<H",d,e+20)[0]
        secoff=e+24+optsz
        # map a flat image region big enough
        total=0
        secs=[]
        for i in range(nsec):
            o=secoff+i*40
            vaddr=struct.unpack_from("<I",d,o+12)[0]
            vsize=struct.unpack_from("<I",d,o+8)[0]
            rawsz=struct.unpack_from("<I",d,o+16)[0]
            rawpt=struct.unpack_from("<I",d,o+20)[0]
            secs.append((vaddr,vsize,rawsz,rawpt))
            total=max(total, vaddr+max(vsize,rawsz))
        total=(total+0xfff)&~0xfff
        self.uc.mem_map(IMAGE_BASE, total)
        # headers
        self.uc.mem_write(IMAGE_BASE, d[:0x400])
        for vaddr,vsize,rawsz,rawpt in secs:
            if rawsz:
                self.uc.mem_write(IMAGE_BASE+vaddr, d[rawpt:rawpt+rawsz])
        self.image_end=IMAGE_BASE+total

    def _map_misc(self):
        u=self.uc
        u.mem_map(STACK_BASE, STACK_SIZE)
        u.mem_map(TEB_BASE, TEB_SIZE)
        u.mem_map(HDR_BUF, HDR_SIZE)
        u.mem_map(SCRATCH, SCRATCH_SZ)
        u.mem_map(FILEIMG, FILEIMG_SZ)
        # header buffer = crafted header
        u.mem_write(HDR_BUF, self.hdr[:0x380])
        # file image: real crafted bytes where provided, else recognizable filler
        u.mem_write(FILEIMG, (b"\xAA"*FILEIMG_SZ))
        if self.fileimg_bytes:
            fb=self.fileimg_bytes[:FILEIMG_SZ]
            u.mem_write(FILEIMG, fb)
        # g_cache_hdr slot -> HDR_BUF ; g_tagmem slot -> 0
        u.mem_write(G_CACHE_HDR+IMAGE_BASE-IMAGE_BASE, b"")  # noop
        u.mem_write(IMAGE_BASE+G_CACHE_HDR, struct.pack("<Q", HDR_BUF))
        u.mem_write(IMAGE_BASE+G_TAGMEM, struct.pack("<Q", 0))
        # TEB/gs: StackBase@+8, StackLimit@+0x10
        u.mem_write(TEB_BASE+0x08, struct.pack("<Q", STACK_BASE+STACK_SIZE))
        u.mem_write(TEB_BASE+0x10, struct.pack("<Q", STACK_BASE))
        try: u.msr_write(0xC0000101, TEB_BASE)  # GS base
        except Exception: pass

    # ---- stubs ----------------------------------------------------------
    def _alloc(self, size):
        # back the allocation with EXACTLY size (page-rounded) then a guard page
        size&=0xffffffffffffffff
        pr=(size+0xfff)&~0xfff
        if pr==0: pr=0x1000
        base=ARENA_BASE
        # (re)map fresh arena of pr bytes; leave the next page unmapped as guard
        try: self.uc.mem_unmap(ARENA_BASE, 0x40000000)
        except Exception: pass
        # cap mapping so huge sizes don't OOM; guard begins right after `pr`
        MAPCAP=0x8000000  # 128MB cap
        mp=min(pr, MAPCAP)
        self.uc.mem_map(base, mp)
        self.allocs.append((base,size,mp))
        self.log(f"[alloc] size={size:#x} (req) -> base={base:#x} mapped={mp:#x} guard@{base+mp:#x}")
        return base

    def _read(self, off, size, dst):
        self.reads.append((off,size,dst))
        # locate the alloc dst belongs to
        info=""
        for b,s,mp in self.allocs:
            if b<=dst< b+ s + 0x1000000:
                end=b+s
                over = (dst+size) - end
                info=f" alloc=[{b:#x},{end:#x}) dst_off={dst-b:#x}"
                if over>0:
                    info+=f"  *** READ OVERRUNS ALLOC BY {over:#x} BYTES ***"
                break
        self.log(f"[read] off={off:#x} size={size:#x} dst={dst:#x}{info}")
        # build `size` source bytes: real file bytes where available, else filler.
        srcoff = off if off < FILEIMG_SZ else 0
        avail  = max(0, FILEIMG_SZ - srcoff)
        take   = min(size, avail)
        src    = bytes(self.uc.mem_read(FILEIMG+srcoff, take)) if take else b""
        if len(src) < size:
            src = src + b"\xAA"*(size-len(src))
        # write `size` bytes into dst.  ReadFile does NOT know dst's allocation
        # size, so if dst+size crosses the arena guard page this faults for real.
        self.uc.mem_write(dst, src[:size])          # may raise UC_ERR_WRITE_UNMAPPED
        return 1

    def _hook(self):
        STUBS={
            0x73cfb0: ("lock?",       lambda u,a: 0),
            0x6be4c0: ("strnlen",     self._strnlen),
            0x6be200: ("be200",       lambda u,a: 0),
            0x67c730: ("align128",    self._align128),
            0x67ba60: ("alloc",       self._stub_alloc),
            0x9ed715: ("memset",      self._memset),
            0x6ad1c0: ("setglob",     lambda u,a: 0),
            0x6ad010: ("chk->1",      lambda u,a: 1),
            0x6be130: ("be130->scr",  lambda u,a: SCRATCH),
            0x67bbb0: ("fileread",    self._stub_read),
            0x6be240: ("be240reg",    self._be240),
            0x6be230: ("be230->scr",  lambda u,a: SCRATCH),
            0x6c9610: ("sub6c9610->0",lambda u,a: 0),
            0x679880: ("err880",      lambda u,a: 0),
            0x67ba50: ("free",        lambda u,a: 0),
            0x67bd10: ("fin",         lambda u,a: 0),
        }
        self.STUBS=STUBS
        def code_hook(u,addr,size,ud):
            rva=addr-IMAGE_BASE
            if self.trace and FN_ENTRY<=rva<FN_END:
                ins=next(self.md.disasm(u.mem_read(addr,15),addr))
                self.log(f"    {rva:#x}: {ins.mnemonic} {ins.op_str}")
            # intercept direct calls to stub targets
            try: b=u.mem_read(addr,1)[0]
            except Exception: return
            if b==0xE8:
                rel=struct.unpack("<i", u.mem_read(addr+1,4))[0]
                tgt=(addr+5+rel)-IMAGE_BASE
                if tgt in STUBS:
                    name,fn=STUBS[tgt]
                    args=[u.reg_read(r) for r in (UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9)]
                    ret=fn(u,args)
                    if ret is None: ret=0
                    u.reg_write(UC_X86_REG_RAX, ret & 0xffffffffffffffff)
                    u.reg_write(UC_X86_REG_RIP, addr+5)   # skip the call
        self.uc.hook_add(UC_HOOK_CODE, code_hook)

    def _strnlen(self,u,a):
        ptr,mx=a[0],a[1]&0xffffffff
        data=u.mem_read(ptr, min(mx+1,0x40))
        n=data.find(b"\x00")
        return (mx if n<0 else n)
    def _align128(self,u,a):
        return ALIGN(a[0]&0xffffffff)
    def _stub_alloc(self,u,a):
        return self._alloc(a[0])
    def _memset(self,u,a):
        dst,val,n=a[0],a[1]&0xff,a[2]
        # cap to mapped arena to avoid writing into guard
        for b,s,mp in self.allocs:
            if b<=dst<b+mp:
                n=min(n, (b+mp)-dst); break
        if n and n<0x2000000:
            u.mem_write(dst, bytes([val])*n)
        return dst
    def _be240(self,u,a):
        # 0x6be240(rcx=ptr) registers a pointer in a global list.  At 0x6c9c58 the
        # ptr = g_tags + 12*tagcount + 32, computed from the attacker tag count.
        ptr=a[0]
        tagmem=struct.unpack("<Q", self.uc.mem_read(IMAGE_BASE+G_TAGMEM,8))[0]
        rip=u.reg_read(UC_X86_REG_RIP)
        self.log(f"    [be240] register ptr={ptr:#x}  (rip rva {rip-IMAGE_BASE:#x})"
                 + (f"  g_tagmem+{ptr-tagmem:#x}" if tagmem and ptr>tagmem else ""))
        return 0

    def _stub_read(self,u,a):
        # 0x67bbb0(ecx, edx=off, r8d=size, r9=dst)  -- the section reader.
        # Dump the register state here: this is the attacker's controlled-write
        # primitive.  dst(r9), size(r8d), off(edx) are all derived from .map
        # header fields, so they are attacker-controlled at this call site.
        off=a[1]&0xffffffff; size=a[2]&0xffffffff; dst=a[3]
        tagmem=struct.unpack("<Q", self.uc.mem_read(IMAGE_BASE+G_TAGMEM,8))[0]
        if not getattr(self,"_rc_shown",False):
            self.log("    --- REGISTER STATE at section-read call 0x6c9ad5 (controlled write) ---")
            self.log(f"      r9  (dst)  = {dst:#x}   = g_tagmem({tagmem:#x}) + {dst-tagmem:#x}")
            self.log(f"      r8d (size) = {size:#x}   = align128(hdr[+0x2d4])")
            self.log(f"      edx (foff) = {off:#x}   = hdr[+0x10]")
            self.log(f"      rcx        = {u.reg_read(UC_X86_REG_RCX):#x}")
            self.log(f"      write-dest offset-from-heap-base = {dst-tagmem:#x}  (= attacker hdr[+0x2d0], sign-extended)")
            self._rc_shown=True
        return self._read(off,size,dst)

    # ---- run ------------------------------------------------------------
    def run(self):
        u=self.uc
        sp=STACK_BASE+STACK_SIZE-0x400
        u.reg_write(UC_X86_REG_RSP, sp)
        u.mem_write(sp, struct.pack("<Q", RET_SENTINEL))
        u.reg_write(UC_X86_REG_RCX, 0)
        try:
            u.emu_start(IMAGE_BASE+FN_ENTRY, RET_SENTINEL, count=200000)
            self.log("[done] function returned, rax=%#x"%u.reg_read(UC_X86_REG_RAX))
        except UcError as e:
            rip=u.reg_read(UC_X86_REG_RIP); rva=rip-IMAGE_BASE
            self.fault=(e,rip)
            self.log(f"[FAULT] {e} @ rip={rip:#x} (rva {rva:#x})")
            try:
                ins=next(self.md.disasm(u.mem_read(rip,15),rip))
                self.log(f"        insn: {ins.mnemonic} {ins.op_str}")
            except Exception: pass
            self._dump_regs()

    def _dump_regs(self):
        u=self.uc
        for name,r in [("rax",UC_X86_REG_RAX),("rbx",UC_X86_REG_RBX),("rcx",UC_X86_REG_RCX),
                       ("rdx",UC_X86_REG_RDX),("rsi",UC_X86_REG_RSI),("rdi",UC_X86_REG_RDI),
                       ("r8",UC_X86_REG_R8),("r9",UC_X86_REG_R9),("r14",UC_X86_REG_R14),
                       ("r15",UC_X86_REG_R15)]:
            self.log(f"        {name}={u.reg_read(r):#x}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("dll"); ap.add_argument("hdr"); ap.add_argument("--trace",action="store_true")
    ap.add_argument("--fileimg",default=None,help="real crafted file bytes the section reads pull from")
    args=ap.parse_args()
    h=H2(args.dll,args.hdr,trace=args.trace,fileimg=args.fileimg)
    h.run()
    print("\n=== SUMMARY ===")
    for b,s,mp in h.allocs: print(f" alloc base={b:#x} req_size={s:#x} mapped={mp:#x}")
    for off,size,dst in h.reads: print(f" read off={off:#x} size={size:#x} dst={dst:#x}")
    if h.fault: print(f" FAULT: {h.fault[0]} @ {h.fault[1]:#x}")
