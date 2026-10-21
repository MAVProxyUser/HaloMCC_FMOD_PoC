#!/usr/bin/env python3
# From-scratch Unicorn harness for Halo 2 (halo2.dll) bitstream primitives.
# Drives the REAL decode leaf functions on attacker-controlled bitstream bytes
# with a guard (unmapped) page immediately after the destination buffer, so any
# out-of-bounds WRITE faults and is caught. Demonstrates the bound empirically.
import sys,struct,pefile
from unicorn import *
from unicorn.x86_const import *
DLL="/Users/kfinisterre/Library/Application Support/ReclaimerMac/prefix/drive_c/Program Files/Steam/steamapps/common/Halo The Master Chief Collection/halo2/halo2.dll"
IMAGE_BASE=0x180000000
STACK=0x7f0000000; STACK_SZ=0x100000
BS=0x200000000                 # c_bitstream struct
DATA=0x201000000               # bitstream data buffer
DATA_SZ=0x100000
DST_REGION=0x202000000         # dest buffer region; guard page right after the exact buffer
RET_SENTINEL=0x4444444444440000
PAGE=0x1000
def rvas(pe):
    base=pe.OPTIONAL_HEADER.ImageBase
    out=[]
    for s in pe.sections:
        out.append((base+s.VirtualAddress, s.Misc_VirtualSize, s.get_data()))
    return out
class H:
    def __init__(self):
        self.pe=pefile.PE(DLL,fast_load=True)
        self.uc=Uc(UC_ARCH_X86,UC_MODE_64)
        self.fault=None
        self._map_image()
        self.uc.mem_map(STACK,STACK_SZ)
        self.uc.mem_map(BS& ~(PAGE-1),PAGE)
        self.uc.mem_map(DATA,DATA_SZ)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED,self._bad)
    def _map_image(self):
        base=self.pe.OPTIONAL_HEADER.ImageBase
        size=self.pe.OPTIONAL_HEADER.SizeOfImage
        self.uc.mem_map(base, (size+PAGE-1)&~(PAGE-1))
        self.uc.mem_write(base, self.pe.header)
        for s in self.pe.sections:
            d=s.get_data()
            if d: self.uc.mem_write(base+s.VirtualAddress, d)
    def _bad(self,uc,access,addr,size,val,ud):
        rip=uc.reg_read(UC_X86_REG_RIP)
        if (addr & ~0xffff)==(RET_SENTINEL & ~0xffff):
            return False  # clean stop at sentinel return
        self.fault=(access,addr,size,val,rip)
        print("  !! MEM FAULT access=%d addr=0x%x size=%d rip_rva=0x%x"%(access,addr,size,rip-IMAGE_BASE))
        return False
    def setup_bitstream(self, data_bytes, size_bytes=None):
        self.uc.mem_write(DATA, b'\x00'*0x1000)
        self.uc.mem_write(DATA, data_bytes)
        if size_bytes is None: size_bytes=len(data_bytes)
        b=BS
        self.uc.mem_write(b, struct.pack("<Q",DATA))      # [+0]=data ptr
        self.uc.mem_write(b+8, struct.pack("<I",size_bytes)) # [+8]=size bytes
        self.uc.mem_write(b+0x10, b'\x00'*0x10)
        self.uc.mem_write(b+0x14, struct.pack("<I",0))    # [+0x14]=bit pos
        self.uc.mem_write(b+0x18, struct.pack("<I",0))    # [+0x18]=flag
    def call(self, rva, rcx=0,rdx=0,r8=0,r9=0):
        uc=self.uc; self.fault=None
        uc.reg_write(UC_X86_REG_RSP, STACK+STACK_SZ-0x200)
        uc.mem_write(STACK+STACK_SZ-0x200, struct.pack("<Q",RET_SENTINEL))
        uc.reg_write(UC_X86_REG_RCX,rcx); uc.reg_write(UC_X86_REG_RDX,rdx)
        uc.reg_write(UC_X86_REG_R8,r8); uc.reg_write(UC_X86_REG_R9,r9)
        try:
            uc.emu_start(IMAGE_BASE+rva, RET_SENTINEL, count=2_000_000)
        except UcError as e:
            if self.fault is None: self.fault=('ucerr',str(e),0,0,uc.reg_read(UC_X86_REG_RIP))
        return uc.reg_read(UC_X86_REG_RAX)

def map_guarded_dst(h, buf_bytes):
    # map a region, place dst so that dst+buf_bytes lands exactly at an unmapped guard page
    region=DST_REGION
    npages=(buf_bytes+PAGE-1)//PAGE
    # map npages, leave the next page UNMAPPED as guard
    h.uc.mem_map(region, npages*PAGE)
    dst=region+npages*PAGE-buf_bytes   # end of buffer == end of mapped == start of guard
    h.uc.mem_write(region, b'\xCC'*(npages*PAGE))
    return dst

print("=== halo2.dll bitstream primitive safety harness ===")
# TEST 1: core bit reader sub_741260 — request 32 bits from a 2-byte bitstream (EOF clamp)
h=H()
h.setup_bitstream(b'\xAA\xBB', size_bytes=2)
val=h.call(0x741260, rcx=BS, rdx=32)
pos=struct.unpack("<I",h.uc.mem_read(BS+0x14,4))[0]
print("T1 read_bits(32) from 2-byte stream -> val=0x%x bitpos=%d fault=%s"%(val,pos,h.fault))

# TEST 2: wide string reader sub_7416b0, max=0x80 (128 chars=256 bytes), all-0xFF stream (NO null)
h2=H()
dst=map_guarded_dst(h2, 0x100)   # 256-byte buffer, guard page immediately after
h2.setup_bitstream(b'\xFF'*0x2000, size_bytes=0x2000)   # plenty of non-null data
h2.call(0x7416b0, rcx=BS, rdx=0, r8=dst, r9=0x80)
last=struct.unpack("<H",h2.uc.mem_read(dst+0xFE,2))[0]
print("T2 read_wstring(max=128) all-0xFF -> dst[127]=0x%04x fault=%s"%(last,h2.fault))

# TEST 3 (POSITIVE CONTROL): prove the harness CAN detect an OOB write.
# Same 256-byte guarded buffer, but ask the SAME reader for 129 chars (r9=0x81).
# 129 chars = 258 bytes -> write to dst[128] lands on the guard page -> MUST fault.
# This shows (a) the guard mechanism works, and (b) the only thing bounding the
# write is the r9 length arg, which at every real call site is a compile-time
# constant <= the destination field size.
h3=H()
dst=map_guarded_dst(h3,0x100)     # 256-byte buffer, guard page at dst+256
h3.setup_bitstream(b'\xFF'*0x2000, size_bytes=0x2000)
h3.call(0x7416b0, rcx=BS, rdx=0, r8=dst, r9=0x81)   # 0x81 = 129 > buffer capacity
print("T3 POSITIVE CONTROL read_wstring(max=129) into 128-cap buf -> fault=%s"%(h3.fault,))
print("   (expected: a MEM FAULT at the guard page == harness detects OOB)")
print("=== done ===")
