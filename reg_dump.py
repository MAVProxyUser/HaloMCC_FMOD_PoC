#!/usr/bin/env python3
# Disassemble FMOD codec registration (RVA given) and extract every codec
# descriptor pointer it passes (RIP-relative LEA into .data/.rdata), then dump
# each descriptor's name string + open/read callback RVAs.
import sys, struct, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM

PATH = sys.argv[1]
REG_RVA = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x4630d0
p = pefile.PE(PATH)
base = p.OPTIONAL_HEADER.ImageBase
img = p.get_memory_mapped_image(ImageBase=base)
size = len(img)
secs = []
for s in p.sections:
    nm = s.Name.rstrip(b"\0").decode('latin1')
    secs.append((nm, s.VirtualAddress, s.VirtualAddress+s.Misc_VirtualSize, bool(s.Characteristics & 0x20000000)))
def sec_of(rva):
    for nm,a,b,x in secs:
        if a<=rva<b: return nm,x
    return None,False
def qword(rva):
    if 0<=rva and rva+8<=size: return struct.unpack_from("<Q", img, rva)[0]
    return None
def cstr(rva, n=32):
    if not (0<=rva<size): return None
    e=img.find(b"\0", rva, rva+n)
    if e==-1: e=rva+n
    try: return img[rva:e].decode('latin1')
    except: return None

md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

# Disassemble up to 0x1200 bytes of the registration function, collect LEA RIP-rel targets
code = img[REG_RVA:REG_RVA+0x1600]
lea_targets = []
calls = []
for ins in md.disasm(code, base+REG_RVA):
    if ins.mnemonic == "lea":
        for op in ins.operands:
            if op.type == CS_OP_MEM and op.mem.base == 0x1a + 0:  # rip base? use reg name check below
                pass
        # simpler: capstone sets rip-relative via op.mem.base == X86_REG_RIP
        for op in ins.operands:
            if op.type == CS_OP_MEM:
                # compute target = next_ip + disp when base is RIP
                reg = ins.reg_name(op.mem.base) if op.mem.base else None
                if reg == "rip":
                    tgt = ins.address + ins.size + op.mem.disp - base
                    lea_targets.append((ins.address-base, ins.reg_name(ins.operands[0].reg) if ins.operands[0].type==1 else "?", tgt))
    if ins.mnemonic == "call":
        calls.append(ins.address-base)
    # stop if we hit a long run of int3 padding
    if ins.mnemonic == "ret" and (ins.address-base) - REG_RVA > 0x40:
        # keep going a little; registration may have several rets — don't stop hard
        pass

print("reg func @ rva 0x%x : %d LEA-rip targets, %d calls" % (REG_RVA, len(lea_targets), len(calls)))

OFF_NAME=0x00; OFF_VER=0x08; OFF_OPEN=0x18; OFF_CLOSE=0x20; OFF_READ=0x28; OFF_GETWAVE=0x50
seen=set()
for site, dst, tgt in lea_targets:
    nm,_ = sec_of(tgt)
    if nm not in (".data", ".rdata", "_RDATA"): continue
    # does this look like a codec descriptor? name field -> a readable short ASCII string in .rdata
    nameptr = qword(tgt+OFF_NAME)
    if nameptr is None: continue
    nrva = nameptr - base
    s = cstr(nrva)
    opn = qword(tgt+OFF_OPEN)
    if not (s and all(32<=ord(c)<127 for c in s) and 1<=len(s)<=24 and opn): continue
    orva = opn - base; onm, ox = sec_of(orva)
    if not (onm and ox): continue
    if tgt in seen: continue
    seen.add(tgt)
    rd = qword(tgt+OFF_READ); gw = qword(tgt+OFF_GETWAVE)
    print("\n[descriptor @ rva 0x%x]  (lea at 0x%x -> %s)" % (tgt, site, dst))
    print("   name    = \"%s\"  (rva 0x%x)" % (s, nrva))
    print("   version = 0x%x" % (qword(tgt+OFF_VER) or 0))
    print("   open    = rva 0x%x (%s%s)" % (orva, onm, "/exec" if ox else ""))
    if rd:
        rrva=rd-base; rnm,rx=sec_of(rrva); print("   read    = rva 0x%x (%s)" % (rrva, rnm))
    if gw:
        grva=gw-base; gnm,gx=sec_of(grva); print("   getwave = rva 0x%x (%s)" % (grva, gnm))
