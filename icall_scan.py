#!/usr/bin/env python3
# Recursively (bounded) disassemble from an entry RVA, following direct calls,
# and report every INDIRECT call/jmp (ff /2, ff /3, ff /4, ff /5 via reg or
# [reg+disp], excluding rip-relative) -- the corruptible control-transfer sinks.
import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG

PATH=sys.argv[1]; ENTRY=int(sys.argv[2],0)
MAXFUNC=int(sys.argv[3]) if len(sys.argv)>3 else 60
p=pefile.PE(PATH); base=p.OPTIONAL_HEADER.ImageBase
img=p.get_memory_mapped_image(ImageBase=base); size=len(img)
secs=[(s.Name.rstrip(b"\0").decode('latin1'),s.VirtualAddress,s.VirtualAddress+s.Misc_VirtualSize,bool(s.Characteristics&0x20000000)) for s in p.sections]
def execok(r):
  for nm,a,b,x in secs:
    if a<=r<b: return x
  return False
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

seen=set(); queue=[ENTRY]; order=[]
icalls=[]
while queue and len(seen)<MAXFUNC:
    f=queue.pop(0)
    if f in seen or not execok(f): continue
    seen.add(f); order.append(f)
    code=img[f:f+0x1400]
    for ins in md.disasm(code, base+f):
        m=ins.mnemonic
        # stop at terminal padding
        if m=="int3": break
        if m=="call":
            op=ins.operands[0]
            if op.type==CS_OP_REG:
                icalls.append((ins.address-base, f, "call %s"%ins.reg_name(op.reg)))
            elif op.type==CS_OP_MEM:
                b_=ins.reg_name(op.mem.base or 0); i_=ins.reg_name(op.mem.index or 0)
                if b_=="rip":
                    pass  # fixed import/vtable-in-image, not attacker-corruptible via heap
                else:
                    icalls.append((ins.address-base, f, "call [%s%s+0x%x]"%(b_, ("+%s*%d"%(i_,op.mem.scale) if i_ else ""), op.mem.disp & 0xffffffffffffffff)))
                    continue
            else:
                try:
                    t=int(ins.op_str,16)-base
                    if execok(t) and t not in seen and t not in queue and len(seen)+len(queue)<MAXFUNC*2:
                        queue.append(t)
                except: pass
        elif m=="jmp":
            op=ins.operands[0]
            if op.type==CS_OP_REG:
                icalls.append((ins.address-base, f, "JMP %s"%ins.reg_name(op.reg)))
            elif op.type==CS_OP_MEM and ins.reg_name(op.mem.base or 0)!="rip":
                b_=ins.reg_name(op.mem.base or 0)
                icalls.append((ins.address-base, f, "JMP [%s+0x%x]"%(b_, op.mem.disp & 0xffffffff)))
            else:
                # tail-call: follow direct jmp target as a function
                try:
                    t=int(ins.op_str,16)-base
                    if execok(t) and t not in seen and t not in queue: queue.append(t)
                except: pass

print("explored %d functions from 0x%x" % (len(seen), ENTRY))
print("indirect control transfers via register/heap (CFG off => unvalidated):")
for site, fn, desc in icalls:
    print("  0x%-8x (in func 0x%-8x)  %s" % (site, fn, desc))
if not icalls:
    print("  (none found in explored set)")
