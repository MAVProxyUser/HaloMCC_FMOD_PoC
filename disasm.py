#!/usr/bin/env python3
# Linear disassembly of a function with annotations: rip-relative targets,
# direct call targets, and FLAGGED indirect call/jmp (PC-control candidates).
import sys, pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, CS_GRP_JUMP, CS_GRP_CALL

PATH=sys.argv[1]; FUNC=int(sys.argv[2],0); NINS=int(sys.argv[3]) if len(sys.argv)>3 else 160
p=pefile.PE(PATH); base=p.OPTIONAL_HEADER.ImageBase
img=p.get_memory_mapped_image(ImageBase=base); size=len(img)
secs=[(s.Name.rstrip(b"\0").decode('latin1'),s.VirtualAddress,s.VirtualAddress+s.Misc_VirtualSize,bool(s.Characteristics&0x20000000)) for s in p.sections]
def sec_of(r):
  for nm,a,b,x in secs:
    if a<=r<b: return nm,x
  return "?",False
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
blob=img[FUNC:FUNC+NINS*12]
n=0; indirects=[]; calls=[]
for ins in md.disasm(blob, base+FUNC):
  n+=1
  ann=""
  # rip-relative memory
  for op in ins.operands:
    if op.type==CS_OP_MEM and ins.reg_name(op.mem.base or 0)=="rip":
      tgt=ins.address+ins.size+op.mem.disp-base; nm,x=sec_of(tgt)
      ann+="  ; [rip]->0x%x (%s%s)"%(tgt,nm,"/x" if x else "")
  m=ins.mnemonic
  if m=="call":
    op=ins.operands[0]
    if op.type==CS_OP_REG:
      ann+="  ; **INDIRECT CALL via %s**"%ins.reg_name(op.reg); indirects.append((ins.address-base,ins.op_str))
    elif op.type==CS_OP_MEM and ins.reg_name(op.mem.base or 0)!="rip":
      ann+="  ; **INDIRECT CALL [mem]**"; indirects.append((ins.address-base,ins.op_str))
    elif op.type==CS_OP_MEM:
      pass
    else:
      try:
        t=int(ins.op_str,16)-base; calls.append(t); ann+="  ; call 0x%x"%t
      except: pass
  if m in ("jmp",) and ins.operands[0].type in (CS_OP_REG,) :
    ann+="  ; **INDIRECT JMP via %s**"%ins.reg_name(ins.operands[0].reg); indirects.append((ins.address-base,ins.op_str))
  if m=="jmp" and ins.operands[0].type==CS_OP_MEM and ins.reg_name(ins.operands[0].mem.base or 0)!="rip":
    ann+="  ; **INDIRECT JMP [mem]**"; indirects.append((ins.address-base,ins.op_str))
  print("0x%06x: %-9s %-34s%s" % (ins.address-base, m, ins.op_str, ann))
  if n>=NINS: break
  # stop at obvious function end (int3 padding / ret followed by int3)
print("\n--- direct calls: %s" % sorted(set("0x%x"%c for c in calls)))
print("--- INDIRECT control transfers (%d): %s" % (len(indirects), indirects))
