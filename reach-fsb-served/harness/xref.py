#!/usr/bin/env python3
"""Find direct-call xrefs (E8 rel32) to a target RVA, and rip-relative
memory refs (any opcode) that resolve to a target RVA, across .text."""
import sys; sys.path.insert(0,'.')
from pe import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_OP_MEM,CS_GRP_CALL,CS_GRP_JUMP
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

def callers(pe, target_rva, also_jmp=True):
    """scan .text linearly for e8/e9 rel32 to target."""
    s=[x for x in pe.sections if x["name"]==".text"][0]
    base=pe.image_base; tgt=base+target_rva
    data=pe.data; raw=s["rawptr"]; rsz=s["rawsize"]; va=s["vaddr"]
    hits=[]
    for i in range(raw, raw+rsz-5):
        b=data[i]
        if b==0xE8 or (also_jmp and b==0xE9):
            rel=int.from_bytes(data[i+1:i+5],'little',signed=True)
            ins_va=base+va+(i-raw)
            if ins_va+5+rel==tgt:
                hits.append((va+(i-raw), 'call' if b==0xE8 else 'jmp'))
    return hits

def riprefs(pe, target_rva):
    """full disasm of .text, collect instructions whose mem operand is rip-relative to target."""
    s=[x for x in pe.sections if x["name"]==".text"][0]
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    base=pe.image_base; code=pe.data[s["rawptr"]:s["rawptr"]+s["rawsize"]]
    tgt=base+target_rva; hits=[]
    for ins in md.disasm(code, base+s["vaddr"]):
        for op in ins.operands:
            if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                ea=ins.address+ins.size+op.mem.disp
                if ea==tgt:
                    hits.append((ins.address-base, ins.mnemonic, ins.op_str))
    return hits

if __name__=="__main__":
    pe=PE(sys.argv[1]); mode=sys.argv[2]; rva=int(sys.argv[3],0)
    if mode=="call":
        for r,k in callers(pe,rva): print(f"  {k} from rva {r:#x}")
    elif mode=="rip":
        for r,m,o in riprefs(pe,rva):
            kind="WRITE" if (o.split(',')[0].strip().startswith('[') or ('[rip' in o.split(',')[0])) else "read/lea"
            print(f"  rva {r:#x}: {m} {o}   [{kind}]")
