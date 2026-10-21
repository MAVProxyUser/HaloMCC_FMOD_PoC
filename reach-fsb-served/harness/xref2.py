#!/usr/bin/env python3
"""Clean xref: disassemble each .pdata function separately (no linear desync).
Collect (a) direct calls to a target rva, (b) rip-relative refs to a target rva.
Report the containing function for each."""
import sys, struct, bisect; sys.path.insert(0,'.')
from pe import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_OP_IMM

def pdata(pe):
    s=[x for x in pe.sections if x["name"]==".pdata"][0]
    blob=pe.data[s["rawptr"]:s["rawptr"]+s["vsize"]]
    fns=[]
    for i in range(0,len(blob)-11,12):
        beg,end,unw=struct.unpack_from("<III",blob,i)
        if beg==0 and end==0: continue
        if end>beg and pe.rva2off(beg) is not None:
            fns.append((beg,end))
    fns.sort(); return fns

def scan(pe, call_target=None, rip_target=None, imm_val=None):
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    base=pe.image_base; fns=pdata(pe)
    out=[]
    for beg,end in fns:
        o=pe.rva2off(beg); code=pe.data[o:o+(end-beg)]
        for ins in md.disasm(code, base+beg):
            rvains=ins.address-base
            if call_target is not None and ins.mnemonic in ("call","jmp"):
                for op in ins.operands:
                    if op.type==X86_OP_IMM and op.imm-base==call_target:
                        out.append((beg,rvains,ins.mnemonic,ins.op_str))
            if rip_target is not None:
                for op in ins.operands:
                    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
                        if ins.address+ins.size+op.mem.disp-base==rip_target:
                            out.append((beg,rvains,ins.mnemonic,ins.op_str))
            if imm_val is not None:
                for op in ins.operands:
                    if op.type==X86_OP_IMM and op.imm==imm_val:
                        out.append((beg,rvains,ins.mnemonic,ins.op_str))
    return out

if __name__=="__main__":
    pe=PE(sys.argv[1]); mode=sys.argv[2]; val=int(sys.argv[3],0)
    kw={"call":"call_target","rip":"rip_target","imm":"imm_val"}[mode]
    res=scan(pe, **{kw:val})
    seen=set()
    for beg,r,m,o in res:
        print(f"  fn {beg:#x}  @ {r:#x}: {m} {o}")
    print(f"  total {len(res)} hits in {len(set(x[0] for x in res))} functions")
