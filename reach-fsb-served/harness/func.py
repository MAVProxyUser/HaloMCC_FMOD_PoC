#!/usr/bin/env python3
"""Parse .pdata RUNTIME_FUNCTION table; find/disassemble the function containing an RVA."""
import sys, struct, bisect
sys.path.insert(0,'.')
from pe import PE
from capstone import Cs,CS_ARCH_X86,CS_MODE_64

def pdata(pe):
    s=[x for x in pe.sections if x["name"]==".pdata"][0]
    blob=pe.data[s["rawptr"]:s["rawptr"]+s["vsize"]]
    fns=[]
    for i in range(0,len(blob)-11,12):
        beg,end,unw=struct.unpack_from("<III",blob,i)
        if beg==0 and end==0: continue
        fns.append((beg,end,unw))
    fns.sort()
    return fns

def func_of(fns, rva):
    begs=[f[0] for f in fns]
    i=bisect.bisect_right(begs,rva)-1
    if i>=0 and fns[i][0]<=rva<fns[i][1]:
        return fns[i]
    return None

def disf(pe, beg, end, md=None, maxins=400):
    if md is None:
        md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    o=pe.rva2off(beg)
    code=pe.data[o:o+(end-beg)]
    out=[]
    for ins in md.disasm(code, pe.image_base+beg):
        out.append(ins)
        if len(out)>=maxins: break
    return out

if __name__=="__main__":
    pe=PE(sys.argv[1])
    fns=pdata(pe)
    rva=int(sys.argv[2],0)
    f=func_of(fns,rva)
    if not f:
        print(f"no pdata function for {rva:#x}"); sys.exit(1)
    beg,end,unw=f
    print(f"function {beg:#x}..{end:#x} (size {end-beg:#x}) contains {rva:#x}")
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    for ins in disf(pe,beg,end,md):
        mark=" <==" if ins.address==pe.image_base+rva else ""
        print(f"  {ins.address:#x}: {ins.mnemonic:8} {ins.op_str}{mark}")
