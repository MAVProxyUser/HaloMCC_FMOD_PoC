#!/usr/bin/env python3
# Binary-hardening assessment of a PE. Read-only; parses headers with pefile.
import sys, pefile

p = pefile.PE(sys.argv[1], fast_load=True)
p.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
])

dc = p.OPTIONAL_HEADER.DllCharacteristics
flags = {
    'DYNAMIC_BASE (ASLR)':        0x0040,
    'FORCE_INTEGRITY':            0x0080,
    'NX_COMPAT (DEP)':            0x0100,
    'NO_ISOLATION':               0x0200,
    'NO_SEH':                     0x0400,
    'NO_BIND':                    0x0800,
    'APPCONTAINER':               0x1000,
    'WDM_DRIVER':                 0x2000,
    'GUARD_CF (CFG)':             0x4000,
    'HIGH_ENTROPY_VA':            0x0020,
    'TERMINAL_SERVER_AWARE':      0x8000,
}
print("== DllCharacteristics: 0x%04x ==" % dc)
for name, bit in flags.items():
    print("  [%s] %s" % ("x" if dc & bit else " ", name))

print("\n== Machine / subsystem ==")
print("  Machine         : 0x%x (%s)" % (p.FILE_HEADER.Machine,
      'x64' if p.FILE_HEADER.Machine == 0x8664 else hex(p.FILE_HEADER.Machine)))
print("  ImageBase       : 0x%x" % p.OPTIONAL_HEADER.ImageBase)
print("  SizeOfImage     : 0x%x" % p.OPTIONAL_HEADER.SizeOfImage)
print("  Subsystem       : %d" % p.OPTIONAL_HEADER.Subsystem)
print("  Characteristics : 0x%x (RELOCS_STRIPPED=%s)" %
      (p.FILE_HEADER.Characteristics, bool(p.FILE_HEADER.Characteristics & 0x1)))
reloc = p.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']]
print("  Has .reloc dir  : %s (size 0x%x)  -> ASLR actually usable: %s" %
      (reloc.VirtualAddress != 0, reloc.Size, (dc & 0x40) and reloc.Size > 0))

print("\n== Load Config (CFG / GS / SEH) ==")
lc = getattr(p, 'DIRECTORY_ENTRY_LOAD_CONFIG', None)
if not lc:
    print("  (no load config directory)")
else:
    s = lc.struct
    def g(n): return getattr(s, n, None)
    cookie = g('SecurityCookie')
    print("  SecurityCookie (/GS)       : %s" % (hex(cookie) if cookie else "none"))
    seh_t = g('SEHandlerTable'); seh_c = g('SEHandlerCount')
    print("  SEHandlerTable/Count       : %s / %s" %
          (hex(seh_t) if seh_t else "0", seh_c))
    gcf_t = g('GuardCFFunctionTable'); gcf_c = g('GuardCFFunctionCount')
    gflags = g('GuardFlags')
    print("  GuardCFFunctionTable/Count : %s / %s" %
          (hex(gcf_t) if gcf_t else "0", gcf_c))
    print("  GuardFlags                 : %s" % (hex(gflags) if gflags is not None else "n/a"))
    print("  GuardAddressTakenIatEntryTable: %s" % (hex(g('GuardAddressTakenIatEntryTable') or 0)))
    print("  GuardLongJumpTargetTable      : %s" % (hex(g('GuardLongJumpTargetTable') or 0)))

print("\n== Authenticode signature ==")
sec = p.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
print("  Signed (cert dir present): %s (size 0x%x)" % (sec.Size > 0, sec.Size))

print("\n== Sections (W^X check) ==")
RWX = []
for sec in p.sections:
    ch = sec.Characteristics
    r = bool(ch & 0x40000000); w = bool(ch & 0x80000000); x = bool(ch & 0x20000000)
    perm = ("r" if r else "-") + ("w" if w else "-") + ("x" if x else "-")
    nm = sec.Name.rstrip(b"\x00").decode('latin1')
    print("  %-10s va=0x%08x vsz=0x%08x  %s" % (nm, sec.VirtualAddress, sec.Misc_VirtualSize, perm))
    if w and x:
        RWX.append(nm)
print("  RWX sections: %s" % (RWX if RWX else "none (good)"))

print("\n== TLS ==")
tls = getattr(p, 'DIRECTORY_ENTRY_TLS', None)
print("  Has TLS directory: %s" % (tls is not None))

print("\n== Imports (Win32 surface the codec path may need) ==")
if hasattr(p, 'DIRECTORY_ENTRY_IMPORT'):
    for d in p.DIRECTORY_ENTRY_IMPORT:
        names = [imp.name.decode() if imp.name else ("ord#%d" % imp.ordinal) for imp in d.imports]
        print("  %s (%d): %s" % (d.dll.decode(), len(names), ", ".join(names[:12]) + (" ..." if len(names) > 12 else "")))
else:
    print("  (no imports)")

print("\n== Exports ==")
if hasattr(p, 'DIRECTORY_ENTRY_EXPORT') and p.DIRECTORY_ENTRY_EXPORT.symbols:
    syms = [e.name.decode() if e.name else ("ord#%d" % e.ordinal) for e in p.DIRECTORY_ENTRY_EXPORT.symbols]
    print("  %d exports: %s" % (len(syms), ", ".join(syms[:20]) + (" ..." if len(syms) > 20 else "")))
else:
    print("  no exports (FMOD is internal; must call by RVA)")
