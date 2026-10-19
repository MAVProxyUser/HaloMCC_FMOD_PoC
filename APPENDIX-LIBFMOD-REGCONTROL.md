# Native-macOS register control in standalone `libfmod.dylib` + hardening (usable/unusable)

Authorized MSRC/CVP security research local only on the user's own
Apple-Silicon Mac. Companion to `TECHNICAL-ANALYSIS.md`. This proves the FSB5
memory-corruption primitive **directly in Firelight's shipped `libfmod.dylib`** — real FMOD code,
code-signed by `TeamIdentifier=FNXNE97GV7`, run **natively on arm64** under `lldb` (no Unicorn
emulation, no Rosetta, no `halo3.dll`) — and outlines exactly which process/binary mitigations make
that control usable vs unusable.

Evidence log (reproducible): [`libfmod-regcontrol.log`](libfmod-regcontrol.log). Target:
`downloads/fmod_2_02_22_laguna/libfmod.dylib` (FMOD **2.02.22**, 8 May 2024),
`sha256 67b100ec…a8dd0caa`. Driver: `fsb5_probe` driving
`System::createSound(bank, 0x2080 = OPENONLY|CREATESTREAM, NULL)` — the exact MCC load call.

---

## 1. Register control — CONFIRMED (native arm64, under lldb)

Two crafted banks give two distinct, attacker-controlled fault states inside FMOD's own FSB5
sample-table builder (one function, `libfmod` unnamed symbol `b51f0`, reached
`createSound → …(b53d4/b819c0/b80f94)→ b51f0`):

### RUN A — `poc_v2` (numSamples*4 32-bit integer overflow): controlled OOB **write**
```
stop: EXC_BAD_ACCESS (code=2 WRITE)  address = 0x100968000
pc  = libfmod`b51f0 + 196   ->  str  w10, [x0, x8, lsl #2]        ; offsetTab[x8] = w10
  x0  = 0x100579bb8   ; base of the UNDER-allocated sample-offset table
  x8  = 0x000fb912    ; loop index i  (loop trip count = numSamples = 0x7fffffff, attacker +0x08)
  x10 = 0x0153af8f    ; value written (walked from the blob via x9: ldrb/ldr [x9])
  x0 + (x8<<2) = 0x100968000   == the fault address (page-aligned -> ran off the table)
```
`numSamples` (file `+0x08`) is multiplied by 4 as a **32-bit** value to size the table, so the
allocation wraps/under-sizes while the populate loop still indexes `i = 0 … numSamples`. The store
`str w10,[x0,x8,lsl#2]` therefore walks `x8` past the buffer until it hits the first unmapped page.
**Attacker controls the write extent** (via `numSamples`) **and the written value** (`w10`, loaded
from the attacker blob the loop walks through `x9`). This is a linear heap overflow with
attacker-controlled length and payload.

### RUN B — `poc_v3` (type-6 chunk, 24-bit `size`): attacker-controlled **dereference address**
```
stop: EXC_BAD_ACCESS                 address = 0xb2b800000
pc  = libfmod`b51f0 + 240   ->  ldr  w14, [x13] ; str w14, [x13], #0x4
  x13 = 0x0b2b800000   ; the walk pointer == the fault address (≈ 48 GiB off base)
  x11 = 0x00ffffff     ; 0xffffff = the 24-bit chunk-size field mask in play
  x9  = 0x0b2b005914   ; sibling walk pointer, same attacker magnitude
```
Here the per-chunk advance `ptr += size` (24-bit attacker `size`, unbounded) drives the walk pointer
`x13` to an **attacker-magnitude address**, and the read/write through `x13` faults there. The
dereferenced address register is attacker-controlled — the same primitive the from-scratch loader
showed against `halo3.dll` as `fault = buffer + attacker_size` (canonical report §6.2).

**So on the shipped arm64 `libfmod`, an attacker controls, at the fault: the OOB write index/extent
and written value (RUN A), and the dereferenced address register (RUN B).** Register/▶memory-access
control is proven natively. (`poc_v5`'s exact byte-addressed variant returns `FMOD_ERR_VERSION` on
2.01.09/2.02.22 — a later sub-format version gate — but `poc_v2`/`poc_v3` pass it and corrupt memory;
the gate does not cover the overflow, consistent with sdk-bisect §5.2.)

### What is NOT single-shot reachable here: full PC (`pc = 0x4141…`) control
`halo3.dll` reached arbitrary **RIP** because its decode dispatcher `readData` does
`call [instance+0xa8]` **after** a sound object exists (canonical report §7.1). That sink is the same
FMOD code and is present in `libfmod` too (as a plain `blr`, see §2), but reaching it needs
`createSound` to *succeed* and leave a **corrupted codec function pointer** — a heap-groom across
objects, not a single malformed file. With these inputs `createSound` faults *during* parsing (RUN
A/B) before any codec object is callable. So the native-lib result proves the **corruption primitive
and that the control-transfer sink is unauthenticated**; the end-to-end `blr`-hijack is the same
engineering groom already argued in §7.2, not a one-file demo.

---

## 2. Hardening — what makes the control usable vs unusable

Measured on the actual `libfmod.dylib` arm64 slice (+ the process/OS context), compared to the
Windows `halo3.dll` posture in §3 of the canonical report.

| Mitigation | State on this `libfmod` / macOS | Effect on the proven primitive |
|---|---|---|
| **PAC** (ARM pointer authentication) | **ABSENT.** Slice is plain `arm64` (`CPU_SUBTYPE_ARM64_ALL`, capabilities `0x0`), **not** `arm64e`; **0** `pac*/aut*/braa/blraa/retab` instructions in the whole slice; all **1200** indirect branches are plain `blr/br xN`. | **USABLE.** A corrupted function pointer / vtable reached by the parser transfers control through an **unauthenticated** `blr` — the arm64 analogue of Windows **CFG-off**. Nothing validates the branch target. |
| **CFG** (Control Flow Guard) | **N/A** — a Windows/PE feature; no Mach-O equivalent, and none under Rosetta for the x86_64 slice. | **USABLE** (same as `halo3.dll`, where `GUARD_CF` is off). |
| **Stack canary** (`__stack_chk_guard`) | **Present** in `libfmod`. | **Irrelevant** to this bug — the corruption is a **heap/data** OOB write, not a stack-frame return overwrite (mirrors the §3 "/GS partial" note). |
| **DEP / NX** | **ON.** `__TEXT` maxprot `r-x` (`0x5`), `__DATA`/`__DATA_CONST` `rw-` (`0x3`), no RWX. | Blocks shellcode-in-data; code execution needs **ROP/JOP** (same as `halo3.dll`). |
| **ASLR / PIE** | **ON.** Dylib is position-independent; dyld randomizes the base — observed empirically, the load base moved across runs (`0x104c04000` / `0x104be8000` / `0x104cd4000`). | **UNUSABLE without an info leak.** Weaponizing the unauthenticated `blr` needs an absolute target, i.e. a leak to recover `libfmod`/heap base. |
| **Hardened runtime / library validation / code signing** | **ON** (`flags=0x10000 runtime`, `TeamIdentifier=FNXNE97GV7`). | **No effect on this bug class** — these gate loading a *malicious dylib* or JIT/code injection, not in-process data-driven corruption. Neither help nor hinder. |

### Usable vs unusable — the bottom line
* **Usable (the corruption and the sink):** the register/memory-write control is real and native; and
  because the arm64 slice has **no PAC** (and Mach-O has no CFG), the control-transfer sink — a plain
  `blr` through a function pointer — is **unauthenticated**, exactly like the CFG-off
  `call [instance+0xa8]` in `halo3.dll`. DEP only forces ROP/JOP; the stack canary doesn't cover the
  heap write.
* **Unusable (the wall):** **ASLR** is the gate. Turning the unauthenticated `blr` into a chosen
  `pc` needs an absolute address, i.e. an **information leak** — and both leak tracks are **negative**
  (the transport/netcode protocol discloses no pointer, and the FMOD OOB-read reflection does not
  reach the server; canonical report §7.3). So on this hardened build the primitive stops at
  **controlled memory corruption + an unauthenticated control-transfer sink**; end-to-end
  **PC-controlled RCE is not achievable without an out-of-band ASLR-defeat** not supplied by this bug.
* **The one mitigation that *would* make it unusable even with a leak** is **PAC**: had `libfmod`
  (and MCC's Windows build) shipped as **`arm64e`** / with CFG, the corrupted-pointer `blr` would be a
  `blraa` (authenticated) / CFG-checked indirect call, and the function-pointer hijack would require a
  separate PAC-signing-gadget or CFG bypass. This build has **neither** — which is precisely why the
  sink is open.

This reproduces, on a **second CPU architecture and OS**, the same conclusion as the Windows analysis:
a proven controlled-corruption primitive into an **unauthenticated indirect-branch sink**, gated only
by **ASLR** (with no working info leak), so honestly bounded at *remote DoS + memory corruption +
arbitrary-control-transfer sink* rather than demonstrated RCE on hardened builds.

---

## 3. Reproduction
```bash
cd sdk-bisect
D=downloads/fmod_2_02_22_laguna/libfmod.dylib          # FMOD 2.02.22, arm64 slice (native)
# RUN A — controlled OOB write
lldb -b -o run -o "register read pc x0 x8 x10" -o "disassemble --pc" -o quit \
  -- fsb5_probe $D ../poc_v2_numsamples_oob.fsb 0x2080 0x00020222
# RUN B — attacker-controlled dereference address
lldb -b -o run -o "register read pc x11 x13" -o "disassemble --pc" -o quit \
  -- fsb5_probe $D ../poc_v3_type6_bigsize.fsb 0x2080 0x00020222
# Hardening: PAC must be 0, blr/br many, slice must be plain arm64
otool -arch arm64 -tv $D | grep -cE '\b(pacia|pacibsp|braa|blraa|retab)\b'   # -> 0  (no PAC)
otool -arch arm64 -tv $D | grep -cE '\b(blr|br)\s+x[0-9]+'                    # -> ~1200 plain
lipo -detailed_info $D | grep -A2 'architecture arm64$'                        # cpusubtype ARM64_ALL
```

## 4. Artifacts
* `libfmod-regcontrol.log` — full captured lldb runs (A + B) + the hardening probes.
* driver `fsb5_probe[.c]`; samples `poc_v2_numsamples_oob.fsb`,
  `poc_v3_type6_bigsize.fsb`. The `libfmod.dylib` binaries themselves are third-party
  Firelight files, not redistributed (see `FMOD-SDK-BINARIES.txt`).
