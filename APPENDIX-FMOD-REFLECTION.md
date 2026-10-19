# FMOD OOB-read → ASLR-defeat reflection experiment — findings

Authorized MSRC/CVP security research local only on the user's own
machine. Companion to the canonical report `TECHNICAL-ANALYSIS.md` (not edited here) and to
the client-side leak hunt [`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md). This
file answers the one route that both prior tracks left open: **can the proven controlled OOB *read*
in FMOD's FSB5 parser be turned into an ASLR-defeating information leak that reaches the
attacker-controlled server?**

Evidence log: [`fmod-reflection-SQ1.log`](fmod-reflection-SQ1.log). Crafted sample:
[`poc_v6_leak_reflect.fsb`](poc_v6_leak_reflect.fsb). Crafter:
[`craft_leak.py`](craft_leak.py). Harness instrument (env-gated, OFF by default):
the `RAWLOAD_LEAK` mode added to [`rawload.py`](rawload.py).

---

## TL;DR verdict — **NOT CONFIRMED** (the leak does not reach the server)

The three links of the FMOD-reflection ASLR-defeat chain resolve as:

| # | Link | Result | How established |
|---|---|---|---|
| **1** | OOB read can be **non-faulting** and pointed at a **pointer** | **CONFIRMED** | **Dynamically**, real `halo3.dll` code in the Unicorn loader |
| **2** | Those bytes **surface in FMOD API output** | **PARTIAL** | RE + dynamic: the in-scope sample-header primitive surfaces only **quantized / ≤32-bit** values; a **full-pointer** reflection exists only via a *different* primitive (readData PCM copy) |
| **3** | The engine **forwards** any of those to the server | **BREAKS** | **Static RE** + cross-ref to the netcode track: no server-observable field carries them |

**Net:** the controlled OOB read is a genuine, non-faulting, attacker-offset-targeted info-leak
*primitive* (link 1 is real and now demonstrated against planted pointer bytes). But there is **no
in-engine path that both preserves a full 64-bit pointer and forwards it to the attacker-controlled
server**. For the specific primitive named in the tasking (the `poc_v5` sample-header-walk over-read,
builder `halo3+0x4e92e0`), the pointer is already destroyed at link 2 (it is consumed as quantized
chunk metadata); for the one path that *does* reflect raw bytes (the `readData` PCM memcpy), link 3
breaks because decoded audio is a **client-local** effect that is never serialized to the wire.

So the FMOD-reflection route — the last credible ASLR-defeat vector after the protocol track came up
empty — **is not a working leak under this threat model.** The finding therefore stays at **remote
DoS + local memory corruption with a proven CFG-unguarded RIP sink** (arbitrary RIP is already shown
in the canonical report §7.1); it does **not** upgrade to remote RCE on `HIGH_ENTROPY_VA` builds via
this vector. One residual that RE here did not exhaustively close is noted in §4.

---

## 0. Threat model (unchanged, correct version)

The attacker **controls the dedicated server**, is the **QUIC endpoint**, and therefore **decrypts
everything the client sends**. Wire encryption is irrelevant. A leak "reaches the attacker" iff some
byte **derived from the over-read** is placed into a **client→server** (or replicated) protocol field
the server observes in plaintext. The corrupting second bank then weaponises the leaked address
(§7.2/§7.3 of the canonical report). We need a *read-only* first bank whose over-read bytes come back.

The controlled read primitive (canonical report §4.2, §6.2): in the FSB5 sample-header walk
`halo3+0x4e92e0`, `r10 += size` steps by an attacker 24-bit chunk `size` field with no bound, and the
next iteration dereferences `*r10`. The dereference address is `blob + Σ(size)` — **attacker
controlled to the byte** (`poc_v5`: `fault_addr - blob == size`, exactly). The open question was
whether that read can be made *non-faulting* and *reflected*.

---

## 1. SQ1 — CAN THE OOB READ BE NON-FAULTING AND POINTED AT A POINTER?  **CONFIRMED (dynamic)**

### Method
A new **env-gated** mode (`RAWLOAD_LEAK=1`, OFF by default, mirrors the `PELOAD_*` convention) was
added to the from-scratch Unicorn loader. When set, the allocator places the FSB sample-header
**blob** at the start of a large contiguous arena with **no guard page** (so a near-distance OOB read
lands in *mapped* memory instead of faulting), and plants a recognisable **adjacent FMOD object** at
`blob + RAWLOAD_LEAK_DELTA` holding real pointer-bearing bytes — a live `halo3` `.text` pointer
(`0x180500e00`, i.e. `readData`) at `+0x00`/`+0x80`/`+0xa8` (vtable / decoder fn-ptrs) and a heap
pointer (`0x00007ff612345678`) at `+0x160`. A `UC_HOOK_MEM_READ` records every read the **real FMOD
parser code** performs into that planted region. The sample `poc_v6_leak_reflect.fsb` sizes the walk
so the dereference lands exactly at `blob + DELTA`.

```bash
# craft + drive the REAL halo3 FSB parser with a mapped, pointer-bearing neighbour
./uenv/bin/python -I craft_leak.py  0x2a0000
RAWLOAD_LEAK=1 ./uenv/bin/python -I rawload.py halo3.dll poc_v6_leak_reflect.fsb
```

### Result (from `fmod-reflection-SQ1.log`)
```
[leak] planted adjacent FMOD object @ 0x3002a2000 (= blob 0x300002000 + 0x2a0000)
[leak]   +0x00 vtable       = 0x0000000180500e00  (halo3 .text, ASLR'd base)
...
==================== LEAK-REFLECTION (SQ1) ====================
  >>> the real FMOD parser READ planted pointer bytes at attacker-chosen
      offsets WITHOUT faulting (OOB read landed in MAPPED memory):
    halo3+0x4e9400 read 4 byte(s) @ 0x3002a2000  (blob+0x2a0000)  = 0x80500e00
    halo3+0x4ea280 read 4 byte(s) @ 0x3002a2000  (blob+0x2a0000)  = 0x80500e00
    halo3+0x4ea440 read 4 byte(s) @ 0x3002a2000  (blob+0x2a0000)  = 0x80500e00
[=] open() returned to sentinel cleanly.
```

Three distinct instructions in the **real `halo3.dll`** FSB codec read the low dword of the planted
`.text` pointer (`0x80500e00`) from `blob+0x2a0000` — the sample-header-walk chunk read
(`halo3+0x4e9400`), the per-sample base/chunk parser (`halo3+0x4ea280`, inside `0x4ea150`), and the
per-sample getter (`halo3+0x4ea440`, inside `0x4ea400`). **No fault**; `open()` ran to completion.

**Offset is fully attacker-controlled.** Re-running with `RAWLOAD_LEAK_DELTA=0x100000` and a sample
crafted for that distance moved every read to `blob+0x100000` on command (run B in the log). The
distance equals the input's 24-bit `size` field byte-for-byte (canonical report §6.2).

**The map-vs-fault contrast is the whole point.** The *same file* `poc_v6_leak_reflect.fsb` run
**without** `RAWLOAD_LEAK` faults at `halo3+0x4e9400` (the adjacent page is unmapped — a guard page).
With leak mode the adjacent page is mapped and the identical read returns the planted bytes cleanly.
In a real process the heap *is* mapped at near distances, so the near OOB read is non-faulting there
too. **SQ1 is confirmed: the OOB read can be non-faulting and made to read a known pointer's bytes.**

---

## 2. SQ2 — DO THOSE BYTES SURFACE IN FMOD API OUTPUT?  **PARTIAL**

What the over-read bytes *become* was reconstructed from disassembly of the four functions the SQ1
run exercised (`0x4e92e0`, `0x4ea150`, `0x4ea400`, `0x4abde0`) and the decode dispatcher `0x500e00`.

### 2a. The sample-header-walk primitive (`poc_v5`/`poc_v6`) surfaces only QUANTIZED values
The walk at `0x4e92e0` and the per-sample parsers consume each over-read dword as a **chunk header**,
not as data:

```
0x4e9400  mov ebx,[r10]            ; over-read dword
0x4e9406  shr r11d,1 ; and 0xffffff ; size  = bits 1..24   (24-bit, quantized)
0x4e9412  shr eax,0x19             ; type  = bits 25..31   (7-bit)
0x4e9415  and bl,1                 ; more  = bit 0
```
and `0x4e93e6` stores `offsetTab[i] = r10 - blob` — an **offset delta**, not the bytes. The per-sample
properties that surface via the public API are table-lookups / enums, not raw memory (`0x4ea150`):

| FMOD API output | How it is derived from the (over-read) sample base entry | Carries raw bytes? |
|---|---|---|
| `getFrequency` / `defaultfrequency` | `freq_table[(base>>1)&0xf]` — **4-bit index** into `{0xac44=44100, 0xbb80=48000, 0x17700=96000,…}` | **No — quantized** |
| `getFormat` (channels) | `chan_table[(base>>5)&3]` — **2-bit index** | **No — quantized** |
| `getFormat` (format/bits) | enum constant (`[sub+8]=2`) / codec-ID key `*chunkptr` **validated against a registry** in `0x4abde0` (`cmp [rax+0x18],esi` list walk) | **No — enum / validated** |
| `getNumSubSounds` | `= numSamples` (header `+0x08`, an attacker field) | **No — attacker's own value, not memory** |
| `getLength` (sample count) | `base_entry >> 34` (**30-bit**), **or** a type-0 chunk's raw dword (`0x4ea2a0: mov eax,[r10]; mov [sub+0x18],eax`) | **Partial — ≤32 bits** |

So the richest leakable value from this primitive is `getLength`: at most the **low 32 bits** of an
over-read dword. Under `HIGH_ENTROPY_VA` a 64-bit module/heap pointer is `0x00007ff6_xxxxxxxx`; the
entropic high half (bits 32–47) is **lost**. The 24-bit chunk `size` surfaced by the getter
(`0x4ea400` → `*r9`) is even narrower. **No API output of this primitive reconstructs a full
pointer.** (This is the dynamic evidence from SQ1 too: the planted `0x80500e00` was interpreted as
`type=(0x80500e00>>25)=0x40`, `size=0x280700` — i.e. quantised into control fields, then rejected as a
bad format: `open` returned `0x13 = FMOD_ERR_FORMAT`.)

### 2b. The one FULL-byte reflection is a DIFFERENT primitive — the `readData` PCM copy
The decode dispatcher `halo3+0x500e00` calls the format decoder `call [codec+0xa8]`, which fills the
codec's PCM buffer `[codec+0x160]`, then copies it to the **caller's output buffer** via a plain
memcpy:
```
0x500f83  add rdx, [rbx+0x160]     ; src = codec PCM buffer (+ offset)
0x500f8d  call 0x62153f            ; 0x62153f = jmp [memcpy thunk]  -> raw byte copy to caller buf
```
For an **uncompressed (PCM) sub-sound**, the decoder is near-identity and the sound's data region is
located at `data_base(+0x30) + (base_entry>>7<<5)` for `dataSize(+0x34)` bytes — all attacker-set
header fields, and the per-sample offset partly derives from a possibly-over-read base entry. Sizing
these to **alias adjacent heap** makes `readData` return raw neighbouring bytes **verbatim**,
including full 64-bit pointers. This is the genuine "raw bytes in an API output buffer" surface.

> Honesty: 2b is established **structurally** (the memcpy is unambiguous in the disassembly), not
> driven end-to-end dynamically. Faithfully driving a PCM decode-to-output requires the real
> format-specific decoder at `[codec+0xa8]` to run; the canonical report §7.1 already documents that
> the live FMOD setup diverges under instrumentation (`setup=0`, bank rejected), and the harness's
> `--decode` mode diverts at the *first* indirect call (`0x500e52`) before reaching the memcpy. So 2b
> is the "full-pointer" surface **in principle**; it does not change the verdict, because link 3
> breaks for it regardless (§3).

**SQ2 conclusion:** the in-scope sample-header over-read reflects only **quantized/≤32-bit** values
(no usable full pointer); a full-pointer reflection exists only through the separate `readData` PCM
path.

---

## 3. SQ3 — DOES THE ENGINE FORWARD ANY OF THOSE TO THE SERVER?  **NO (static)**

Traced each candidate output to its consumer; cross-checked against the netcode track
(`APPENDIX-INFOLEAK-PROTOCOL.md`), which already established both server-observable protocols are
pointer-free by construction.

**`readData` PCM output → FMOD mixer → audio device (local only).** The non-callback callers of the
decode dispatcher `0x500e00` are all FMOD-internal stream/mixer reads:
```
halo3+0x475c4c  call 0x500e00      ; resampler/stream read -> local PCM buffer
halo3+0x4cb8fe  call 0x500e00      ; stream buffer fill, bytes_read accumulated at [rdi+0x224]
halo3+0x4ea4b7  jmp  0x500e00      ; the codec read callback itself
```
They fill a local PCM buffer that feeds the audio device. **There is no socket/bitstream write in
this path.** Decoding an `sfx*.fsb` bank is a **client-local playback** effect: in a client/server
title the server authors sound as a **quantized event** (datum-handle + sound-tag index — the
engine's `biped_handle_simulation_warp` / datum-handle model, per the netcode track), each client
loads *its own* copy of the bank and decodes independently, and **no decode result is sent back** —
the server already knows what it told the client to play, so there is no "here are the length/bytes I
decoded" message. Such a message would be useless for gameplay and does not exist in either protocol.

**`getLength` / `getFormat` / `getNumSubSounds` → local sound setup (not replicated).** These
configure channel/looping/playback locally. The halo3 session bitstream replicates **quantized state
and datum handles**, not FMOD sound-object fields (netcode track §3b); the Reclaimer `serde` layer is
**pointer-free, bounds-checked, and its request/response pairs are client-pull downloads** — the
server→client *push* (corruption) direction, not a client-memory-disclosure direction (netcode track
§3a). Neither ingests an FMOD getter result.

**The only genuine sound→network path in the engine is voice chat**, which is a **separate
microphone-capture pipeline** (`voice_output`, `voice_proximity`, `voice-repeater`, `voice mask`
strings). It captures the mic and sends encoded frames; it is **not fed by the sfx-bank decode
mixer**. There is no loopback of the game mixer into the voice uplink, so over-read-derived sfx bytes
never enter it.

**SQ3 conclusion:** no server-observable field carries any over-read-derived value. The chain breaks
at the forward-to-server link.

---

## 4. Verdict and the exact chain

**LEAK NOT CONFIRMED** for the FMOD-reflection ASLR-defeat route under the (correct) malicious-server
threat model. Precisely where each candidate chain dies:

```
poc_v5 header-walk primitive (in scope):
  read offset (= 24-bit size, attacker)  ->  OOB read lands on pointer  [SQ1: CONFIRMED, non-faulting]
     ->  bytes consumed as quantized chunk type/size + offset-table delta, or getLength (<=32 bit)
         [SQ2: pointer DESTROYED here — no full 64-bit pointer survives to any API output]
     ->  (even the quantized value) not written to any client->server field
         [SQ3: not forwarded]
  ==> breaks at LINK 2 (and again at LINK 3).

readData PCM-copy primitive (the full-byte reflection):
  crafted PCM data region aliases adjacent heap  ->  readData memcpy returns raw bytes incl. full ptr
         [SQ2b: full pointer preserved — structural]
     ->  consumed by FMOD mixer -> audio device; decoded sfx is client-local, never serialized
         [SQ3: not forwarded — voice uplink is a separate mic pipeline]
  ==> breaks at LINK 3.
```

Dynamic vs. static: **SQ1 confirmed dynamically** (real `halo3.dll` code, Unicorn loader, planted
pointer, register/provenance capture, no fault). **SQ2 is RE + the SQ1 dynamic trace** (the planted
dword was observed being quantized into control fields). **SQ3 is static RE** (readData consumers are
FMOD-internal; cross-referenced to the netcode track's exhaustive protocol analysis) — consistent
with the tasking's note that live end-to-end wire capture is not reproducible on this macOS loader.

**Residual not exhaustively closed by RE (stated for honesty):** a server-authored **Megalo** script
that queries a sound property (e.g. a duration/playback accessor) and writes it to a **replicated
Megalo variable** was not exhaustively excluded by binary RE. Even if such an accessor exists, it
would carry only the **quantized / ≤32-bit** values of §2a (never a full pointer), so it could not
by itself defeat `HIGH_ENTROPY_VA`; it is a theoretical partial-leak at most. This mirrors the netcode
track's one residual (a miscomputed variable-length bitstream field). Confirming/denying it needs
targeted RE of the Megalo sound opcodes + the specific packet builders — not completed here.

**Consequence for the canonical report §7.3:** the "recommended next experiment" now has a concrete
**negative** result. The controlled OOB read is a real info-leak *primitive* (non-faulting,
pointer-targeted, attacker-offset), but it is **not reflected to the attacker-controlled server** by
any engine path — so it does not supply the ASLR defeat that would lift this from DoS + local
corruption + proven RIP sink to remote RCE on hardened builds. Both ASLR-defeat tracks (protocol and
FMOD-reflection) are now negative.

---

## 5. Reproduction

```bash
# (venv as in the canonical report: unicorn==2.1.4, pefile, capstone)
./uenv/bin/python -I craft_leak.py  0x2a0000

# SQ1 — non-faulting OOB read onto a planted pointer (leak mode ON)
RAWLOAD_LEAK=1 ./uenv/bin/python -I rawload.py halo3.dll poc_v6_leak_reflect.fsb

# contrast — same file, leak mode OFF => the identical read FAULTS at halo3+0x4e9400
./uenv/bin/python -I rawload.py halo3.dll poc_v6_leak_reflect.fsb

# offset is attacker-controlled — move every planted read to blob+0x100000
./uenv/bin/python -I craft_leak.py  0x100000
RAWLOAD_LEAK=1 RAWLOAD_LEAK_DELTA=0x100000 ./uenv/bin/python -I rawload.py halo3.dll poc_v6_leak_reflect.fsb
```

Env knobs (all OFF/absent by default): `RAWLOAD_LEAK=1` enables the instrument;
`RAWLOAD_LEAK_DELTA` (default `0x2a0000`) sets the plant distance; `RAWLOAD_LEAK_TEXTPTR` /
`RAWLOAD_LEAK_HEAPPTR` set the planted pointer values.

Sample sha256:
```
poc_v6_leak_reflect.fsb  abdc8da8e0ad9055d5e96929af774bab369f3d420d3f9077cd783d0c0bb63bc9   (DELTA=0x2a0000 build)
```

## 6. Artifacts

* `rawload.py` — `RAWLOAD_LEAK` mode added (env-gated, OFF by default; `_plant_adjacent`,
  the `MEM_READ` hook, and `_leak_report`). Default behaviour is byte-identical to before (verified:
  `poc_v5` and `poc_v6` both still fault at the same RIPs with the env unset).
* `craft_leak.py` — crafts `poc_v6_leak_reflect.fsb` for a chosen plant distance.
* `poc_v6_leak_reflect.fsb` — the SQ1 sample.
* `fmod-reflection-SQ1.log` — captured SQ1 evidence (runs A and B).

## 7. Scope / housekeeping

Authorized local research only; nothing published, no accounts, not a git repo (nothing committed).
No Halo runtime was launched for this track (the experiment is pure Unicorn emulation of the real
`halo3.dll` code + static RE), so no runtime state needed restoring. Touched only ``
(`rawload.py`, new `craft_leak.py`, `poc_v6_leak_reflect.fsb`, this file, the
log); the SDK-bisect appendix + its evidence untouched; `peload.c` **not** modified (no loader instrument was needed —
the from-scratch loader already runs the real parser). The canonical report `.md` was not edited (the
lead session integrates §7.3).
