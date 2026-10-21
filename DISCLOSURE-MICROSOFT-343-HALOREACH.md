# Disclosure — Microsoft / Halo Studios (343) — Halo: The Master Chief Collection (Halo: Reach)

**Audience:** the MCC product team (Microsoft / Halo Studios, formerly 343 Industries) and MSRC.
**Product:** Halo: The Master Chief Collection — **Halo: Reach** (`haloreach/haloreach.dll`). This is the
Reach-specific companion to the Halo 3 advisory ([`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md));
it is the **same defect in a second shipped, now internet-accessible title**.
**Binary identity:**
`sha1   706181dd768c9aed35ffe230e3ec8c31ab4b0cc4`
`sha256 738dd2d24ea3aea12e1ee9aa4a61094bf116027d42004c35a19e5048608b0894`
**Summary:** `haloreach.dll` statically links the **same shared FMOD low-level build** as `halo3.dll`
(build path `…\main\h3\external_libraries\fmod\lowlevel_api\…`), whose **FSB5 sound-bank parser** has an
integer-overflow / out-of-bounds memory-corruption bug. It is reached when the engine opens a
**mod-supplied, untrusted** `fmod/pc/sfx*.fsb` bank via `System::createStream`, with no user interaction
beyond joining a server that requires the mod. Impact: remote **DoS** + **memory corruption** + a
**CFG-disabled indirect-call sink that yields arbitrary RIP** — the same chain proven in Halo 3,
present in Reach as **byte-identical code**.
**Full technical detail:** [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) (§3.2 covers the multi-title
confirmation).

## 1. The defect (bundled FMOD, reached from MCC's content path) — Reach RVAs

`createStream(path, FMOD_OPENONLY|FMOD_CREATESTREAM, NULL)` with no type hint → FMOD content-detects
FSB and runs the FSB codec `open`, which parses the 0x3C-byte header + per-sample header table. Two
unchecked fields (identical logic to Halo 3; RVAs here are `haloreach.dll`'s):

* `numSamples` (+0x08): the sample-offset table is sized `numSamples * 4` as a **32-bit** multiply →
  integer overflow → zero/undersized allocation (table alloc `call 0x57b1e0`, `~0x60287d`) that the
  loop then overflows (offset-table store `mov [rsi], eax` at `0x6028d6`).
* per-sample chunk `size` (24-bit): the walk does `ptr += size` with no bound — the 24-bit mask
  `and r11d, 0xffffff` at `0x6028fb` — so the next dereference is out-of-bounds at `blob + Σ(size)`:
  the walk read **`movzx eax, byte ptr [r10]` at `0x6028d8`** (the direct analogue of Halo 3's
  faulting `0x4e93e8`).

The decode path `Sound::readData` (Reach dispatcher **`0x61a3a0`**) dispatches through a codec-instance
function pointer — **`call qword ptr [rcx+0xa8]` at `0x61a3f2`** (`rcx` = the codec instance) — and
**Control Flow Guard is disabled** on this build, so corrupting that pointer yields exact, arbitrary
instruction-pointer control. ASLR (`HIGH_ENTROPY_VA`) is on and **no info-leak was found** via the
examined routes, so end-to-end RCE on the shipping build is **not demonstrated** and would require an
additional ASLR-defeat primitive — but the corruption primitive and the control sink are present.

## 2. Basis of confirmation (byte-for-byte code identity with Halo 3)

Reach was confirmed by **binary code identity**, not assumption:

* The FSB5 **sample-table builder** body is **byte-identical** to Halo 3's: a **96-byte run** of Halo
  3's builder (`halo3+0x4e92e0` region) occurs **verbatim** in `haloreach.dll` at RVA `0x602880`; the
  disassembly there is the identical allocation + `numSamples` loop + offset-table store + the
  `movzx [r10]` OOB read + the 24-bit-size chunk walk and type dispatch.
* The **decode/RIP sink** is likewise **byte-identical**: a **96-byte run** of Halo 3's `readData`
  dispatcher (`halo3+0x500e00`) occurs verbatim at Reach `0x61a3a0`, including the
  `mov edx, [rcx+0x13c]` setup and the `call [rcx+0xa8]` indirect call (`0x61a3f2`).
* `FMOD FSB Codec`, `FSB5`, and `fmod_codec_fsb` strings are present in `haloreach.dll`.

Honesty on what was *run*: the **RIP demonstration (`RIP = 0x4141…`) was performed against Halo 3's
real `halo3.dll`** ([`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md) §2); Reach's RIP sink
is confirmed by the **byte-identical `readData` / `call [rcx+0xa8]`** above, not separately RIP-executed.

**Update — the FSB5 crash is now reproduced in Reach itself** (not only by code identity):

* **From-scratch emulation of the real `haloreach.dll`:** a Unicorn loader drives the real Reach FSB
  codec open callback (`0x602ac0`) on `poc_v2_numsamples_oob.fsb` → fault at `0x6028d8` (and `poc_v3`
  → `0x6029b0`).
* **Natively, in the live game via a *normal custom game*** (no server, no Workshop — the crafted bank
  placed as `haloreach/fmod/pc/sfx.fsb`, loaded at audio init of a stock `reach.sh match` Slayer game):
  the real process takes an access violation `0xC0000005` at **`haloreach.dll+0x6028d8`** (the FSB5
  builder OOB read), `sig=11`, `RIP=0x1806028d8`, return `0x602d30` (immediately past the builder call
  in open `0x602ac0`) → `haloreach.dll` engine → game `exe`. **Reproduced twice**; the faulting **RIP is
  stable at `0x1806028d8`** while the **fault address tracks ASLR** across runs (`0x116523000`,
  `0x1114c6000`) — the signature of a genuine out-of-bounds walk pointer, not a fixed null-deref.

This upgrades Reach from code-identity to a **natively-reproduced DoS / memory-corruption crash in the
shipping binary**; the RIP sink remains confirmed by code identity (above), not separately RIP-executed
on Reach.

## 3. Why "update FMOD" is necessary but not sufficient

The bug is **unpatched upstream in FMOD**: standalone FMOD Core crashes on the same input through at
least **2.03.11 (runtime-confirmed)**, and FMOD's public changelog shows **no FSB5 fix through 2.03.15
(Sep 2026)**; no CVE exists ([`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md)). Moving to a newer
FMOD will **not** remove the defect unless Firelight fixes it (disclosed in parallel —
[`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md)). Because MCC links the same FMOD build across its FMOD-based
titles, one upstream fix (re-integrated into MCC) addresses Halo 3 and Halo: Reach together.

## 4. Recommended MCC-side fixes (defense in depth)

Identical to the Halo 3 advisory, applied to the Reach engine module:

1. **Validate FSB5 header fields before handing the bank to FMOD** — `numSamples`, `sampleHeadersSize`,
   `nameTableSize`, `dataSize`, and every per-sample chunk `size` against the real file size, with sane
   caps and **64-bit** allocation math; reject on mismatch.
2. **Restrict mod banks to FSB5** — pass `FMOD_CREATESOUNDEXINFO::suggestedsoundtype =
   FMOD_SOUND_TYPE_FSB` and refuse anything FMOD does not identify as FSB.
3. **Build the FMOD/engine modules with Control Flow Guard (`/guard:cf`)** so the decode-pointer
   indirect call (`call [rcx+0xa8]`, `0x61a3f2`) is validated — removes the RIP sink.
4. **Treat server-pushed / required content as opt-in**, and decode untrusted mod audio in a
   low-privilege sandboxed process returning PCM.
5. Coordinate with **Firelight** for the upstream parser fix.

## 5. Severity framing (for triage)

Remote, no user interaction beyond joining, on the shareable-content path, with a CFG-unguarded
indirect-call sink that yields arbitrary RIP — now in a **second shipped title** that is
internet-accessible. Confirmed impact today: **remote DoS + memory corruption**. RCE is the escalation
ceiling, gated on an ASLR-defeat leak **not** found via the examined routes
([`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md),
[`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md)); we do not overclaim RCE, but the primitive
+ sink warrant high-end client-vulnerability triage. PoC inputs are tiny parser inputs, not working
exploits; crashing samples and symbolized backtraces can be shared privately. Authorized security
research for responsible disclosure via MSRC.
