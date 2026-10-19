# Disclosure — Firelight Technologies (FMOD)

**Audience:** the FMOD Engine maintainers (Firelight Technologies / Bose).
**Component:** FMOD Core API — the **FSB5 container / sample-header parser** in the FSB codec `open`.
**Class:** integer overflow → heap under-allocation + unbounded, attacker-stepped out-of-bounds
access (CWE-190 → CWE-787/CWE-125).
**Status:** **unpatched in every FMOD line we could test** (1.10.x through 2.02.22, May 2024; changelog
clean through 2.03.15, Sep 2026). See [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md).
**Full technical detail:** [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md).

This report is addressed to you because the defect is **in the FMOD Core API**, not in any one
licensee. It was found in Halo: The Master Chief Collection (which statically links FMOD 1.10.x) but
reproduces in standalone `libfmod` on current lines, so it affects the whole FMOD install base where a
title opens **untrusted** FSB5 input.

## 1. Where it is

The defect is in the FSB5 sample-table builder invoked by the FSB codec's `open` callback, reached
from **`System::createSound` / `System::createStream`** when FMOD content-detects an FSB container
(no `FMOD_CREATESOUNDEXINFO::suggestedsoundtype` needed). It triggers during the create call itself —
`FMOD_OPENONLY` does **not** avoid it, because the container header is parsed before any sample data
is decoded.

In MCC's statically-linked FMOD 1.10.x (`halo3.dll`) the builder is at RVA `0x4e92e0` (faults at
`0x4e93e8`, called from `open` `0x4e95d0`). In the standalone macOS **2.02.22** `libfmod.dylib` it is
the same logic (unnamed symbol `b51f0`, arm64 RVA ~`0xb52b4`), reached
`createSound → … → b51f0`.

## 2. Root cause (two independent defects, same function)

Reconstructed from disassembly (field offsets are into the 0x3C-byte FSB5 header):

```c
blob      = alloc(hdr->sampleHeadersSize);        // +0x0c, used directly as a size (unchecked)
read(file, blob, 1, hdr->sampleHeadersSize);
offsetTab = alloc(hdr->numSamples * 4);           // +0x08 * 4  -> 32-bit MULTIPLY  (DEFECT 1)
for (i = 0; i < hdr->numSamples; i++) {           // attacker loop count
    offsetTab[i] = (ptr - blob);                  // writes numSamples entries
    hasChunks = *ptr & 1;  ptr += 8;
    while (hasChunks) {
        dword = *ptr; ptr += 4;
        size  = (dword >> 1) & 0xffffff;           // 24-bit, attacker-controlled
        more  = dword & 1;
        ptr  += size;                              // unbounded step               (DEFECT 2)
        hasChunks = more;
    }
}
```

* **DEFECT 1 — 32-bit integer overflow on the allocation size.** `numSamples * 4` is evaluated as a
  **32-bit** value. `numSamples = 0x40000000` → `0x1_0000_0000` truncates to **0** → a zero/undersized
  `offsetTab` that the loop then writes `numSamples` 4-byte entries into (**heap overflow, attacker-
  controlled extent and written value**). `numSamples = 0x7fffffff` → a ~4 GiB request (allocator
  failure / DoS). `sampleHeadersSize` (+0x0c) is likewise used directly as an allocation size.
* **DEFECT 2 — unbounded, attacker-stepped walk.** `ptr += size` uses a 24-bit attacker field with no
  check that `ptr` stays within `blob[0 .. sampleHeadersSize]`; the next iteration dereferences
  `*ptr`. The access address is `blob + Σ(size)` — **attacker-controlled to the byte**.

## 3. Impact

* **Guaranteed:** remote/queryless **DoS** (a crafted bank crashes any caller that opens it) and
  **memory corruption** (a controlled OOB write/read).
* **Fault is a WRITE.** On standalone 2.02.22 the observed crash is a **byte-write translation fault to
  an unmapped page** inside `createSound` — i.e. the under-allocated table being written past
  (strengthens the corruption/exploitability story over a pure read). Evidence:
  [`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md), `libfmod-regcontrol.log`.
* **Control-flow:** in the downstream (MCC) build, corrupting an adjacent codec object's decoder
  function pointer (`+0xa8`) and then calling `Sound::readData` transfers control to the attacker
  value (demonstrated as arbitrary RIP in that build). FMOD's own arm64 `libfmod` compiles these
  indirect calls as **plain `blr` (no pointer authentication)**, so the sink is unauthenticated there
  too (§7.5 of the technical doc).

## 4. A note on the existing version gate

Later lines added a sub-format **version gate** that cleanly rejects some malformed variants
(`FMOD_ERR_FORMAT` / `FMOD_ERR_VERSION`). It does **not** cover the sample-count / chunk-size overflow:
the two overflow vectors (`poc_v2` numSamples, `poc_v3` type-6 size) still corrupt memory on 2.02.22.
The real defect is untouched by that gate.

## 5. Suggested fix

In the FSB5 header/sample-table parser, before any allocation or walk:

1. **Overflow-safe sizing.** Compute `numSamples * 4` (and every derived size) in **64-bit** with an
   explicit upper bound; reject on overflow or implausible magnitude.
2. **Cross-check the header against the actual stream length.** Validate
   `0x3C + sampleHeadersSize + nameTableSize + dataSize` against the real file/stream size; reject on
   mismatch. Bound `sampleHeadersSize`, `nameTableSize`, `numSamples`.
3. **Bound the sample-header walk.** Ensure every `ptr += size` keeps the cursor within
   `blob[0 .. sampleHeadersSize]`; reject a chunk whose `size`/offset would leave the blob.
4. Consider compiling indirect codec dispatch with **pointer authentication (arm64e)** / platform CFI
   so a corrupted codec function pointer cannot be used for control-flow hijack.

## 6. Reproduction

A minimal, non-weaponized crashing bank (`poc_v2_numsamples_oob.fsb`, `numSamples = 0x7FFFFFFF`) and a
version-agnostic probe are in this repository; see [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md)
§9 and `fsb5_probe.c`:

```
fsb5_probe <libfmod> poc_v2_numsamples_oob.fsb 0x2080 <version>
#   -> SIGBUS inside FMOD::System::createSound  == vulnerable
```

The PoC inputs are tiny parser inputs (headers + a few tagged bytes), not working exploits. Crashing
samples and symbolized backtraces can be shared privately on request. Full analysis and the
cross-version results are in [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) and
[`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md).

This is authorized security research for responsible disclosure.
