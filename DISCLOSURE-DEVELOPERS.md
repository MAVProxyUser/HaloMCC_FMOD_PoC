# Advisory — for developers shipping FMOD

**Audience:** any studio or developer whose application links the **FMOD Engine** (directly, or via the
official **Unity** / **Unreal** integrations) and may open **FSB / FSB5** sound banks that did not come
from your own trusted build pipeline.
**What:** the FMOD Core API's **FSB5 container parser** has an unpatched integer-overflow / out-of-
bounds memory-corruption bug. A single crafted `.fsb` can crash the process (DoS) and corrupt memory,
with a control-flow sink reachable in at least one shipping title.
**Reference:** full root cause, reproduction, and hardening analysis in
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md); upstream status in
[`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md); evidence that FSB travels bundled and
network-delivered across many FMOD titles in
[`ECOSYSTEM-FSB-EXPOSURE.md`](ECOSYSTEM-FSB-EXPOSURE.md). Disclosed to Firelight in
[`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md).

## Are you affected?

You are at risk **only if both** are true:

1. You link a vulnerable FMOD build. We runtime-confirmed crashes from FMOD **1.10.x through 2.02.22
   (May 2024)**, and the public changelog shows **no FSB5 fix through 2.03.15 (Sep 2026)** — so treat
   **all current lines as vulnerable** until Firelight states otherwise.
2. Your app feeds FMOD an **FSB/FSB5 bank whose bytes an attacker can influence** — e.g. mod loaders,
   user-generated-content pipelines, downloadable/streamed banks, networked asset delivery, or an
   asset-extraction/preview front-end on an embedded FMOD.

If every bank you ever open is produced by your own build and shipped read-only inside your package,
this bug is **not attacker-reachable** in your product (the vulnerable code is present, but nothing
hostile reaches it). Most titles are in this category — do not panic; do audit your content paths.

## The bug in one paragraph

Opening a bank via `System::createSound` / `System::createStream` runs FMOD's FSB5 codec `open`, which
trusts header fields from the file: it sizes the sample-offset table as `numSamples * 4` using **32-bit
math** (integer overflow → undersized allocation → heap overflow), and it walks the per-sample header
blob stepping by an unchecked **24-bit `size`** field (out-of-bounds read/write at an attacker-
controlled offset). `FMOD_OPENONLY` does not help — the header is parsed at open time. The decode
dispatch (`Sound::readData`) calls through a codec-instance function pointer, which on platforms
without CFG/PAC is an unauthenticated indirect call.

## What to do now

1. **Don't feed untrusted banks to FMOD unchecked.** Before `createSound`/`createStream`, validate the
   FSB5 header in your own (memory-safe) code and reject on any inconsistency:
   * magic `FSB5`, sane version;
   * `numSamples` capped and **`numSamples * 4` checked in 64-bit** ≤ file size;
   * `0x3C + sampleHeadersSize + nameTableSize + dataSize` consistent with the real file size;
   * a bounded walk of the sample-header blob where every chunk `size`/offset stays within
     `sampleHeadersSize`.
2. **Constrain the format.** Pass `FMOD_CREATESOUNDEXINFO::suggestedsoundtype = FMOD_SOUND_TYPE_FSB`
   and refuse anything FMOD does not identify as FSB, so content-sniffing can't route an attacker file
   into another codec.
3. **Isolate decoding.** Decode untrusted audio in a low-privilege, sandboxed process that returns PCM;
   treat a crash there as a handled error, not a process-killing fault.
4. **Build with platform CFI** — Control Flow Guard (`/guard:cf`) on Windows, pointer authentication
   (`arm64e`) where available — so a corrupted codec function pointer cannot be used for control-flow
   hijack. (FMOD's own shipped arm64 `libfmod` is plain `arm64` with **no PAC**; see
   [`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md).)
5. **Watch for the upstream fix.** Track FMOD's revision history and update once Firelight ships a
   bounds/overflow fix in the FSB5 parser; re-test with the PoC inputs here.

## How to test your build

The repository includes a version-agnostic probe (`fsb5_probe.c`) and a minimal crashing input
(`poc_v2_numsamples_oob.fsb`). Point the probe at your `libfmod`:

```
fsb5_probe <your libfmod> poc_v2_numsamples_oob.fsb 0x2080 <version>
#   SIGSEGV/SIGBUS inside createSound == vulnerable ; a clean FMOD_ERR_* == safe on that build
```

See [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md) for the harness and the cross-version
results, and [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) for the full analysis. The PoC files are
tiny parser inputs, not working exploits. This advisory is published as authorized security research.
