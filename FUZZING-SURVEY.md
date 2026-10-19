# FMOD in MCC's halo3.dll: why mod sound banks are a risk

Written 2026-10-19 for the Project Reclaimer developers (and, through them, 343 Industries). It is a summary meant to
support a fix, not a full crash analysis. All observations come from static review of `halo3.dll` and a short local
fuzzing trial on a Mac, using a third-party PE loader. They should be confirmed on Windows before being relied on.

## Summary

`halo3.dll` statically links the FMOD Studio low-level library (1.10 series, ~2019). When a mod supplies sound banks
(`halo3/fmod/pc/sfx*.fsb`), halo3 opens each file with FMOD **without telling FMOD which format to expect**. FMOD then
identifies the file by its content and hands it to whichever of its built-in decoders claims it. Mod files can reach
players without any action on their part, so every one of those decoders becomes attack surface. A short fuzzing
trial of mutated banks produced reproducible crashes inside FMOD.

## Why this is exposed

1. **Mod content can reach players without any choice on their part.**
   - Reclaimer servers can share mod files with joining players (`share_mods`).
   - Customization mods are pushed on join, and the client's own text says players have "no way to turn them down".
   - Workshop items are third-party content as well.
   - `.fsb` files of up to 2 GiB are on the client's shareable-file allowlist.
2. **halo3 opens the banks with no type hint.** A bank is opened through `System::createStream(path,
   FMOD_CREATESTREAM | FMOD_OPENONLY, exinfo = NULL)` (wrapper at `halo3+0x460b60`, called from the bank loader at
   `halo3+0x172fc8`). Without `FMOD_CREATESOUNDEXINFO::suggestedsoundtype`, FMOD probes its codecs in priority order:
   FSB5, WAV, Ogg Vorbis, AIFF, FLAC, MOD, S3M, XM, IT, MIDI/DLS, ASF, MPEG, playlists and ID3.
   - A file named `sfx.something.fsb` therefore does not have to be an FSB at all.
   - Under the test loader, WAV (including IMA ADPCM), AIFF, MP3 (with ID3 tags), Ogg Vorbis, FLAC, MOD, S3M, IT and
     playlist files placed at that path were all opened and decoded by halo3's FMOD.
3. **Mods can add banks as well as replace them.** halo3 opens the main bank (`sfx.fsb`) at start-up. At map load
   it also opens `sfx.<name>.fsb` for names taken from the map's sound tags, so a mod map can choose which extra banks
   are opened.
4. **Nothing validates a bank before FMOD sees it.** Before a bank is loaded, the client only checks that the
   file's hash matches the server's manifest, which proves the bytes are the ones the server intended. Its path
   handling for bank names is strict (no traversal), but no format or content check is made.
5. **Old, broad parser code.** FMOD's tracker-module, MIDI/DLS, FLAC, Vorbis, MPEG, ID3 and playlist readers are the
   classic sources of memory-safety bugs in media libraries. This FMOD build is several years old, and the versions of
   its bundled third-party decoders could not be identified from the binary.

## What was observed

- **Test method:** a harness loaded `halo3.dll` on its own and ran halo3's own FMOD setup. It then put files through
  the same calls halo3 uses for a mod bank: create the stream, enumerate sub-sounds, seek, read, release.
  - The seeds were real Workshop `.fsb` banks plus small valid files in the other formats above.
  - Mutations were simple: bit flips, header field changes, truncation and splicing.
- **Results:**
  - Out of 400 mutated files, 10 crashed the process inside FMOD's code.
  - The crashes reproduce deterministically.
  - They come from several different parsers: the FSB5 container path, the WAV/ADPCM path, tracker formats and the
    playlist reader.
- **What the crashes look like:** some are simple NULL-pointer reads. Others are consistent with out-of-bounds memory
  access while parsing or decoding.
- **Not done:** detailed root-cause analysis. The crashing samples are kept locally and can be shared privately with
  the developers on request.

Caveat: this ran under a macOS PE loader, not Windows. Memory layout and allocator behaviour differ. Each crash
should be reproduced on Windows, ideally with a debug allocator (for example PageHeap), before drawing conclusions.

## Suggested mitigations (most effective first)

1. **Restrict mod banks to FSB5.** Pass an `FMOD_CREATESOUNDEXINFO` with `suggestedsoundtype = FMOD_SOUND_TYPE_FSB`,
   and refuse files that FMOD does not identify as FSB. This removes the tracker, MIDI/DLS, FLAC, MPEG, playlist and
   other decoders from the reachable surface in one change.
2. **Validate FSB5 headers in the client before halo3 sees them.** Check that the sample count, header/name/data
   sizes and per-sample offsets and lengths are consistent with the file size, and cap the counts. The client already
   does this kind of checking for other mod formats in Rust.
3. **Ask before installing pushed content.** Treat server-pushed sound banks (customization mods included) as
   opt-in, or at least only for servers the player trusts.
4. **Update FMOD** to a current, maintained release if MCC's build allows it.
5. **Optionally, decode in isolation:** a separate low-privilege process could decode mod audio and pass PCM back.

## References in the binary

| What | Where (halo3.dll RVA) |
|---|---|
| FMOD system setup (creates and inits FMOD, then opens `sfx.fsb`) | `0x172984` |
| Bank loader (`sfx[.name].fsb`, via the client's asset-path hook, type 3) | `0x172fc8` |
| `System::createStream` wrapper (mode `0x2080`, no exinfo) | `0x460b60` |
| `Sound::getSubSound` / `seekData` / `readData` / `release` wrappers | `0x460df0` / `0x4611a0` / `0x460fc0` / `0x460cb0` |
| Codec registration (FSB5, WAV, Ogg, AIFF, FLAC, MOD, S3M, XM, IT, MIDI, DLS, ASF, MPEG, playlist, ID3) | `0x4630d0` |
| Client: shareable mod file types and size caps | client v0.9.20 `exe+0x1888d70` |

## The 10 crashes in detail (no root-cause or exploitability analysis)

| # | Seed the mutant came from | When it crashed | Kind of fault | Reproduced on rerun |
|---|---|---|---|---|
| 1 | IMA ADPCM `.wav` | while opening | the process aborted on a heap-consistency check | **no**: the rerun ended with a clean FMOD "format" error |
| 2 | FSB5 bank (`falcon_lod`) | while decoding, after the first data | invalid memory read | yes |
| 3 | FSB5 bank (`lich_windup`) | right after a successful open, while decoding | read past the end of a buffer (faulted at a page boundary) | yes |
| 4 | FSB5 bank (`locust_…_metal`) | same as 3 | same as 3 | yes |
| 5 | FSB5 bank (`vulture_thruster_loop_in`) | while decoding a later sub-sound | invalid memory read | yes |
| 6 | FSB5 bank (`wombat_gun`) | same as 3 | same as 3 | yes |
| 7 | `.pls` playlist | while opening | NULL-pointer read | yes |
| 8 | `.pls` playlist (different mutant) | while opening | NULL-pointer read, same spot as 7 | yes |
| 9 | ProTracker `.mod` | right after opening | near-NULL read (a missing structure) | yes |
| 10 | Scream Tracker `.s3m` | while opening | invalid pointer use | yes, but the faulting spot moved between runs |

What this tells us:

- **Reproducibility:** 9 of 10 reproduce. #1 looks timing- or heap-layout-dependent.
- **Inputs:** every mutant came from flipping or rewriting header fields, truncating, or splicing files. That is the
  kind of input a malformed or malicious mod bank would carry.
- **The FSB5 container itself crashes (5 of 10).** Restricting mod banks to FSB5 removes most of the reachable
  decoders but is not sufficient on its own. FSB5 headers also need validating: counts, sizes and offsets against the
  file size.
- **The other five come from the non-FSB paths:** the playlist reader, two tracker formats and WAV/ADPCM. These are
  reachable only because halo3 opens banks without a format hint.
- **Severity varies.**
  - #7–9 (NULL reads) are crashes only.
  - The rest are out-of-bounds or invalid-pointer accesses, or an allocator inconsistency. They may involve memory
    corruption.
  - Whether any of them can be controlled is a root-cause question for the developers.
- **Platform:** all of this comes from a macOS PE loader. Memory layout and allocator behaviour differ from Windows.
  Reproduce each crash on Windows with a debug allocator (e.g. PageHeap) before ranking severity. The crashing samples
  are kept privately and can be shared with the developers on request.
