# Disclosure — Microsoft / Halo Studios (343) — Halo: The Master Chief Collection

**Audience:** the MCC product team (Microsoft / Halo Studios, formerly 343 Industries) and MSRC.
**Product:** Halo: The Master Chief Collection — **multiple titles**: confirmed in `halo3/halo3.dll`
**and** `haloreach/haloreach.dll`, which statically link the **same shared FMOD build**
(`…\main\h3\external_libraries\fmod\lowlevel_api\…`). The FSB5 sample-table builder is **byte-identical**
across them (a 96-byte run of Halo 3's builder occurs verbatim in `haloreach.dll` at RVA `0x602880`;
OOB read at `0x6028d8` = the analogue of Halo 3's `0x4e93e8`). The remaining MCC engine DLLs (Halo CE,
Halo 2, Halo 2A/`groundhog`, Halo 3: ODST, Halo 4) ship the same shared FMOD and are **expected**
affected; they were not installed in the test environment, so they are not claimed as confirmed. See
§3.2 of the technical analysis. `haloreach.dll`: `sha256 738dd2d24ea3aea1…608b0894`.
**Binary identity:**
`sha1   fb2edf5805dd9c2adf5127f5abdd4834684b41bc`
`sha256 b209d8454b12dc77e54ccd2c9924ec8d44b8619d21cf98e36ffaf601e67efb63`
**Summary:** `halo3.dll` statically links **FMOD 1.10.x**, whose **FSB5 sound-bank parser** has an
integer-overflow / out-of-bounds memory-corruption bug. It is reached when the engine opens a
**mod-supplied, untrusted** `fmod/pc/sfx*.fsb` bank via `System::createStream`, with no user
interaction beyond joining a server that requires the mod. Confirmed: remote **DoS** + **memory
corruption** + a **CFG-disabled indirect-call sink that yields arbitrary RIP**.
**Full technical detail:** [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md).

## 1. The defect (in the bundled FMOD, reached from MCC's content path)

`createStream(path, FMOD_OPENONLY|FMOD_CREATESTREAM, NULL)` with no type hint → FMOD content-detects
FSB and runs the FSB codec `open`, which parses the 0x3C-byte header + per-sample header table. Two
unchecked fields:

* `numSamples` (+0x08): the sample-offset table is sized `numSamples * 4` as a **32-bit** multiply →
  integer overflow → zero/undersized allocation that the loop then overflows (builder RVA `0x4e92e0`).
* per-sample chunk `size` (24-bit): the walk does `ptr += size` with no bound → an attacker-controlled
  out-of-bounds dereference at `blob + Σ(size)` (faults at `0x4e93e8`).

The decode path `Sound::readData` (`0x500e00`) dispatches through a codec-instance function pointer —
`call [instance+0xa8]` at `0x500e52` — and **Control Flow Guard is disabled** on this build
(`GUARD_CF` clear), so corrupting that pointer yields exact, arbitrary instruction-pointer control
(demonstrated: planting `0x4141414141414141` → `RIP = 0x4141414141414141`, every time;
`rip-control-real-halo3.log`). ASLR (`HIGH_ENTROPY_VA`) is on and **no info-leak was found** via the
examined routes, so end-to-end RCE on the shipping build is **not demonstrated** and would require an
additional ASLR-defeat primitive — but the corruption and the control sink are proven.

## 2. Live in-game crash (your engine, real client + dedicated server)

Joined a real dedicated server, integrity check **passing on the original bank**, mid-match on the
real Hugegrass map; FMOD's map-load `createStream` opened a crafted ADD bank and the engine faulted in
the FSB5 parser (`live-crash-ingame.log`):

```
Joining 127.0.0.1:49190 now that this game is up.
Join preparation: mods checked in 6.4 s, map prepared in 0.6 s.
Loading sound bank sfx.corvette_glassing_beam.fsb from <map>'s mod package
Experimental startup exception 0xC0000005 in halo3.dll at RVA 0x4E93E8
Access kind 0 (read); Access target: 300080000003
Registers: ... r10 300080000003 ...
Unwound call chain (halo3.dll RVAs): 4E93E8 <- halo3+0x4E9840   (FSB open, just after call 0x4e92e0)
```

`0xC0000005` read access violation at `halo3+0x4E93E8`, far-OOB target `0x300080000003` (= the
file-controlled walk pointer). This matches a from-scratch loader **and** a standalone FMOD harness to
the instruction. Delivery honesty: the bank was substituted at the engine-initiated `createStream` via
a loader asset-redirect (the community loader was used to drive the real client); every other element
is the genuine in-game path. On native Windows MCC the same `createStream` opens mod-package banks
directly. The reachability vectors (published Workshop item / server custom map) are in
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §§6, 13.

## 3. Why "update FMOD" is necessary but not sufficient

The bug is **unpatched upstream in FMOD**: standalone FMOD Core crashes on the same input through at
least **2.02.22 (May 2024)**, and FMOD's public changelog shows **no FSB5 fix through 2.03.15 (Sep
2026)**; no CVE exists. See [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md). So simply moving
to a newer FMOD will **not** remove the defect unless Firelight fixes it (we are disclosing to them in
parallel — [`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md)).

## 4. Recommended MCC-side fixes (defense in depth)

1. **Validate FSB5 header fields before handing the bank to FMOD** — `numSamples`, `sampleHeadersSize`,
   `nameTableSize`, `dataSize`, and every per-sample chunk `size` against the real file size, with
   sane caps and **64-bit** allocation math; reject on mismatch.
2. **Restrict mod banks to FSB5** — pass `FMOD_CREATESOUNDEXINFO::suggestedsoundtype =
   FMOD_SOUND_TYPE_FSB` and refuse anything FMOD does not identify as FSB (removes the other
   content-sniffed codecs from the attack surface; see [`FUZZING-SURVEY.md`](FUZZING-SURVEY.md)).
3. **Build the FMOD/engine modules with Control Flow Guard (`/guard:cf`)** so the decode-pointer
   indirect call is validated — this alone removes the demonstrated RIP sink.
4. **Treat server-pushed / required content as opt-in**, and decode untrusted mod audio in a
   low-privilege sandboxed process returning PCM.
5. Coordinate with **Firelight** for the upstream parser fix so a future FMOD update actually helps.

## 5. Severity framing (for triage)

Remote, no user interaction beyond joining, on the shareable-content path, with a proven CFG-unguarded
indirect-call sink that yields arbitrary RIP. Confirmed impact today: **remote DoS + memory
corruption**. RCE is the escalation ceiling, gated on an ASLR-defeat leak we did **not** find via the
examined routes ([`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md),
[`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md)) — so we do not overclaim RCE, but the
primitive + sink warrant high-end client-vulnerability triage. PoC inputs are tiny parser inputs, not
working exploits; crashing samples and symbolized backtraces can be shared privately. This is
authorized security research for responsible disclosure via MSRC.
