# FMOD FSB5 memory corruption → RIP control (Halo: MCC `halo3.dll`)

A memory-corruption vulnerability in the **FMOD** FSB5 sound-bank parser, statically linked into Halo:
The Master Chief Collection's `halo3.dll`, reached from a **mod-delivered, untrusted sound bank** with
no user interaction beyond joining a server. The bug is **upstream in FMOD** (third-party audio
middleware) and is **unpatched in every FMOD line tested**, so it is a supply-chain concern for the
wider FMOD ecosystem, not only MCC.

This repository is a flat set of cross-linked Markdown writeups plus the proof-of-concept harness,
crafted inputs, and evidence logs. Start with [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md).

> Authorized security research for responsible disclosure (Microsoft MSRC / Cyber Verification
> Program). The crafted `.fsb` files are tiny parser inputs, not working exploits. `halo3.dll` and the
> third-party FMOD `libfmod` binaries are **not** redistributed here (see
> [`FMOD-SDK-BINARIES.txt`](FMOD-SDK-BINARIES.txt)).

## What is proven

| # | Result | Evidence |
|---|---|---|
| 1 | **OOB crash** at `halo3+0x4E93E8` in the FSB5 sample-table builder, from an unvalidated header | real `halo3.dll` (harness), from-scratch loader, **live in-game** (`live-crash-ingame.log`) |
| 2 | **Arbitrary RIP control** — `Sound::readData` does `call [instance+0xa8]` with **CFG off**; `RIP` = any value that corrupts that pointer | real `halo3.dll` — `rip-control-real-halo3.log` |
| 3 | **Live in-game crash** (real client + dedicated server, direct-connect, integrity-passing join) at `0x4E93E8` | `live-crash-ingame.log` |
| 4 | **Unpatched upstream** — standalone FMOD Core (arm64-native) crashes through **2.03.11 (2025, GitHub-sourced)**; changelog clean through **2.03.15 (Sep 2026)**; newest on GitHub is **2.04.00** (Windows-only); no CVE | [`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md) |
| 5 | **No ASLR-defeat info-leak** via either route (protocol **and** FMOD OOB-read reflection) — so RCE on `HIGH_ENTROPY_VA` is **not** demonstrated | [`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md), [`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md) |
| 6 | **Native-arm64 register control** in the shipped `libfmod.dylib` (no emulation); arm64 slice has **no PAC** → the indirect-call sink is unauthenticated | [`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md) |
| 7 | **Multi-title (per-title, not MCC-wide)** — same FSB5 builder is **byte-identical in `haloreach.dll`** (96-byte verbatim run at RVA `0x602880`; OOB read `0x6028d8`) → **Halo 3 + Halo: Reach affected** (both internet-reachable). **Halo 2 (classic) is NOT affected** — it uses the **Miles Sound System** (`mss64.dll`), not FMOD. Others unverified | §3.2 of [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) |
| 8 | **Separate non-FMOD bonus bug** — a **controlled heap overflow / write primitive** in Halo 2's server-delivered `.map` tag loader (alloc `0x6c9a64` sized from header `+0x14`/`+0x2d0`, section read `0x6c9ad5` sized from `+0x2d4`; attacker controls write dest/len/src, dest offset can go negative). **Not** the FMOD defect; emulation-confirmed on the real `halo2.dll`, live-unconfirmed | [`APPENDIX-HALO2-MAP-TAGLOADER.md`](APPENDIX-HALO2-MAP-TAGLOADER.md) |

**Honest bottom line:** remote **DoS + memory corruption** with a proven **CFG-/PAC-unguarded
indirect-call sink that yields arbitrary RIP**. Full one-shot RCE on the hardened build is **gated on
an ASLR-defeat leak that this bug does not supply** (both leak routes came back negative). See
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §7.

## The defect, in one paragraph

`createStream(path, 0x2080, NULL)` (no type hint) → FMOD's FSB5 codec `open` parses a 0x3C-byte header
+ a per-sample header table. `numSamples` (+0x08) sizes the offset table as `numSamples * 4` in
**32-bit** math (integer overflow → undersized allocation → heap overflow); the per-sample walk steps
by an unchecked **24-bit `size`** (out-of-bounds access at `blob + Σ(size)`). The decode path
(`readData`, `halo3+0x500e00`) then calls through the codec-instance function pointer `+0xa8` with
Control Flow Guard off → RIP control if that pointer is corrupted. Register/file-byte mapping and ASCII
diagrams: [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §4.4.

## Documents (the disclosure chain)

Core:
- **[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md)** — the full report: root cause, the register-
  overwrite primitive (+ ASCII file-layout/overflow diagrams), abused FMOD API surface, delivery,
  exploitability, hardening (Windows + native arm64), pedigree/scope, and the runtime-mitigation theory.

Audience-targeted disclosures:
- **[`DISCLOSURE-FMOD.md`](DISCLOSURE-FMOD.md)** — Firelight Technologies (FMOD): the upstream parser
  fix (the defect is theirs and ships to the whole ecosystem).
- **[`DISCLOSURE-RECLAIMER.md`](DISCLOSURE-RECLAIMER.md)** — Project Reclaimer: the delivery path, the
  connect→fetch→use crash log, and loader-level mitigations (patch the game memory to prevent the
  trigger + a secondary Rust file-rejection check).
- **[`DISCLOSURE-MICROSOFT-343.md`](DISCLOSURE-MICROSOFT-343.md)** — Microsoft / Halo Studios (343):
  the MCC product view, the live in-game crash, and MCC-side fixes (why "update FMOD" alone is not
  enough).
- **[`DISCLOSURE-MICROSOFT-343-HALOREACH.md`](DISCLOSURE-MICROSOFT-343-HALOREACH.md)** — the Halo: Reach companion of the Microsoft advisory (same defect, byte-identical parser + RIP sink; Reach RVAs).
- **[`DISCLOSURE-DEVELOPERS.md`](DISCLOSURE-DEVELOPERS.md)** — any studio shipping FMOD: are you
  affected, and how to harden your FSB5 content path.

Appendices (detailed findings):
- **[`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md)** — standalone-FMOD cross-version proof +
  changelog review.
- **[`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md)** — client-side leak hunt (no
  protocol leak).
- **[`APPENDIX-FMOD-REFLECTION.md`](APPENDIX-FMOD-REFLECTION.md)** — FMOD OOB-read reflection (leak not
  confirmed).
- **[`APPENDIX-NETCODE-PROTOCOL.md`](APPENDIX-NETCODE-PROTOCOL.md)** — exhaustive Blam netcode message inventory (why no message leaks a pointer) + a graded memory-corruption triage (var-length strings, Megalo VM, datum-handle index, host-migration UAF, int-overflow).
- **[`APPENDIX-HALO2-MAP-TAGLOADER.md`](APPENDIX-HALO2-MAP-TAGLOADER.md)** — a **separate, non-FMOD** finding: a **confirmed controlled heap-buffer-overflow / controlled-write primitive** in Halo 2 (classic)'s server-delivered `.map` tag-cache loader (`halo2.dll`), proven on the real DLL under from-scratch emulation (`halo2-taghunt/`). Distinct from the FMOD bug.
- **[`APPENDIX-HALO2-VARIANT-BIN.md`](APPENDIX-HALO2-VARIANT-BIN.md)** — Halo 2 game-variant `.bin` surface, audited to a **clean negative** (every attacker count/length/index is bounded; a positive OOB-write control proves the harness).
- **[`APPENDIX-LIBFMOD-REGCONTROL.md`](APPENDIX-LIBFMOD-REGCONTROL.md)** — native-arm64 register control
  + hardening.
- **[`APPENDIX-REACH-FSB-SERVED.md`](APPENDIX-REACH-FSB-SERVED.md)** — Halo: Reach **dynamic crash in the real `haloreach.dll`** (`0x6028d8`, emulation + native in-game) and the **server→client served-bank delivery** audit (Reclaimer `share_mods` direct push vs. Reach's Steam-Workshop gate). Turnkey serve/crash scripts + crash logs in [`reach-fsb-served/`](reach-fsb-served/).
- **[`FUZZING-SURVEY.md`](FUZZING-SURVEY.md)** — the initial multi-codec fuzzing survey this follows up.
- **[`ECOSYSTEM-FSB-EXPOSURE.md`](ECOSYSTEM-FSB-EXPOSURE.md)** — evidence that FSB is bundled in mods and **served over the network** across many FMOD games (Minecraft Bedrock, Celeste, Dark Souls, Guitar Hero, …), i.e. MCC's delivery shape is not unique — graded by confidence, with confirmed non-FMOD games called out.

## Repository layout (flat)

Everything is in the repository root; the `.md` writeups cross-link each other. The proof-of-concept
tooling (`rawload.py`, `craft.py`, `craft_leak.py`, `fsb5_probe.c`, `harden.py`, …), the crafted
samples (`poc_v1…v6_*.fsb`, `poc_tag_414140.fsb`), the demonstration mod (`mod-demo/`), the env-gated
loader additions (`peload-fmod-poc-additions.c`), and the evidence logs
(`rip-control-real-halo3.log`, `live-crash-ingame.log`, `libfmod-regcontrol.log`, …) all live in root.
A full annotated index is in [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §10.
