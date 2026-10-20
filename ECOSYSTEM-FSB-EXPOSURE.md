# FSB across the FMOD ecosystem — Halo is not the only one

**Purpose.** To show that MCC is *one instance* of a broad pattern, not a special case: the FMOD
**FSB / FSB5** sound-bank format travels through games as (a) **mod bundles**, (b) **server-pushed /
network-delivered content**, and (c) **downloadable asset archives**, across many FMOD titles —
several of which also have **client/server, map-based** play. Companion to
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §11 (scope) and
[`DISCLOSURE-DEVELOPERS.md`](DISCLOSURE-DEVELOPERS.md).

**Honesty up front (what this does and does not claim).** This bug's *reachability* in any title
still needs **both** a vulnerable FMOD build **and** a path that feeds FMOD an **attacker-influenced**
FSB (see [`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §11.1). This document does **not** claim the
games below are exploitable; it establishes that **FSB is routinely passed around untrusted and even
served over the network**, so MCC's delivery shape is common, not unique. Every row is graded by how
firmly it is established, and **confirmed non-FMOD games are called out** so the premise isn't
over-stated.

`FSB` = an FMOD sound bank built by FMOD Designer/Studio (the newer Studio `.bank` is a wrapper that
contains FSB5 sub-banks); it is often paired with a `.fev` event file. Sources: FMOD Core "Sound"
API, [fileinfo.com/extension/fsb](https://fileinfo.com/extension/fsb).

---

## 1. Confirmed FMOD + FSB usage (concrete evidence)

| Game / engine | FMOD? | FSB evidence | Delivery shape | Client/server maps? |
|---|---|---|---|---|
| **Halo: MCC (`halo3.dll`)** | **Yes (binary-confirmed)** | this repo — FSB5 parser RE'd + crashed + RIP | **mod-delivered** `fmod/pc/sfx*.fsb`, auto-downloaded from a server | **Yes** (Reclaimer dedicated servers, maps) |
| **Dark Souls III / Dark Souls Remastered** (FromSoftware) | Yes | `.fsb`/`.fev`; [DS3-Audio-Extractor](https://github.com/Joel-Paul/DS3-Audio-Extractor) chains `fsbext`/`fsb5_split`/FMOD; [DSR mod #314](https://www.nexusmods.com/darksoulsremastered/mods/314) swaps `.fev`/`.fsb` via FMOD Designer 4.28 | mods **replace** local `.fsb` (Nexus) | P2P/matchmaking (not custom-map push) |
| **Guitar Hero: World Tour / GH5** (Neversoft) | Yes | dev write-up: "each stereo track is split apart from the interleaved **FMOD Sound Bank (FSB)** file at run time" ([gamedeveloper.com](https://www.gamedeveloper.com/audio/bonus-feature-backstage-with-the-audio-of-i-guitar-hero-5-i-)) | custom-song packs shared/charted ([ghwt.de](https://ghwt.de/)) | online MP (no custom-map push) |
| **Celeste** (Extremely OK) | Yes (FMOD Studio) | FMOD **banks** (FSB5 inside); Everest "Custom Audio"; FMOD Bank Tools extract/rebuild ([Everest Mod Structure](https://github.com/EverestAPI/Resources/wiki/Mod-Structure)) | **mod bundles** on GameBanana ship audio in the mod folder | no native MP (CelesteNet is a mod) |
| **Hearthstone / Unity+FMOD titles broadly** | Yes | [`HearthSim/python-fsb5`](https://github.com/HearthSim/python-fsb5) extracts FSB5 that **Unity packs into `.resource` files**; also [`Fmod5Sharp`](https://github.com/SamboyCoding/Fmod5Sharp), [`fsbex`](https://github.com/astral4/fsbex), [`gdawg/fsbext`](https://github.com/gdawg/fsbext) | asset archives / mod extraction | varies |
| **Path of Exile** (GGG) | Yes | [`ggpk-explorer`](https://github.com/juddisjudd/ggpk-explorer) ships an `fmod_bank` parser (FMOD banks inside PoE's GGPK) | content in GGPK / patch CDN | **Yes** (online ARPG; instanced areas) |
| **Minecraft: Bedrock Edition** (Mojang) | **Yes** (on FMOD's titles list) | **Mojang-confirmed:** the official [`Mojang/bedrock-samples`](https://github.com/Mojang/bedrock-samples/tree/main/resource_pack/sounds) resource pack ships **4,761 `.fsb` files** (vs 3 `.ogg`), and two sampled banks are **FSB5** (magic `46 53 42 35`, version 1) — the same container with the vulnerable parser. **Microsoft-documented:** Bedrock supports `.wav`/`.ogg`/`.fsb` custom sounds ([learn.microsoft.com](https://learn.microsoft.com/en-us/minecraft/creator/documents/addcustomsounds)) | **server-pushed resource packs** (see §2a) | **Yes** (dedicated servers, worlds) |

(This is now **Mojang/Microsoft-confirmed**, not community-reported: Mojang's own add-on sample repo is full of FSB5 banks in the resource-pack layout, and Microsoft's creator docs list `.fsb` as a supported pack sound format. See §2a for the delivery path and what remains untested.)

---

## 2. Served over the network — the closest parallels to Halo/MCC

The MCC shape is "**untrusted server → network-delivered FSB → client FMOD parse**." That shape exists
elsewhere:

* **Minecraft: Bedrock Edition — server-forced resource packs (strongest parallel).** A Bedrock
  dedicated server can **require** clients to download a resource pack on join: set
  `texturepack-required=true` (or "Require resource packs"), and a joining player must **download the
  pack or disconnect**. Resource packs carry `.fsb` audio (Microsoft-documented, see §2a), which the
  client's FMOD then loads. So a single server can push bank content to every joining client — exactly
  MCC's "auto-downloaded, no way to turn it down" pattern, on a far larger install base. Sources:
  [xgamingserver guide](https://xgamingserver.com/docs/minecraft-bedrock/add-resource-pack),
  [falixnodes KB](https://kb.falixnodes.net/minecraft/bedrock/configuration/resource-pack) (host guides;
  not Mojang-official — verify exact syntax against Bedrock dedicated-server docs).
* **Natural Selection 2 / Unknown Worlds (Spark engine).** Dedicated servers **auto-download** the
  Workshop map/mods a client needs on join (`-mods`/`MapCycle.json`), i.e. server-driven content
  delivery onto maps ([UWE forums guide](https://forums.unknownworlds.com/discussion/comment/2021953)).
  NS2/Subnautica use FMOD (the community "FSB Extractor" thread lives on the UWE forums), though we did
  not binary-confirm the FMOD role here — **FMOD = reported**, server map/mod delivery = confirmed.
* **Unity + FMOD asset bundles.** Unity games that use FMOD commonly embed FSB5 banks inside Unity
  `.resource`/asset-bundle files (established by `python-fsb5`); titles that stream or download asset
  bundles (live-service content, UGC) can thus deliver FSB5 to the client over the network.

---

## 2a. Minecraft Bedrock — premise confirmed; live-client crash needs a Windows/mobile client

**Confirmed (Mojang/Microsoft + binary), not community-reported:**

* Mojang's own add-on repo [`Mojang/bedrock-samples`](https://github.com/Mojang/bedrock-samples/tree/main/resource_pack/sounds)
  ships **4,761 `.fsb` files** under `resource_pack/sounds/…` (vs 3 `.ogg`); two sampled banks are
  **FSB5** (magic `46 53 42 35`, version 1, with the `numSamples` / `sampleHeadersSize` header this
  analysis targets). Bedrock's sounds *are* FMOD FSB5 banks, in the resource-pack layout a custom/server
  pack overrides by matching path + name.
* Microsoft's creator docs list **`.wav` / `.ogg` / `.fsb`** as supported pack sound formats and say you
  replace a vanilla sound by matching its name (extension may differ)
  ([learn.microsoft.com](https://learn.microsoft.com/en-us/minecraft/creator/documents/addcustomsounds)).
* A Bedrock dedicated server can **force** a joining client to download a pack (§2).
* The crafted FSB5 crashes a **current standalone FMOD** (runtime-confirmed through 2.03.11,
  `fmod-2_03_11-regression.log`) — the vulnerable-parser family Bedrock links.

→ The chain "**untrusted server → pack `.fsb` (FSB5) → client FMOD parser**" is **documented and
binary-evidenced**, the same shape as the Halo path, on a far larger install base.

**The mechanism, concretely (from Mojang's own repo):**

* **How sounds resolve.** `resource_pack/sounds/sound_definitions.json` (1.0 MB, **2,439 sound events**)
  maps each event to an **extension-less path**, e.g. `"sounds/ambient/nether/crimson_forest/mood1"` or
  `"sounds/music/game/calm1"`; the client resolves that to the actual file (`mood1.fsb`) from the
  **active pack stack**. A resource pack therefore overrides a sound simply by providing a file at the
  same path — and a **server-delivered pack mounts into that stack exactly like a local one**, so a
  server-supplied `.fsb` at a resolved path is what the client's sound system loads.
* **The banks are the exact vulnerable container.** Every Bedrock `.fsb` sampled is **FSB5 version 1**
  with the precise header this bug targets — `numSamples`, `sampleHeadersSize`, `nameTableSize`,
  `dataSize` (benign values in the shipped files, e.g. `numSamples=1`). A crafted bank
  (`poc_v2`: `numSamples=0x7FFFFFFF`) is **structurally a valid pack sound** — same magic/version — so it
  is delivered and parsed like any other.
* **Served at connect, before the game starts (protocol).** The Bedrock join sequence (after auth,
  **before `StartGame`**) is `ResourcePacksInfo` → client response → chunked download via
  `ResourcePackDataInfo` + `ResourcePackChunkRequest`/`ResourcePackChunkData` (client re-hashes the
  reassembled pack) → `ResourcePackStack`. `ResourcePacksInfo`/`ResourcePackStack` carry a
  **`mustAccept` / forced** boolean: when set, the joining client must **download the pack or
  disconnect**. So a single server pushes bank bytes — including any `.fsb` — to every joining client
  at connect time, with no in-match user action. (Sources: community/library protocol docs —
  [wiki.vg Bedrock Protocol](https://wikivg.booky.dev/Bedrock_Protocol),
  [SerenityJS `ResourcePacksInfoPacket`](https://www.serenityjs.net/classes/_serenityjs_protocol.ResourcePacksInfoPacket.html),
  [Mojang bedrock-protocol-docs: resource-pack handling](https://deepwiki.com/Mojang/bedrock-protocol-docs/2.3-resource-pack-handling);
  not re-derived from a client here.)

**Not testable on the research machine (honest):** there is **no Bedrock client for macOS** — the
official "Minecraft" installer is the **Java-Edition** launcher (`com.mojang.minecraftlauncher`), and
Java Edition uses OpenAL/LWJGL, **not FMOD**. Empirically, on the research machine the Java install's
asset index (`assets/indexes/34.json`) lists **4,961 `.ogg` sound paths and 0 `.fsb`**, with
`lwjgl-openal` / `lwjgl-stb` (Vorbis) natives and **no `libfmod`** — the exact mirror image of Bedrock's
**4,761 FSB5 banks**. Same game, same sounds, two editions: **Java = OpenAL/Vorbis `.ogg` (not a
vector); Bedrock = FMOD `.fsb` (the vulnerable parser).** The **Bedrock Dedicated
Server** (`bedrock_server.exe`) is **Windows + headless with no FMOD linked** (it only *serves* the
pack), so neither running nor "wrapping" it exercises the client-side parse. Observing the actual crash
requires a **Bedrock client that links FMOD** — Windows / Android / iOS / console.

**Turnkey controlled test (your own client + your own local server).** A ready pack
`FMOD_FSB5_Test.mcpack` replaces vanilla `sounds/ambient/nether/crimson_forest/mood1.fsb` with the
crafted FSB5 (`numSamples = 0x7FFFFFFF`):

1. Client route — import `FMOD_FSB5_Test.mcpack` (double-click into the Bedrock client), apply it to a
   world. Server route — drop the `FMOD_FSB5_Test/` folder into the BDS `resource_packs/`, add its
   header UUID to the world's `world_resource_packs.json`, and set `texturepack-required=true` in
   `server.properties`.
2. Join (locally) with a **Windows/mobile Bedrock client** and trigger that ambient (Nether crimson
   forest) so the client loads the bank.
3. Crash/hang at the FMOD FSB5 parse = reproduced; a clean rejection = that Bedrock build validates the
   bank (record which).

**Caveats:** Bedrock's bundled FMOD version may differ from those tested here and Mojang may add
validation, so treat this as *plausible and documented*, not *confirmed-crashing*, until run on a real
client. Use only on your own local server and client, never against other players. The pack is a
parser-input test, not a weaponized exploit. Bedrock is a Microsoft product — in MSRC scope alongside
MCC.

## 3. Passed around in bundles (mod / UGC ecosystems)

FSB is a first-class modding artifact, shared as downloadable bundles:

* **Celeste** — custom maps/mods are distributed as zips on **GameBanana** (and via the Everest mod
  manager, Olympus) that ship their own FMOD bank audio in the mod folder; "FMOD Bank Tools" extract
  and **rebuild** banks ([Everest Mapping FAQ](https://github.com/everestapi/resources/wiki/Mapping-FAQ)).
* **Dark Souls** — sound mods on Nexus replace the game's `.fsb`/`.fev` (FMOD Designer workflow).
* **Guitar Hero** — custom-song communities package/share song audio derived from the games' FSB banks.
* **Generic** — a large cross-game tooling ecosystem exists purely to open/convert FSB/FSB5
  (`python-fsb5`, `Fmod5Sharp`, `fsbex`, `fsbext`, FMOD Bank Tools, and ~235 GitHub repos matching
  "FSB5 FMOD sample bank"), which is itself evidence that FSB banks are routinely extracted, modified,
  and re-shared across titles.

---

## 4. Which FMOD-list games have client/server, map-based play?

From Wikipedia's [*Games using FMOD*](https://en.wikipedia.org/wiki/FMOD#Games_using_FMOD), the titles
that combine **networked client/server play on maps/levels** with **FMOD** (confidence noted):

| Game | FMOD | Client/server + maps | Content delivery to client |
|---|---|---|---|
| **Halo 3 / MCC** | confirmed | dedicated servers, maps | mod banks auto-downloaded (**this bug**) |
| **Minecraft: Bedrock** | confirmed (list) | dedicated servers, worlds | **server-forced resource packs** (§2) |
| **Natural Selection 2** | reported | dedicated servers, maps | Workshop maps/mods auto-downloaded (§2) |
| **Path of Exile** | confirmed (GGPK fmod_bank) | online ARPG, instanced areas | patch CDN / GGPK |
| **Worms** series | on list | online MP | — (not established) |
| **LittleBigPlanet** | on list | **shared user-created levels** served online | user levels (audio role not established) |
| **Roblox** | on list; **FMOD unconfirmed** | user "places" served to clients | managed asset pipeline (could not confirm FMOD/FSB) |

(Only Halo/MCC is binary-confirmed end-to-end by us. The others are candidates by the two independent
properties — FMOD use and server-delivered map content — not claims of exploitability.)

---

## 5. Confirmed non-FMOD (premise guardrails)

To keep the scope honest, several heavily-modded client/server games that one might assume are FMOD are
**not**:

* **PAYDAY 2** — **Wwise** (soundbanks + `.stream`/`.wem`); BeardLib/SuperBLT load custom audio. Not FMOD.
* **Risk of Rain 2** — **Wwise**; custom audio via `R2API.Sound` (Wwise soundbanks). Not FMOD.
* **Source-engine games** (CS, TF2, GMod) — Valve's own audio (FastDL delivers content, but not FSB).
* **Roblox** — FMOD use could not be confirmed from public docs; its audio API is proprietary/managed.

These are excluded precisely because the premise is "confirm FSB **for sure**" — moddability alone
does not imply FMOD/FSB.

---

## 6. Bottom line

MCC is **not** unique: FSB/FSB5 is FMOD's native bank format, it is **routinely bundled in mods and
shared** (Celeste, Dark Souls, Guitar Hero, and a broad cross-game extractor ecosystem), and it is
**served over the network to clients** in at least one far-larger title — **Minecraft: Bedrock**, whose
dedicated servers can force a joining client to download a resource pack containing `.fsb` audio that
the client's FMOD then parses. That is the same "untrusted server → FSB → client-side FMOD" shape as
the Halo path. The unpatched-upstream status of the FSB5 parser
([`APPENDIX-UNPATCHED-SDK.md`](APPENDIX-UNPATCHED-SDK.md)) is what makes this ecosystem-wide rather than
MCC-specific — while the exposure-caveat in §11.1 keeps the claim bounded: present the vulnerable code
+ an untrusted-FSB path, and the primitive travels with it.
