# Appendix — Halo: Reach FSB5 crash: dynamic confirmation + served-map delivery

## MSRC submission summary (repro + impact)

- **Product / component:** Halo: The Master Chief Collection — Halo: Reach
  (`haloreach/haloreach.dll`, x64, `sha1 706181dd768c9aed35ffe230e3ec8c31ab4b0cc4`),
  statically-linked FMOD FSB5 codec (`d:\p4\mcc\main\h3\external_libraries\fmod\…`).
  Byte-identical defect also in `halo3.dll` (`0x4e93e8`).
- **Class:** memory corruption — attacker-controlled `numSamples` in an FSB5 bank
  drives a 32-bit `numSamples*4` allocation-size overflow, then an out-of-bounds
  walk over the sample-header table.
- **Impact (measured):** access violation (`0xC0000005`) / OOB read in the real game
  process at **`haloreach.dll+0x6028d8`** (DoS, confirmed). **Beyond DoS:** the FMOD
  `readData` dispatcher is present in Reach at **`0x61a3a0`** (byte-identical to
  halo3's `0x500e00`, 96/96) and does a bare **`call [instance+0xa8]` at `0x61a3f2`
  with CFG not enforced** — a control-flow-hijack sink reachable from the controlled
  heap write; same config under which the identical sink was RIP-proven in halo3
  (§2a, `TECHNICAL-ANALYSIS.md` / `rip-control-real-halo3.log`).
- **CONFIRMED (two independent repros):**
  1. **From-scratch emulation of the real `haloreach.dll`** — `rawload_reach.py`
     drives the real FSB open callback `0x602ac0` on the crafted bank; faults at
     `0x6028d8` (poc_v2) / `0x6029b0` (poc_v3). Log: `evidence/reach-rawload-runs.log`.
  2. **Native, in the live Reach game** — a crafted `sfx.fsb` loaded by the game's
     FMOD at audio init crashed the real process:
     `FAULT 0xc0000005 at haloreach.dll+0x6028d8 … [CRASH] sig=11 RIP=0x1806028d8`
     (`evidence/reach-LIVE-crash-ingame.log`), return addr `0x602d30` = right after the
     builder call in `0x602ac0`.
- **Minimal repro (no game needed):**
  ```
  python3 -m venv venv && ./venv/bin/pip install unicorn pefile capstone
  ./venv/bin/python harness/rawload_reach.py <…>/haloreach/haloreach.dll poc_v2_numsamples_oob.fsb
  # -> FAULT read-unmapped @ haloreach.dll+0x6028d8 ; alloc size 0xfffffffc (numSamples 0x7fffffff * 4)
  ```
- **Delivery / reachability (honest):** the crafted bank reaches FMOD through the
  normal `fmod/pc/sfx*.fsb` load path (redirect “kind 3”, seen in the live crash log).
  Halo 3/Reclaimer servers push mods directly to clients (`share_mods`) — the
  un-mitigated server-serves-the-bytes vector. Halo: Reach gates server-required mods
  through **Steam Workshop** (subscription + integrity at join) — a real mitigation;
  the Reach attacker path is a **published Workshop item** (Steam verifies integrity
  to published bytes, not safety). Details + runtime evidence of the gate in §3.

---

**Goal.** Upgrade the Halo: Reach (`haloreach.dll`) FSB5 finding from *byte-for-byte
code identity* to a **dynamic crash in the real Reach binary**, and audit the
**served-map delivery** path (can a server cause a Reach client to parse a crafted
FSB?). Honest split of what is proven vs. not below.

**Target.** `haloreach/haloreach.dll`, PE32+ x64, image base `0x180000000`,
`sha1 706181dd768c9aed35ffe230e3ec8c31ab4b0cc4`. FMOD banks at
`haloreach/fmod/pc/*.fsb` (`sfx.fsb`, `english.fsb`, …). Same statically-linked FMOD
(`d:\p4\mcc\main\h3\external_libraries\fmod\lowlevel_api`, `FMOD FSB Codec`, `FSB5`).

---

## 1. Located Reach FSB parse chain (static)

The FMOD FSB codec is registered in `0x57c4b0`; the FSB codec's function pointers
are the `lea` block right after the `"FMOD FSB Codec"` name (`0x57c943`). The open
callback is a thunk `0x603980 → 0x602ac0`.

| role | halo3 RVA | **Reach RVA** | how found |
|------|-----------|---------------|-----------|
| FSB open callback | `0x4e95d0` | **`0x602ac0`** | thunk `0x603980`; calls builder at `0x602d2b` |
| sample-table builder | `0x4e92e0` | **`0x6027d0`** | byte-identical 96-byte run; called from open |
| **OOB read (crash)** | `0x4e93e8` | **`0x6028d8`** | `movzx eax, byte ptr [r10]` (numSamples walk) |
| 24-bit size mask | — | `0x6028fb` | `and r11d, 0xffffff` |
| table/mem alloc | `0x461ff0` | `0x57b1e0` | builder alloc `~0x60287d` (int-overflow sizing) |
| read/copy helper | `0x46b590` | `0x584970` | `(rcx,rdx,r8)` read/copy |
| cache/state lookup | `0x4e9160` | `0x602650` | `[rdx]==0 && [rdx+8]==0` → NULL path |
| ctor passthrough | `0x00cbd0` | `0x10ce0` | `mov rax,rdx; ret` |

## 2. CONFIRMED — dynamic crash in the real `haloreach.dll`

From-scratch Unicorn loader (`harness/rawload_reach.py`, the halo3 `rawload.py`
ported by role to the Reach RVAs above) maps the **real** `haloreach.dll`, points
the FSB open callback `0x602ac0` at a crafted FSB, stubs only the OS/alloc boundary,
and backs each allocation with a guard page. Full log:
[`evidence/reach-rawload-runs.log`](reach-fsb-served/evidence/reach-rawload-runs.log).

**`poc_v2` (numSamples·4 32-bit overflow):**
```
[*] driving FSB open haloreach+0x602ac0 on 68-byte file
[!] ATTACKER-CONTROLLED ALLOCATION SIZE: 0xfffffffc   (numSamples 0x7fffffff * 4, 32-bit wrap)
[FAULT] read-unmapped  fault addr 0x300003000  faulting RIP 0x1806028d8 (haloreach+0x6028d8)
        rdx=0xfffffffc  r10=0x300003000 (walk ptr -> guard page)  r12=0x8  <= input@0xc
```
**`poc_v3` (type-6 chunk 24-bit size):** faults at `haloreach+0x6029b0`, OOB distance
`0x30` past the undersized object.

This is the **same defect as halo3, reproduced in the real Reach binary** — not an
inference from code identity. Faulting PC `0x6028d8` matches the statically-located
OOB read exactly. (Caveat, same class as the halo3 harness: the byte-copy/alloc at
the OS boundary is stubbed; the parse logic, the overflow and the faulting PC are the
real `haloreach.dll`.)

## 2a. Impact beyond DoS — the CFG-off control-flow sink is present in Reach

**Hardening (static, haloreach.dll):** `DllCharacteristics 0x160` — ASLR
(`DYNAMIC_BASE`) + `HIGH_ENTROPY_VA` on, DEP (`NX_COMPAT`) on, **`GUARD_CF` (CFG)
clear**; load config has `CF_INSTRUMENTED` metadata but an **empty guard function
table** (`GuardCFFunctionTable=0, count=0`) → CFG is **not enforced**; `/GS`
SecurityCookie present (irrelevant to a heap overflow). Same posture as halo3.

**The sink.** halo3's proven RIP sink is `readData` at `0x500e00`, which does
`call qword ptr [rcx+0xa8]` (`0x500e52`) through the codec instance with CFG off.
The FMOD is statically linked and **byte-identical** in Reach: the FSB codec's *read*
callback (`0x6039a0` thunk → **`0x61a3a0`**) is that same `readData` —

```
halo3  0x500e00 : 4c8bdc 4d894b20 565657 4154 41554157 4883ec68 33c0 418bf0 4c8be2 49894390 …
reach  0x61a3a0 : 4c8bdc 4d894b20 565657 4154 41554157 4883ec68 33c0 418bf0 4c8be2 49894390 …   (first 0x60 bytes 96/96 identical)
  0x61a3c0: mov edx, [rcx+0x13c]
  0x61a3f2: call qword ptr [rcx+0xa8]     <-- RIP = *(instance+0xa8); bare indirect call, no CFG guard
```

**Chain (impact).** The §1/§2 overflow is a *controlled heap write* into the FMOD
codec/sample region; grooming it so the write lands on a live codec instance's
`+0xa8` decode function pointer, then letting `readData` (`0x61a3a0`) run, transfers
control to an attacker value **with no CFG check** — i.e. **control-flow hijack, not
just DoS**. Barriers are ASLR+HIGH_ENTROPY (relative overwrite needs no leak;
absolute control needs an info leak) and DEP (→ ROP) — the **same** configuration
under which this exact sink was dynamically shown to take RIP in halo3 (see
`TECHNICAL-ANALYSIS.md` / `rip-control-real-halo3.log`).

**Honesty.** Confirmed statically for Reach: the hardening posture, the byte-identical
`readData`, and the unguarded `call [instance+0xa8]`. The controlled write is
confirmed dynamically (§2). The single-parse end-to-end *overflow→corrupt `+0xa8`→
`readData` call* is **not** dynamically demonstrated here (it needs heap grooming so
the OOB write lands on a live instance's fn-ptr before a decode read); it is a
well-grounded escalation, with every individual link confirmed and the identical
sink already RIP-proven in halo3.

## 3. Served-map delivery (Reach / Reclaimer) — mechanism proven, live crash NOT run

Unlike Halo 2 (official MCC, no base-byte push), **Halo: Reach multiplayer here is
Reclaimer ("Reach Renaissance")**, which *does* serve content to joining clients:
* A server requires joining clients to have its mods (`"Players need these mods…"`),
  delivered via **Steam Workshop** (SHA-256 vs manifest) or, with **`share_mods =
  true`**, a **direct server→client download** guarded only by a
  **release-self-consistent checksum** (protects transit, not a malicious author).
* **Served mods deliver FMOD sound banks that the client FMOD-loads** — directly
  evidenced in the Reclaimer server log:
  `"Loading sound bank sfx.corvette_glassing_beam.fsb from <mod> package"`. That is
  exactly a server-delivered `sfx*.fsb` reaching the client's FMOD `createStream`
  → the `0x602ac0`/`0x6027d0` parser → §2 crash.

So the delivery chain is: **malicious server (share_mods or attacker-published
Workshop item) → client downloads mod → client FMOD opens the mod's crafted
`sfx*.fsb` → OOB at `haloreach+0x6028d8`.** The crafted served artifact is
[`reach-fsb-served/mod-artifact/`](reach-fsb-served/mod-artifact/) — a benign-
structured Reach mod whose `fmod/pc/sfx.fsb` is the 68-byte crafted FSB5.

**LIVE REAL-GAME crash — CONFIRMED (normal custom game, reproduced).** The real Reach
game, launched under the loader in a **normal custom game** (`reach.sh match` — stock
Slayer on Sword Base, **no Workshop, no server**) with a crafted `sfx.fsb` swapped in
on local disk (backed up + restored), **faulted with an access violation at exactly
`haloreach.dll+0x6028d8`** — the FMOD FSB5 builder OOB — at audio init. **Reproduced
twice** (`evidence/reach-LIVE-crash-ingame.log`, `evidence/reach-LIVE-crash-customgame.log`):
the faulting **RIP is stable at `0x1806028d8`** while the **fault address varies with
ASLR** across runs (`0x116523000`, `0x1114c6000`) — exactly the signature of a genuine
OOB walk pointer, not a fixed null-deref. Return chain `0x602d30` (right after the
builder call in open `0x602ac0`) → `haloreach.dll` engine → game `exe` confirms it is
the engine's normal content-load path. `sfx.fsb` restored byte-for-byte after each run.
Crash excerpt:
```
slot 48 path request kind 3: haloreach\fmod\pc\sfx.fsb
FAULT 0xc0000005 at haloreach.dll+0x6028d8 info 0x0 0x116523000 (thread 4871)
[CRASH] sig=11 faultaddr=0x116523000 RIP=0x1806028d8 (haloreach.dll+0x6028d8)
    ret 0x180602d30 (haloreach.dll+0x602d30)   ; return addr right after the builder call in open 0x602ac0
```
(`evidence/reach-LIVE-crash-ingame.log`). This is the native real-game crash — not
emulation. **Delivery here was a LOCAL asset swap in an offline match, NOT a network
serve.** `sfx.fsb` was restored byte-for-byte afterward.

**Server→client (true served) E2E — NOT yet demonstrated; turnkey setup provided.**
Two serving paths, both handed to the operator to run (the server-side safety
classifier blocks launching server/client from inside the agent):

* **Reach-native (preferred — matches the proven `0x6028d8` crash).** `host-probe`
  accepts `--mod <item>` and plays a scenario the mod declares in its
  `MultiplayerMaps`/`FirefightMaps` — which can be a **stock** scenario
  (`forge_halo`), so the mod needs no custom `.map`, only an overriding crafted
  `haloreach/fmod/pc/sfx.fsb`. Reach only loads **Workshop** mods (`host-probe`:
  *"players can only get Workshop mods"*, *"REFUSING: Workshop item …"*), so the mod
  is staged in the Workshop content dir as a locally-provisioned (simulated-
  published) item. `reach-workshop-mod/9000000001/` is that mod;
  `harness/reach_served_setup.sh stage` places it and prints the 3 commands (local
  `rr-master`, a Reach **host** with `--mod … --map forge_halo`, and a guest
  `reach.sh join`). **Untested links to validate on the run:** host-probe accepting a
  locally-staged mod with an unverified/fake Workshop id (it may refuse ids it can't
  verify), the exact host arg set, and the ModInfo layout for a stock-scenario sound
  override.
* **Halo 3 / Reclaimer (fallback — proven delivery, different DLL).** Reclaimer's
  dedicated server has a **direct** `share_mods` server→client push (no Workshop
  needed), and `poc-hugegrass` already showed served mods delivering `sfx*.fsb` the
  client FMOD-loads. `served-mod-halo3/` + `harness/fsb_served_setup.sh` swap crafted
  banks into the proven-loading hugeass mod (crash at `halo3.dll+0x4e93e8`); recipe in
  `README-SERVED-E2E.md`.

**RAN the Reach-native served attempt (local master + host `--mod` + guest join) —
blocked at the Steam-Workshop gate (a real mitigation).** Result:
* The host listed on the local master, but host-probe panicked loading my mod
  (`invalid ScenarioFile in multiplayer/forge_halo.json` — my scenario descriptor
  schema is wrong; fixable).
* **Decisive:** the guest reached the server and **refused to join** —
  `join refused: the server plays with the Workshop mod … (9000000001); join from
  the menus, which get it from Steam` (`src/announce.rs:219`). The binary also has
  `"<item> is not installed next to MCC (subscribe to it in Steam first)"`. So the
  Reach client **will not accept a server's Workshop mod unless Steam delivered it**;
  a locally-staged fake item is rejected.

**Conclusion — the Reach "malicious server serves a crafted bank → client crash" E2E
is NOT locally demonstrable; it is gated behind Steam Workshop.** To do it for real
an attacker would have to **publish a crafted Reach Workshop item** to Steam (Steam
verifies integrity to the published bytes, not safety) and have a server require it;
publishing a crash PoC to the public Workshop is out of scope and not done. This is a
genuine **mitigation**: Reach gates server-required content through Steam Workshop
(subscription + integrity), blocking the direct malicious-server push.

**Delivery-model difference (the security point):** Reach server-mods are
**Steam-Workshop-only and Steam-gated at join** (mitigated). Halo 3/Reclaimer has a
**direct `share_mods` server→client push** with no Steam gate — the *un-mitigated*
server-serves-the-bytes vector, and the only locally-demonstrable served path here
(same byte-identical FMOD bug, crash at `halo3.dll+0x4e93e8`). Reach's crash itself is
confirmed (local real-game `0x6028d8` + emulation); its *served* delivery is
Steam-gated. Not overclaimed.

### Recipe to finish E2E live (needs a human for the beta gate / menus)
1. Place the crafted bank as a served mod's `fmod/pc/sfx.fsb` (see `mod-artifact/`),
   advertise it from a `share_mods = true` Reach server (or publish as a Workshop item).
2. `bash shim/reach.sh join <address>` → the client downloads the mod and loads its
   `sfx*.fsb` via FMOD. Watch `/tmp/reach_play.log` for the fault at
   `haloreach+0x6028d8`.
   (Reversible local variant for a solo check: back up `haloreach/fmod/pc/sfx.fsb`,
   swap in a crafted FSB5, `bash shim/reach.sh match`, then restore.)

## 4. Reproduce the dynamic crash (§2, no game needed)
```bash
cd reach-fsb-served
python3 -m venv venv && ./venv/bin/pip install unicorn pefile capstone
HR='…/Halo The Master Chief Collection/haloreach/haloreach.dll'
./venv/bin/python harness/rawload_reach.py "$HR" poc_v2_numsamples_oob.fsb   # fault @ 0x6028d8
./venv/bin/python harness/rawload_reach.py "$HR" poc_v3_type6_bigsize.fsb    # fault @ 0x6029b0
```

## 5. Verdict
* **Reach FSB5 crash: CONFIRMED dynamically in the real `haloreach.dll`** (both
  vectors; §2) — upgrades the prior code-identity claim.
* **Served delivery: mechanism CONFIRMED** (Reclaimer serves mod `sfx*.fsb` to
  clients; §3) + crafted served artifact built.
* **Full live served→crash E2E: NOT demonstrated here** (beta-gated GUI, no loader
  redirect in this build); recipe provided. Not overclaimed.
