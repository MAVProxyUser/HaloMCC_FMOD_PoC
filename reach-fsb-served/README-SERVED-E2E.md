# Server→client served-FSB crash — run guide (Halo 3 Reclaimer)

The attack: a **malicious server** serves a mod whose `halo3/fmod/pc/*.fsb` bank is a
crafted FSB5 (numSamples·4 overflow). A joining client **downloads** that bank via
`share_mods` and faults in FMOD at **`halo3.dll+0x4e93e8`** when it loads it. (Same
FMOD bug proven live in `haloreach.dll` at `0x6028d8`; Reach's own MP is join-only
here, so the *served* path runs on the Halo 3 dedicated server.)

## The key design rule (you called this out)
**The client must stay CLEAN so it never crashes on a local file — the crafted bank
must arrive from the server.** So:
- The client's **shipped** banks (`…/MCC/halo3/fmod/pc/*.fsb`, `…/haloreach/…`) stay
  ORIGINAL. (Verified clean; the earlier local `sfx.fsb` test was restored.)
- The crafted bank lives **only in what the server serves**
  (`ReclaimerTestServer/content/Mods/…`), never in the client's own content.
- The client must **not already have** that mod, so `share_mods` forces a download.

### Single-machine caveat (important)
Server and client share one loader prefix here, so the client can *see the server's
content folder directly* — then a crafted bank there is both "served" and "local",
which is not a clean proof (and can look like the client crashing itself).
**For an unambiguous server→client demo, run the client from a separate, clean
profile/prefix (ideally a second machine) pointed at this server, with an empty
`ReclaimerContent/Mods/Downloaded`.** Then the only way it gets the crafted bank is
over the wire from the server.

## Steps
1. **Put the crafted banks on the SERVER only** (reversible; backs up originals):
   ```bash
   bash .../scratchpad/fsb_served_setup.sh install
   ```
   This swaps the crafted FSB5 into the server's served hugeass banks
   (`ReclaimerTestServer/content/Mods/Workshop/2984061723/halo3/fmod/pc/…`) and sets
   `share_mods = true`. It does **not** touch any client bank.

2. **Make sure the active server game USES that mod** (so clients must download it):
   the `[[server]]` must reference the mod's map, e.g. in `dedicated.toml`:
   ```toml
   [[server]]
   name = "FSB PoC"
   port = 49190
   base_map = "workshop:2984061723/hugeass_remastered_mcc"
   game = "Slayer"
   ```
   (or start the existing `poc-hugegrass` instance, which already plays this mod).

3. **Start the server:**
   ```bash
   bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh
   bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh status   # ready?
   ```

4. **Join from a CLEAN client** (separate profile/prefix; empty downloaded-mods), so
   it downloads the mod from the server, with FMOD guard pages on:
   ```bash
   PELOAD_AUTO_MODS=1 PELOAD_ALLOC_GUARD=1 RECLAIMER_JOIN=127.0.0.1:49190 \
     bash ~/Desktop/HaloReclaimerMac/shim/play.sh
   ```

5. **Confirm the served crash:**
   ```bash
   grep -nE "download|sound bank|\.fsb|0x4e93e8|0x4e92e0|c0000005|CRASH|FAULT" \
     /tmp/reach_play.log /tmp/reclaimer_*.log
   ```
   Expected: the client logs downloading the mod, then
   `FAULT 0xc0000005 at halo3.dll+0x4e93e8` as FMOD parses the **server-delivered** bank.

## Clean up
```bash
bash ~/Desktop/HaloReclaimerMac/shim/dedicated.sh stop
bash .../scratchpad/fsb_served_setup.sh clean    # restores server banks + dedicated.toml
```

## Honest status
Not yet run end-to-end here (the server-side safety classifier blocks launching the
server/client from inside the agent, and the client-clean separation wants a second
profile). The real-game crash on a crafted bank is already confirmed natively
(`evidence/reach-LIVE-crash-ingame.log`, `haloreach.dll+0x6028d8`); this guide wires
the *delivery* so the crafted bank comes from the server. Run it and share
`/tmp/reach_play.log` + the server log and we close the last link.
