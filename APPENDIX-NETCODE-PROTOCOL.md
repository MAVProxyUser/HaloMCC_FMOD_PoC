# Appendix — the Blam netcode protocol: message inventory + memory-corruption triage

Companion to [`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md) and
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md) §7.3/§12. This enumerates the client↔server protocol
**once the Reclaimer control layer hands off to the actual game backend** (the Halo 3 "Blam" engine
session in `halo3.dll`), says **why no message is useful as an ASLR info-leak**, and then **triages the
netcode for other memory-corruption classes** (leaks, UAF/double-free, format strings, negative-length
`memcpy`, integer overflow, index/salt confusion).

**Provenance & honesty.** The message names below are **binary-sourced** — recovered from `halo3.dll`
strings/RTTI and the Reclaimer client's `serde` machinery (a stripped release `.exe`). Message
*direction* and *payload shape* are **RE-derived** from the Blam engine architecture, not byte-proven
per field. The corruption triage in §5 lists **candidate surfaces with the evidence and the bug class
to check** — **none is a confirmed bug**; the only confirmed memory-corruption in this research is the
**FMOD FSB5** defect (which is in FMOD, not the Blam netcode). Confirming any §5 item needs
disassembly of the specific handler + a replay/fuzz harness (§6).

---

## 1. Two layers

```
  client  <= QUIC/quinn+rustls =>  server          (transport; encrypted on the wire, plaintext at the server)
      |                                |
      |  (A) Reclaimer control/content (Rust, serde)   -- lobby, map prep, mod/map transfer
      |  (B) halo3 Blam engine session (C++, bitstream) -- the in-match game backend
```

The attacker controls the **server/host**, so every "server→client" row below is attacker-emittable,
and every "client→server" row is something the attacker-server receives in plaintext.

---

## 2. Why no message leaks a client pointer — by construction

Confirmed from `halo3.dll`: the session layer is a **bitstream** (`bitstream`, `net_bitstream_debug`,
`net_bitstream_display_errors`, `net_bitstream_capture_structure`, `net_simulation_set_stream_bandwidth`)
over the engine's **datum-handle** object model — objects are referenced by a **32-bit handle = 16-bit
index + 16-bit salt** (`%s Salt Length: 0x`, `hexsalt`, `biped_handle_simulation_warp`,
`sim. gamestate entities`, `?game_state_header`, `game_state_verify_on_read/write`,
`determinism_debug_manager_enable_game_state_checksum`).

Two structural facts make a raw-pointer leak impossible *by design*:

* **Handles, not pointers.** Every object reference on the wire is an index+salt datum-handle, never a
  memory address. This is mandatory: the **same object must be addressable on every machine**, each
  with its own ASLR layout — a raw pointer would be meaningless cross-machine.
* **Quantized fields.** Positions/orientations/velocities/timers are encoded at **explicit bit widths**
  (quantized), not as native 32/64-bit values — a bitstream writer emits exact bit counts, so there is
  no 64-bit pointer slot and no `memcpy`-of-struct that would ship trailing padding by default.

So the netcode protocol fields carry **quantized state + opaque handles + enum/result codes + values**,
not ASLR'd addresses. (The Reclaimer `serde` layer is likewise value-serialized and pointer-free —
[`APPENDIX-INFOLEAK-PROTOCOL.md`](APPENDIX-INFOLEAK-PROTOCOL.md).) The residual leak path is **not** a
protocol field — it is a *miscomputed variable-length field* that over-reads adjacent memory into an
outgoing packet (§5.1), or the FMOD OOB-read reflection (separate appendix) — both unconfirmed.

---

## 3. Layer A — Reclaimer control/content messages (Rust `serde`)

Binary-recovered from the client's serde error machinery. All are value-serialized; request/response
pairs are **client-pull downloads** (server→client content *push* = the corruption direction, not a
disclosure one); a hostile length drives a **bounds-checked panic (DoS)**, not an over-read (zero
`from_raw_parts`/`set_len`/`copy_nonoverlapping`/`MaybeUninit` in the wire path).

| Message (enum variant) | Dir | Payload (shape) | Why not an info-leak |
|---|---|---|---|
| `PrepareMap` / `MapReady` / `MapFailed` / `Rejoining` | S→C / C→S | map id, ready/fail status | logical ids + enums |
| `PreviewRequest`(3) → `PreviewChunk` | C→S / S→C | preview id, chunk index/range → PNG bytes | **client pull**; server-origin content (corruption dir, not disclosure) |
| `ContentRequest::{Manifest, ManifestSources, Chunks, File, Range}` + `ContentManifest` | C→S / S→C | content hashes, chunk/file/byte ranges → mod/map bytes | **client pull download**; `CHUNK_SIZE_MAX_BYTES` bounded; serde value-typed |
| `Countdown`(`millis_left`) / `CountdownCancelled` | S→C | milliseconds | scalar |
| `Selected` / `Ballot` | S→C / C→S | map/mode id, vote | ids/enums |
| `OdstStart` | S→C | mode start flag | enum |
| Forge: `ModeSizes`/`Teams`/`Hud`, `WidgetClick`, `Deployment`, `Objects`, `WorldForge`, `Scripting`, `ForgeProperties`, `ForgeTransforms` | S↔C | widget/object ids, quantized transforms, script refs | ids + quantized values; `#[repr(C)]` padding sends rejected at compile time (bytemuck/zerocopy), raw casts confined to `tiny-skia` (UI) |

**Verdict (Layer A):** no field carries a client pointer; disclosure direction is wrong (pulls are
server→client content). Memory-safe Rust ⇒ a malformed field is a panic (DoS), not a leak.

---

## 4. Layer B — halo3 Blam engine session messages (C++ bitstream)

Binary-confirmed tokens in `halo3.dll`. Direction/payload are RE-derived from the Blam host/peer model
(the Reclaimer dedicated server is the authoritative **host**; clients are peers).

| Message | Dir | Payload (shape) | Why not an info-leak |
|---|---|---|---|
| `join-request` / `join-abort` / `join-refuse` / `join-info` | C↔H | version, NAT type, `join_failed_*` result codes | enums/values; NAT type is a category |
| `membership-update` | H→C | roster: machine/player **indices**, identity (XUID/gamertag), connection **IP:port** | indices + network addresses (IP:port ≠ memory ptr; and the host already has your IP) |
| `time-synchronize` | H↔C | tick/clock values | scalars |
| `boot-machine` / `host-decline` / `host-handoff` / `delegate-leadership` | H→C | machine index, leadership token | indices/tokens (see §5.4 for the *lifecycle* risk) |
| `player-add` / `player-remove` / `parameters-update` | H→C | player index, appearance/team/`service_tag`/`player_name`, settings | enums + quantized + **length-prefixed strings** (see §5.1) |
| `synchronous-update` / `synchronous-client-ready` / `synchronous-actions` | H↔C | deterministic sim step: object **datum-handles** + **quantized** transforms/state + input actions | handles + quantized fields (no pointer by construction, §2) |
| object creation / deletion / update (sim entities) | H→C | object type, datum-handle (index+salt), quantized transform/health/flags | handle not pointer; quantized |
| `game_event` / `game-results` / `statborg` | H→C | game-engine events (score, medal, teleport, respawn), end-game stats | quantized values + handles |
| `c_controller_input_message` | C→H | per-tick input (sticks/buttons/triggers) | quantized input |
| `voice-*` (`voice_output`, `voice_proximity`, `voice_matchmaking`, `voice-repeater`, `voice_mute`) | C↔H→C | encoded mic frames + routing (proximity/team) + player handle | audio payload + handles; **separate mic-capture pipeline**, not fed by the sfx/FMOD decoder (so the FMOD over-read cannot flow here) |
| Megalo variant/script state | H→C | server-authored gametype script + replicated Megalo variables | logical variables; but the *VM* is a code-exec surface — §5.5 |

**Verdict (Layer B):** quantized state + datum-handles + enums/result codes + network addresses — no
ASLR'd client pointer in any field. The disclosure the malicious host *does* get (IP:port, gamertag,
service tag) it already has by virtue of the client connecting; none helps defeat `HIGH_ENTROPY_VA`.

---

## 5. Memory-corruption triage of the Blam netcode (candidate surfaces, graded)

**None of these is a confirmed bug.** They are the surfaces where, *by class*, a Blam-style C++ netcode
is most likely to contain memory-corruption, with the binary evidence that marks each as a candidate
and the exact check that would confirm or refute it. Ranked by plausibility.

### 5.1 Variable-length wire strings → OOB read/write or uninitialized-send leak — **HIGH interest**
Evidence: `player_name`, `service_tag[1-4]`, `chud_talking_player_name`, `chud_variant_name`,
`game_variant_name`, `map_variant_name`, chat; plus a **network-string validation layer**
(`network_string_failed_game_variant_name`, `network_string_failed_map_variant_name`,
`*_name_invalid`/`*_name_verifying`). Class: a wire-supplied length/terminator copied into a fixed
buffer (UTF-8/UTF-16) without a correct bound → **over-write** (corruption) or **over-read** (the one
real info-leak path: trailing bytes beyond the intended string copied into the outgoing/stored buffer).
Why candidate: same family as the FMOD bug; names/tags are attacker-set and replicated. Mitigating:
the `network_string` validator exists — but validation *after* a copy doesn't prevent an over-read
*during* it. **Confirm:** disassemble the variant-name / `player_name` bitstream reader and check the
length clamp vs. the destination buffer size.

### 5.2 Wire-supplied counts/array lengths → integer overflow / OOB — **MEDIUM**
Evidence: hard caps exist (`too many players in forge`, `too many teams`, `too many temporary
variables`, `too many units match this seat substring`), and `EXCEPTION_INT_OVERFLOW` /
`EXCEPTION_ARRAY_BOUNDS_EXCEEDED` are handled. Class: a count read from the wire used to size/index an
allocation or loop **before** the cap check (exactly the FSB5 `numSamples*4` shape). Why candidate:
Forge object arrays, Megalo variable arrays, roster counts are wire-driven. Mitigating: the explicit
caps suggest many counts *are* bounded. **Confirm:** trace each `bitstream read count → alloc/index`
site for a 32-bit multiply or a pre-cap index.

### 5.3 Datum-handle index/salt confusion → OOB / type confusion — **MEDIUM**
Evidence: the datum-handle model + `game_state_verify_on_read/write`, salt handling for game state.
Class: a wire-supplied handle whose **index** isn't range-checked against the object-pool size before
dereference, or whose **salt** mismatch is mishandled → OOB array access or stale-object type
confusion. Why candidate: `synchronous-*` and object update messages carry handles chosen by the host.
Mitigating: salt is the engine's own stale-handle guard. **Confirm:** disassemble the object-update
handler's `handle → object_pool[index]` path for the index bound + salt compare.

### 5.4 Host-migration / reconnect lifecycle → UAF / double-free — **MEDIUM, hard to confirm**
Evidence: `net_speculative_host_migration_disable`, `net_enable_host_migration_loop`,
`delegate-leadership`, `host-handoff`, `boot-machine`, `player-remove`, `ai_reconnect`. Class:
object/player/session lifecycle across a host handoff or a mid-session reconnect is a classic
**use-after-free / double-free** surface (re-entrancy, two machines freeing the same session object,
a `player-remove` racing an in-flight `synchronous-*`). Why candidate: speculative host migration is
inherently racy and server-driven. **Confirm:** model the migration state machine; look for a session/
player object freed on `player-remove`/handoff then referenced by a queued simulation message.

### 5.5 Megalo VM — server-authored script interpreted by the client — **HIGH interest**
Evidence: the Reclaimer variant embeds a full **Megalo** script (seen verbatim in the client exe:
`alias`, `on init`, widget/number/timer variables, class cards). The **server fully authors** the
gametype/variant, and the **client runs its Megalo bytecode/variables**. Class: a bytecode VM fed
attacker-controlled script is a rich memory-safety surface — opcode handlers with wire-controlled
operands, variable-array indices, string/widget tables, stack/recursion depth (`depth exceeded`,
`too many temporary variables` hint at VM limits). Why candidate: this is the **most direct
"server command the client honors"** that is also code/data-interpretation, not just state. **Confirm:**
disassemble the Megalo opcode dispatch + variable-index handling for bounds on wire-supplied indices
and operand counts.

### 5.6 Format strings — **LOW (ruled down)**
No attacker-controlled `printf`-style format sink was found; the `%n`-ish byte sequences are code/data
coincidences, not format strings, and Halo passes player text as `%s` **arguments**, not as the format.
Not a plausible class here.

### 5.7 Negative / unsigned-length `memcpy` — folds into 5.1/5.2
A signed length read as `int` and reinterpreted as a huge `size_t` in a copy is the specific mechanism
behind 5.1/5.2; call it out when disassembling those copies (look for `movsx`/signed compare before an
unsigned-width copy).

**Summary grade:** the **highest-value audit targets** are **5.1 (variable-length name/variant/chat
strings)** and **5.5 (the Megalo VM)** — both are server→client, attacker-authored, and
variable-length/interpreted; **5.2–5.4** are solid secondary targets. All are **candidates**, not
findings.

---

## 6. How to confirm (method)

Same playbook as the FMOD work: (1) disassemble the specific handler in `halo3.dll` (e.g. the
variant-name bitstream reader, the Megalo opcode dispatch, the object-update `handle→pool[index]`),
checking the length/index clamp against the destination; (2) build a **replay/fuzz harness** that
frames a single Blam message and feeds mutated length/count/handle/string fields — either by
instrumenting the Reclaimer dedicated server to emit a crafted message, or by driving the handler
directly in a from-scratch loader like `rawload.py`; (3) run under a crash handler / guard pages and
watch for the fault, exactly as `poc_v2` was driven through FMOD. Until that is done, §5 stays
**candidate surfaces**, not confirmed vulnerabilities.

## 7. Limits

Binary RE of a stripped client `.exe` + `halo3.dll` strings/RTTI; no source, no byte-level proof of any
§5 item. The §2 "no pointer by construction" conclusion is architectural and strong; the §4/§3
per-message payloads are RE-derived; §5 is a prioritized audit map, not a bug list. The only confirmed
memory-corruption in this research remains the FMOD FSB5 defect ([`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md)).
