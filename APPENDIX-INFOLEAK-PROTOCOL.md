# FMOD/MCC ASLR-defeat info-leak hunt — plaintext & client-handler analysis

Authorized MSRC/CVP security research local only on the user's own
machine. Companion to the canonical report `TECHNICAL-ANALYSIS.md` (not edited here).
Capture-attempt log: [`infoleak-plaintext-capture.log`](infoleak-plaintext-capture.log).

## Question

Full RCE from the proven FMOD FSB5 memory-corruption bug (arbitrary RIP, CFG off) needs an
**information leak** to defeat ASLR (`HIGH_ENTROPY_VA` on). Under the **correct threat model** — the
attacker **controls the dedicated server**, is the **QUIC endpoint**, and therefore **decrypts
everything the client sends** — does any plaintext client→server message, or any client response to
a server-crafted command, disclose a **client-side pointer**?

Wire encryption is irrelevant and is **not** the argument here: the server holds the plaintext after
QUIC decryption. The real question is whether that *plaintext application layer* contains a pointer.

## TL;DR verdict

**NO LEAK FOUND in the protocol layers.** The two application protocols a malicious server sees after
decryption both encode **logical / quantized fields and opaque handles, never memory images or raw
pointers**, by construction:

* **Reclaimer transport/app layer (Rust):** `serde`-derived messages. serde serializes field values,
  never raw struct memory; no raw-pointer field; padding-leak-proof. A server-controlled length can
  at worst cause a **panic (DoS)**, not an over-read, because Rust slicing is bounds-checked and no
  `unsafe` raw-copy sits in the wire path.
* **halo3.dll game layer (C++):** a **bitstream** serializer (explicit per-field bit widths) over the
  **datum-handle** object model (32-bit index+salt). Game state is quantized and handle-referenced,
  not pointer-bearing — this is intrinsic to the engine (handles must survive across machines).

**One residual, UNTESTED path remains the only viable ASLR-defeat vector** and it is **not** a
protocol-field leak: the **FMOD OOB-read reflection** — a first (read-only) crafted bank whose
attacker-controlled over-read pulls adjacent heap/module bytes into a buffer that is then reflected
back to the server through game/FMOD state, before a second bank corrupts with the leaked address.
That is an **FMOD-layer experiment** (owned by the SDK/FMOD track), not a transport/netcode property.

> Scope honesty: no live post-map-load session plaintext was captured (the native gameplay bridge
> would not verify on this macOS PE-loader — see Method 3). The Reclaimer client is shipped as a
> **stripped release `.exe` only — there is no Rust source on this machine** (the handler files named
> in the tasking, `dispatch.rs`, `engine_transport.rs`, `client_bridge.rs`, `map_metadata.rs`,
> `megalo/vm.rs`, do not exist here). The handler analysis below is therefore **binary RE** of the
> client `.exe` and `halo3.dll`, not source reading. The verdict rests on serializer architecture +
> protocol direction + absence of unsafe raw-copy, which is decisive, but the FMOD-reflection path is
> the open item and should be tested on the FMOD track.

---

## 1. Plaintext-capture methods (which worked / why each failed)

| Method | Result | Evidence |
|---|---|---|
| **1. rustls key-log (`SSLKEYLOGFILE`)** | **Ruled out** | `SSLKEYLOGFILE` string count = **0** in both client exes; only `NoKeyLog` present (rustls's no-op default). `KeyLogFile` was never wired up, so no session-key export exists → Wireshark/tshark decrypt is impossible. |
| **2. AEAD crypto hook (ring seal/open)** | **Infeasible here** | Backend = `ring` (`'ring'`×45, `aes_gcm`, CHACHA20/POLY1305, `NoKeyLogRing`). ring's AEAD asm entry symbols are **stripped** (0 `ring_core_*`/`aes_gcm_*`/`GFp_*`), so there is no symbol to hook; and it would only expose the Rust app-layer plaintext, already shown pointer-free. |
| **3. Socket plaintext dump on the loopback native-UDP game transport** | **Instrument built; live capture did not reach gameplay** | Added env-gated `plain_dump()` to `i_ws2_WSASendMsg`/`i_ws2_WSARecvMsg` (see §4). Two runs (dedicated server + local client join), with and without `PELOAD_UDP_ROLE` host/client, both left `gameplay_join_verified=false` and the plain logs empty — the native bridge never verified on this loader. |

### Why the prior "all-QUIC, no leak" result was incomplete
The earlier experiment hex-dumped only `sendto`/`recvfrom`. But the engine's **loopback native-UDP
game transport uses `WSASendMsg`/`WSARecvMsg`** (confirmed in `peload.c`: *"the native-UDP
private-bridge transport uses these, NOT sendto/recvfrom"*), and those two functions called the UDP
*tracer* but **never the payload dumper**. So the plaintext game transport was structurally invisible
to that capture — its "100% QUIC" was an artifact of dumping the wrong syscall, not proof of no
plaintext. (Fixed by the new `PELOAD_DUMP_PLAIN` hook.)

## 2. Structural classification of the existing socket capture (`/tmp/udp_run1.txt`, 28,014 datagrams)

Classified by **header structure**, not entropy (full output in the capture log):

```
 13264  quic-short         (short header, fixed-bit set, 1-RTT)
 13497  short-nofixed      (short header, fixed-bit masked by header protection)
   797  quic-long(v=1)     (long header, QUIC v1 Initial/Handshake)
   316  long-nofixed
   140  empty
HALO MC/LC magic packets: 0        Pointer-range LE hits: 0
```

Both short-header buckets are dominated by the **same two 8-byte connection IDs**
(`436f2628d3c51c55` C2S, `211e8568ff7991da` S2C) → they are **one QUIC connection per direction**,
the first-byte variance being QUIC header protection, not a second transport. So the socket layer is
**100% QUIC ciphertext**: no HALO `MCx1`/`LCx1` plaintext game packets, **no x64 pointer-range
little-endian values** (code/stack `00007ff…`, heap `000001../000002..`), no uninitialized padding.
Consistent with the plaintext transport living on the un-dumped `WSASendMsg` path.

## 3. Static handler / serializer analysis (binary RE — the authoritative source)

### 3a. Reclaimer Rust client — the serde application protocol
serde's own derived error machinery leaves the full message taxonomy in the binary:

* **`Message` enum (gameplay/lobby control):** `PrepareMap`, `MapReady`, `MapFailed`, `Rejoining`,
  `PreviewRequest`(3 fields), `PreviewChunk`, `Countdown`(`millis_left`), `CountdownCancelled`,
  `Selected`, `Ballot`, `OdstStart`, and the Forge set (`ModeSizes/Teams/Hud`, `WidgetClick`,
  `Deployment`, `Objects`, `WorldForge`, `Scripting`, `ForgeProperties`, `ForgeTransforms`).
* **`ContentRequest` enum (mod/map transfer):** `Manifest`(1), `ManifestSources`(1), `Chunks`(1),
  `File`(2), `Range`(3); plus `struct ContentManifest` (4 elements). `CHUNK_SIZE_MAX_BYTES` is bounded.

Findings against the four leak classes the tasking asked for:

1. **Raw pointer/handle/address field — NONE.** Every `addr`/`pointer`/`handle`/`offset` string in
   the binary traces to Win32 imports (`WaitOnAddress`, `WakeByAddressSingle`, `CloseHandle`,
   `GetExternalIPAddress`), socket addressing (`public_address`, `socket_addr`, `sockaddr_in`), or
   PE-loader debug (`start_address_of_raw_data`) — not to a serialized protocol field. The only
   "handle"-like values the client exposes are **datum handles** (e.g. the live stats JSON shows
   `"unit":3850765073` = `0xE590FE11` and 8-byte `"key":[…]`), i.e. index+salt, not pointers.
2. **Server-controlled-length over-read — NONE in the Rust path.** serde reads a `Vec<u8>`/`&str`
   by its own encoded length from a correctly-sized buffer; a hostile length drives a
   **bounds-checked** slice → `panic` (DoS), not an over-read. Confirming the absence of an unsafe
   escape hatch: **0** occurrences of `from_raw_parts` / `slice::from_raw` / `set_len` /
   `copy_nonoverlapping` / `MaybeUninit` / `assume_init` in the client's strings.
3. **`#[repr(C)]` padding send — PREVENTED.** The only raw-byte-cast crates are `bytemuck 1.25.2` and
   `zerocopy 0.8.57`, whose `NoUninit`/`IntoBytes` traits **reject types with padding at compile
   time**; and their only call site is **`tiny-skia 0.11.4` `cast_slice`** (graphics pixmaps for the
   stats page/UI), **not** the wire protocol.
4. **A response echoing a buffer back at a server-chosen size — NOT PRESENT.** The request/response
   pairs are all **client-pull downloads** (`ContentRequest::{Manifest,Chunks,File,Range}` and the
   `PreviewRequest`→`PreviewChunk` / "`requestPreviewChunk`" flow). The client-facing strings
   ("*No server sent the chunk list of…*", "*preview ready*", PNG `IDAT/PLTE/IHDR` chunk errors)
   confirm the client **receives and parses** server content/preview chunks. That is the
   *server→client push* direction — i.e. the **corruption** surface (FMOD, PNG, variant parsers),
   **not** a client-memory-disclosure direction. No S2C command makes the client reflect a
   client-side buffer back at a server-chosen size.

**Ranked Rust candidates:** none rises above DoS. The closest "server-interrogates-client" shape,
`PreviewRequest`→`PreviewChunk`, is a download (server-origin content), so it cannot disclose client
memory; even if it sliced a client buffer, a bad range would panic, not over-read.

### 3b. halo3.dll — the C++ session netcode (the leak-prone layer)
The post-map-load C++ surface is where a leak would most plausibly live, and it is server-reachable
via the Megalo gametype script (fully server-authored) and the replicated game state. Binary strings
show the architecture:

* **`bitstream` / bit_stream** serializer — Halo 3 encodes network/game-state fields into a bitstream
  with explicit per-field bit widths (quantized positions, orientations, input, timers). A bitstream
  writer emits exact bit counts per field; it does **not** `memcpy` structs, so trailing-padding
  disclosure is not the default failure mode.
* **datum-handle model** — `%s Salt Length: 0x…`, `?game_state_header`, `sim. gamestate entities`,
  `biped_handle_simulation_warp`, `Simulation Priority`. Objects are referenced by **datum handle
  (index+salt)**, never by pointer — mandatory for cross-machine replication and save/resume.

**Consequence:** the halo3 game packets a malicious server receives carry quantized state and datum
handles, not pointers — so the *protocol fields* do not leak ASLR'd addresses either.

**Residual (untested) halo3 risks**, to be explicit about what was *not* ruled out by RE alone:
* A **variable-length bitstream field** (player name, Forge label, chat, a Megalo-emitted string)
  whose length/bit-count is miscomputed could over-read adjacent memory into the outgoing bitstream —
  a classic C++ leak, but **not evidenced**; confirming/denying it needs targeted RE of the specific
  packet builders (not completed here).
* The **FMOD OOB-read reflection** chain (see TL;DR) — the one path that is both server-controllable
  and genuinely capable of placing *arbitrary adjacent memory* (potentially a pointer) where it could
  be reflected. This is the recommended next experiment and belongs to the FMOD track.

## 4. Loader instrument added (env-gated, OFF by default)

`shim/src/peload.c`:
* `plain_dump(dir,buf,len,ss)` (~line 2916) — hex-dumps the full plaintext datagram + peer port +
  8-byte ASCII magic. Gated on `PELOAD_DUMP_PLAIN=<file>`; inert when unset (mirrors the existing
  `PELOAD_DUMP_UDP` `udp_dump`).
* Wired into `i_ws2_WSASendMsg` (TX, reassembled gather buffer) and `i_ws2_WSARecvMsg` (RX) — the
  loopback native-UDP game transport. Rebuilt with `bash shim/build.sh` (clean).

To use once the native join can be made to verify on this loader:
```
DED_ENV="PELOAD_DUMP_PLAIN=/path/server.log PELOAD_UDP_ROLE=host" bash shim/dedicated.sh
RECLAIMER_JOIN=127.0.0.1:49190 PELOAD_DUMP_PLAIN=/path/client.log PELOAD_UDP_ROLE=client bash shim/play.sh
```
then scan with `scratchpad/classify.py` (pointer-range + MC/LC magic classifier).

## 5. Verdict

**NO LEAK FOUND in either application-protocol layer** that a malicious decrypting server observes:
* Reclaimer serde layer — pointer-free, padding-proof, bounds-checked; raw casts confined to graphics;
  request/response pairs are client-pull downloads (wrong direction for a client-memory leak).
* halo3 bitstream/datum-handle layer — quantized fields + opaque handles, not pointers.

**What remains untested (and is the only credible ASLR-defeat route):** the **FMOD same-bank
controlled OOB *read* reflected back to the server** (bank #1 leaks → defeat ASLR → bank #2 corrupts).
This is an FMOD-layer experiment and is explicitly out of this track's reach; recommend the FMOD/SDK
track attempt to (a) point the OOB read at a known pointer-bearing structure and (b) find an in-engine
path that reflects those bytes into server-visible state. Also untested: a miscomputed variable-length
bitstream field in halo3's netcode (needs targeted packet-builder RE).

Live post-map-load session plaintext was **not** captured here because the native gameplay bridge
would not verify on this macOS PE-loader; the `PELOAD_DUMP_PLAIN` instrument is in place to capture it
whenever a verified join is achievable (native Windows MCC, or once the loader's join flakiness is
resolved).
