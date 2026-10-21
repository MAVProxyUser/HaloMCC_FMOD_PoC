# Appendix — Halo 2 (classic) game-variant `.bin`: format map + parser memory-safety audit

Companion to [`APPENDIX-NETCODE-PROTOCOL.md`](APPENDIX-NETCODE-PROTOCOL.md) and
[`TECHNICAL-ANALYSIS.md`](TECHNICAL-ANALYSIS.md). This audits a **separate, smaller attack surface**
from the FMOD FSB5 work: the server-selectable / host-authored **Halo 2 multiplayer game-variant**
files (`halo2/game_variants/*.bin`, `halo2/hopper_game_variants/*.bin`) and the C++ parser that
consumes them in **`halo2.dll`** (sha1 `7129e1389ec3fe59a30b2a3653d8ee37d44adcc1`, the Miles/XAudio2
title that the FSB5 work already cleared of FMOD — see TECHNICAL-ANALYSIS §3.2).

## Provenance & honesty (read first)

- **Format map** (§1) is **byte-proven**: produced by diffing all 40 stock `game_variants/*.bin` plus
  the hopper set. Field *offsets* and which bytes are attacker-variable are exact; the *semantics* of
  individual metadata integers are inferred from field-name strings in `halo2.dll` and are not all
  byte-proven.
- **Parser location + bound analysis** (§2–§4) is **binary-sourced** — disassembled from `halo2.dll`
  with capstone, functions resolved via the `.pdata` (`RUNTIME_FUNCTION`) table. RVAs are exact.
- **Dynamic result** (§5) is a **from-scratch Unicorn emulation** of the real decode leaf functions on
  attacker-controlled bitstream bytes, with a working **positive control** proving the harness detects
  an out-of-bounds write.
- **Verdict (§6): NO confirmed memory-corruption bug on this surface.** Every attacker-controlled
  length / count / index I traced is bounded (hard compile-time limits, caller clamps, EOF-guarded bit
  reader, bounds-checked dispatch). This surface is graded **candidate-negative / hardened**. The only
  confirmed memory-corruption defect in this whole research remains the **FMOD FSB5** bug, which is
  **not** in `halo2.dll`. I state the scope limits explicitly in §6.

All work is local, on the user's own authorized MCC install. Nothing published.

---

## 1. The `.bin` format — byte-proven map

Every stock variant file is a **fixed 1312 bytes (`0x520`)** — there is no file-level length or count
field that drives the file size. It is the MCC "content header" wrapper (a flat serialized struct +
localization keys + an RSA signature footer), **not** a classic Xbox BLF file (it does not begin with
a `_blf` chunk).

Diffing all 40 variants, only these byte ranges vary (i.e. are attacker-controllable in a
hand-crafted file):

| Offset range | Field | Notes |
|---|---|---|
| `0x00` u32 | per-file index | observed `idx << 24` (01→0, 02→`0x01000000`, 03→`0x02000000`…). **Not a length.** |
| `0x04` .. ~`0x44` | UTF-16 title key #1 | null-terminated UTF-16, e.g. `"$slayer"`. `$`-prefix = localization key. Fixed buffer. |
| `0x44` .. `0x10a` | flat int metadata | game-engine parameters (e.g. `0x44`=category, `0x48`=score/target, `0x50`=time, `0x80`/`0x84`=5, `0xa8`=2, `0xac`=10). Inferred semantics. |
| `0x130` .. `0x156` | UTF-16 title key #2 | duplicate of the name key. |
| `0x230` .. `0x260` | UTF-16 description key | e.g. `"$slayer_desc"`. |
| `0x330`, `0x340` | u32 timestamp ×2 | `0x5de61600` on the stock set (duplicated). |
| `0x350` | **`_fsm` signature chunk** | magic `5F 66 73 6D` = `"_fsm"`, then **big-endian** length `00 00 01 D0` = `0x1D0` = 464 = exactly the bytes from `0x350` to EOF, then version `00 01` / `00 01`. |
| `0x3b0` .. `0x3cf` | 32-byte per-file hash/nonce | fully varies per file. |
| `0x3f4` .. `0x41b` | 40 ASCII hex — **constant** | e.g. `85E3D5677B0D64FD91FACB25D696BF315CB062A1`. Identical across all files ⇒ a **signing-key fingerprint**, not a per-file digest. |
| `0x41c` .. `0x51b` | **256-byte block** | fully varies per file ⇒ an **RSA-2048 signature**. |

Everything else (the `0x00`-region padding, the structural constants) is identical across all 40 files.

**Security-relevant consequences of the format:**
1. **Fixed file size** ⇒ no file-length-driven read/alloc at load; a crafted file that is longer or
   shorter does not grow a copy. (The generic named-`.bin` loader is `halo2+0x6afeb0`, which builds
   `core\%s.bin` / `%s.bin` and is shared by many resources such as `loading_dx11.bin`.)
2. **The file is RSA-signed.** `halo2.dll` statically links a full OpenSSL-derived RSA/SHA-1 stack
   (strings `crypto\rsa\rsa_sign.c`, `rsa_lib.c`, `RSA-SHA1`, `digest too big for rsa key`,
   `data too large for modulus`, `bignum too long`, X509…). The `_fsm` footer + 256-byte signature +
   constant key fingerprint are the artifact of that signing. (I did **not** byte-trace the verify
   call firing on this specific file — the signature *structure* and the crypto code are proven; the
   ordering of verify-vs-parse for the on-disk path is **not** proven here.)
3. The on-disk flat struct is **not** the only representation. When a host serves a variant to clients
   in a session, the variant travels the **Blam bitstream** (the network/saved-game serialization
   layer), decoded field-by-field into the in-memory struct. That bitstream decode — §2 — is the real
   server→client delivery parser and the focus of this audit.

---

## 2. Where variants are parsed in `halo2.dll`

The in-memory / network decode is driven by a **field-descriptor serialization** pattern: each field is
read by a named primitive taking `(c_bitstream*, …, bit_count | max_len)`. The field-name strings
(`game-variant-name`, `variant-count`, `variant-game-engine-index`, `variant-flags`, `map-count`,
`scenario-path`, `random-seed`, …) live in `.rdata` and are passed to the primitives; I used them to
locate the routines.

**Serialization routines for the session/variant container** (reached indirectly through the
serialization registrar, i.e. via a function-pointer table — the standard Blam pattern; no direct
`call` xrefs, consistent with net-replication dispatch):

| RVA | Role |
|---|---|
| `0x8b6ae1` (len `0x89c`) | **main decode-from-bitstream** of the session/game-state struct: `map-valid`, `scenario-path`, `map-count`+`mcc-map-id[]`, `game-instance`, `random-seed`, `simulation-protocol`, `variant-valid`, **`variant-count` + the game-variant array**. |
| `0x8b6484` (len `0x25e`) | sibling (variant-count/name) |
| `0x8b7dc1`, `0x8b82fe` | sibling encode/verify (variant-count/name) |
| `0x8909f0` | decode `variant-game-engine-index` (4-bit) into `variant+0x44`; if 0, `memset(variant,0,0x130)` |

**The shared bitstream primitives** (the whole safety of the surface reduces to these):

| RVA | Primitive | Bound mechanism |
|---|---|---|
| `0x741260` | **core bit reader** `read(bits)` | **EOF-clamped** — see §3.1 |
| `0x741300` | `read_integer(bits)` | tail-calls `0x741260` |
| `0x741310` | `read_qword(bits≤64)` | two `0x741260` reads |
| `0x741200` | `read_bool()` | 1 bit via `0x741260` |
| `0x7416b0` | **`read_wstring(dst, max_chars)`** | **hard bound to `max_chars`** — see §3.2 |
| `0x741040` (via `0x741590`) | **`read_blob(dst, max_bits)`** | **EOF-clamped**; copies `min(remaining, max_bits)/8` bytes — see §3.3 |
| `0x7415b0` | fixed wide-string + `0x100`-byte read | compile-time max (`0x20` chars + `0x100`) |

And the variant **rules** decode (separate from the container above):

| RVA | Role |
|---|---|
| `0x890a36` (len `0x7e6`) | **decode the per-engine game-variant rules** into the `0x130`-byte rules block (`round-setting`, `max-players`, `maximum-allowable-teams`, `lives-per-round`, `respawn-time`, `weapon-set`, CTF/oddball/king/juggernaut/territories fields…) — §3.5 |
| `0x8909f0` | reads only the 4-bit engine index (`+0x44`); zero-fills the `0x130` rules block if index==0 |
| `0x84a0c1` | **apply** dispatch on the engine index — bounds-checked jump table (§3.4) |
| `0x8a1070` (len `0x2af`) | `simulation-data` decode incl. the `filler-size-bits` variable-length field — §3.6 |

---

## 3. Static triage — the three attacker-controlled classes, and why each is bounded

### 3.1 Counts (loop/array drivers): **clamped by the caller**

`variant-count` (`0x8b6cd4`) is read with **max = 2** (`r8d = 2`), then clamped before use:

```
0x8b6cd1  mov  r8d, ebp            ; ebp = 2
0x8b6cd4  lea  rdx, ['variant-count']
0x8b6cde  call 0x741300            ; read_integer -> al (signed)
...
0x8b6cf4  cmp  cl, 2
0x8b6cf7  jg   ...                 ; clamp high
0x8b6d17  cmovg eax, ebp           ; = min(value, 2)
0x8b6d1a  mov  byte [rdi+0x261], al ; stored count, <= 2
0x8b6d25  jle  ...                 ; loop only while i < stored count
0x8b6d40  imul rcx, rax, 0x758     ; variant record stride 0x758, base [rdi+0x268]
```

So at most 2 variant records (each `0x758` bytes) are written into the fixed array at `rdi+0x268`.
`map-count` (`0x8b6b5e`→`[rdi+0x160]`, loop into `rdi+0x164 + i*0x10`) uses the identical
`cmp/jg/cmovg` clamp. **No unclamped count reaches a loop or an index.**

### 3.2 Strings (copy drivers): **hard-bounded, no attacker length field**

`game-variant-name` and `game-variant-description` are read by `sub_7416b0(bitstream, dst, max=0x80)`
(`0x8b6d85`, `0x8b6d69`). There is **no length prefix** — the reader pulls 16-bit chars one at a time
until a null char **or** until `max_chars`, and can never write past `dst[max-1]`:

```
0x7416cb  movsxd rsi, r9d          ; rsi = max_chars (= 0x80 at both call sites)
0x7416e0  loop: read 16 bits (0x741260) -> ax
0x7416ed        mov [rdi], ax      ; store char
0x7416f0        test ax,ax ; je tail  (null -> stop + zero-fill remainder)
0x7416f5        inc ebx ; add rdi,2
0x7416fb        cmp ebx, esi ; jl loop   ; i < max
0x7416ff  mov  [r14 + rsi*2 - 2], 0  ; force-null dst[max-1]  (in bounds)
```

Destination fields are `0x100` bytes apart (`rdi+0x398` name, `rdi+0x498` desc) = 128 UTF-16 chars =
exactly `max`. So a maximally hostile all-non-null bitstream writes exactly 128 chars and stops.
`mcc-map-id`/`game-instance` use the same pattern with `max` = `0x20`/`0x40`.

### 3.3 The core bit reader: **cannot read past the buffer**

`sub_741260` clamps the requested bit count to what remains in the stream, so an over-long or
truncated/crafted stream yields zero-filled values instead of an OOB read:

```
0x741262  mov r8d, [rcx+8]   ; data_size_bytes
0x741268  mov r10d,[rcx+0x14]; current_bit_pos
0x74126e  shl r8d, 3         ; total_bits = size*8
0x741275  sub r8d, r10d      ; remaining = total - pos
0x741278  cmp r8d, edx       ; remaining vs requested
0x74127b  cmovg r8d, edx     ; read = min(remaining, requested)
0x74127f  test r8d,r8d ; jle -> return 0   ; past EOF -> 0, reads nothing
```

(`c_bitstream` layout recovered: `+0`=data ptr, `+8`=size bytes, `+0x14`=bit position, `+0x18`=flag.)

### 3.4 The game-engine-index dispatch: **bounds-checked jump table**

`variant-game-engine-index` is a **4-bit** field (`sub_8909f0`: `read_integer(bits=4)` → `variant+0x44`,
value 0–15). The apply/dispatch (`0x84a0c1`) validates it before the jump table:

```
0x84a182  mov ecx, [rax+0x44]     ; engine index
0x84a185  dec ecx
0x84a187  cmp ecx, 8
0x84a18a  ja  0x84a1f6            ; (index-1) > 8  ->  "unknown game engine type"  (safe default)
0x84a18f  mov ecx, [rsi + rax*4 + 0x84a2cc]  ; 9-entry jump table, index 0..8
0x84a199  jmp rcx
```

A second dispatch in the same function guards `cmp ecx,7 ; ja` before its table. Out-of-range engine
indices hit the error path, not an OOB table fetch — so there is no index→function-pointer OOB.

### 3.5 The per-engine rules decoder (`0x890a36`): all scalars, no count-driven loop

`sub_8909f0` only reads the 4-bit engine index; the actual rules live in a separate decoder
(`0x890a36`, `0x7e6` bytes) that writes every field at a **fixed offset** in the `0x130`-byte rules
block. Critically, **every count/limit field is a bounded scalar, not a serialization count** — none
indexes an array or drives a loop:

```
max-players            -> dword [rsi+0x74]     maximum-allowable-teams -> dword [rsi+0xb4]
max-living-players     -> dword [rsi+0x78]     ball-count              -> word  [rsi+0xf4]
lives-per-round        -> dword [rsi+0x7c]     territory-count         -> word  [rsi+0xf0]
```

Each is read with a small bit width — either a compile-time constant (`r8d=0x10`) or a **minimal-bits
width computed from the range** (`mov r8d,edi; <loop> inc r8d; rol eax,1; cmp eax,<max>; jle`), which
caps the readable value. The decoder is a flat sequence of such reads; the fields that follow a "count"
(`ball-hit-damage`, `speed-with-ball`, `territory-contest-time`, …) are themselves fixed scalars, not
per-element records. So no engine-rule field reaches a loop / alloc / index. The tail
(`cmp [rsi+0x44],0 ; call 0x6a9ad0`) post-validates the decoded rules.

### 3.6 The one variable-length field — `filler-size-bits` (`0x8a1070`): range-checked

`simulation-data` carries an explicit variable-length `filler`, the only stream-supplied *length* found
on this surface. It is **range-checked before the read**:

```
0x8a1163  mov r8d, 0xe            ; read filler-size-bits as a 14-bit value (0..0x3fff)
0x8a1173  call 0x741300
0x8a1178  lea ecx, [rax-1]
0x8a117b  cmp ecx, 0x2fff
0x8a1181  ja  0x8a11a6            ; reject unless 1 <= size <= 0x3000 bits (<=1536 bytes)
0x8a1195  call 0x741590           ; read `size` bits into [rsp+0x50]
```

The destination is a stack buffer in a **`0x10050`-byte frame** (`__chkstk`; buffer at `+0x50`), so the
≤1536-byte filler has ~64 KB of headroom; and `0x741590`→`0x741040` additionally EOF-clamps to the
remaining stream. No overflow. (This field belongs to the netcode `simulation-data`, not the variant
rules, but it is the strongest length candidate on any adjacent path, so it is audited here.)

**On "sign-extended / negative length" specifically** (a class called out for this audit): absent.
Every reader guards the clamped count with `test…jle` / the length with `cmp…ja`; requested bit counts
are small positive constants or range-validated 14-bit values; `movsxd` appears only on the stream
*position*, never on an attacker length used as a copy size.

---

## 4. Candidate table (RVA / field / why a bug would live here / grade)

| # | RVA | Field / primitive | Why it could be a bug | Finding | Grade |
|---|---|---|---|---|---|
| 1 | `0x8b6cd4` | `variant-count` loop | count→array stride `0x758` | `cmovg` clamp to 2 before loop | **safe** |
| 2 | `0x8b6b5e` | `map-count` loop | count→array stride `0x10` | `cmovg` clamp before loop | **safe** |
| 3 | `0x7416b0` | `read_wstring` (name/desc) | unbounded copy if no limit | hard bound = `r9d` const `0x80`; dst field `0x100` B | **safe** (dyn-confirmed §5) |
| 4 | `0x741260` | core bit reader | OOB read past stream | `cmovg` clamp to remaining bits | **safe** (dyn-confirmed §5) |
| 5 | `0x8909f0`/`0x84a0c1` | `variant-game-engine-index` | index→jump/vtable OOB | `cmp…ja` guard before 9-entry table | **safe** |
| 6 | `0x6afeb0` | generic `core\%s.bin` loader | file-length copy | fixed 1312-B file; name in `0x100`-B stack buf | **safe (format-bounded)** |
| 7 | `0x741040` | `read_blob` (fileshare-metadata, `0x2000` bits) | unbounded blob copy | `r8d` is a **bit** count (`0x2000`b = `0x400`B); copy = `min(remaining, const)/8` | **safe** (dyn method §5) |
| 8 | `0x890a36` | per-engine rules decoder (`max-players`, `*-count`, `*-teams`) | an unclamped count → loop/index | **disassembled**: every count is a bounded scalar at a fixed offset, no loop/alloc/index | **safe** |
| 9 | `0x8a1070` | `filler-size-bits` (14-bit length) | stream length → stack copy | `cmp (size-1),0x2fff; ja` range check; dst in `0x10050`-B frame | **safe** |

---

## 5. Dynamic confirmation — from-scratch Unicorn harness

Harness: [`halo2-variant-bitstream-harness.py`](halo2-variant-bitstream-harness.py).
Log: [`halo2-variant-harness.log`](halo2-variant-harness.log). It maps `halo2.dll` into Unicorn and
calls the **real** leaf functions on attacker-controlled bitstream bytes, with a guard (unmapped) page
placed **immediately after** the destination buffer so any OOB write faults and is caught.

```
T1 read_bits(32) from 2-byte stream   -> val=0xbbaa  bitpos=32  fault=None
T2 read_wstring(max=128) all-0xFF      -> dst[127]=0x0000       fault=None
T3 POSITIVE CONTROL read_wstring(max=129) into 128-cap buf
     !! MEM FAULT access=WRITE addr=0x202001000 size=2 rip_rva=0x7416ed
```

- **T1** — asked the bit reader for 32 bits from a 2-byte stream. It returned only the 16 real bits
  (`0xbbaa`), upper bits zero, and **did not fault** reading past the 2-byte buffer. EOF clamp proven
  live (§3.3). (`bitpos` advances to 32 but every later read then computes `remaining<0` → returns 0.)
- **T2** — fed the wide-string reader an **all-`0xFF` (never-null)** stream with `max=128` into a
  256-byte buffer backed by a guard page. It wrote exactly 128 chars, `dst[127]=0`, and **did not
  touch the guard page**. Hard 256-byte bound proven live under maximally hostile input (§3.2).
- **T3 (positive control)** — same buffer, but `max=129`. It **faulted on the guard page**, at the
  store instruction `mov [rdi],ax` (`rip_rva=0x7416ed`). This proves the harness genuinely detects an
  OOB write, so T1/T2's clean results are meaningful — and that the *only* thing bounding the write is
  the length argument, which at every real call site is a compile-time constant ≤ the field size.

---

## 6. Verdict — confirmed vs candidate (honest)

**Confirmed crashing input: NONE.** There is **no confirmed memory-corruption bug** on the Halo 2
game-variant surface in this `halo2.dll`.

The decode path is the **mature, hardened MCC-era Blam bitstream**: counts are caller-clamped before
they drive a loop/array, strings are read with hard compile-time maxima and no attacker length field,
the core bit reader clamps to the remaining buffer (so crafted/truncated streams zero-fill instead of
reading OOB), and the game-engine-index dispatch is a bounds-checked jump table. The on-disk `.bin` is
a **fixed-size, RSA-signed** blob, so there is no file-length-driven copy at load. This mirrors the
halo3 netcode finding (`APPENDIX-NETCODE-PROTOCOL.md`): the bitstream is safe *by construction* over
bounded fields.

I followed the steering to hunt the bug statically first (not fuzz): I traced **every**
attacker-controlled length / count / index through the container decode (`0x8b6ae1`), the per-engine
**rules** decoder (`0x890a36`, §3.5), all shared bitstream primitives including the bulk blob reader
(`0x741040`, §3.3) and the string readers (`0x7416b0`/`0x7415b0`), the engine-index dispatch
(`0x84a0c1`, §3.4), and the one variable-length field on any adjacent path (`filler-size-bits`,
`0x8a1070`, §3.6). **Each one is bounded** by a caller `cmovg` clamp, a compile-time bit-width/byte
max, an explicit `cmp…ja` range check, or the primitive's own EOF clamp — including the
sign/negative-length class. There is no unbounded site to turn into a crafted-`.bin` PoC, so the
"craft one targeted malformed file" step has no target: the precise finding is the *absence* of the
defect, with the guard instruction cited at every site.

**Scope limits (what I did not prove):**
- The per-engine **apply** handlers (the 9 jump-table targets at `halo2+0x84a2cc`, reached from
  `0x84a0c1`) consume the already-decoded, already-bounded scalar rules; I inspected the dispatch guard
  and the handler shape (each loads fixed settings), but did **not** disassemble all nine handler
  bodies end-to-end. They read bounded scalars, so an OOB there would require a *second* bug writing
  past a fixed array — none seen, not exhaustively excluded.
- I did **not** byte-trace the on-disk RSA **verify** call to prove verify-before-parse ordering for a
  locally-placed `.bin`. The signing structure and the crypto code are proven; the ordering is not.
  This matters only for the weaker *local file-tamper* threat, not the network path.

---

## 7. Delivery relevance

- **Network (server/host → client), the interesting path:** in a session the host-selected variant is
  replicated to clients through the Blam **bitstream** decoded by the §2 routines. That decode is the
  one an attacker-host actually reaches, and it is bounded (§3–§5). So a malformed served variant
  **cannot** overflow the client variant struct via these fields → **no remote corruption on this
  surface**. It stays, at most, a semantic/validity concern handled by the engine's own validity flags.
- **Local file (`game_variants/*.bin`):** fixed-size + RSA-signed. A hand-crafted file would fail the
  signature and, regardless, offers no length/count to drive a copy at load. Weak, local-only, and not
  demonstrated.

**Bottom line:** the Halo 2 game-variant `.bin` surface is **candidate-negative / hardened**. It does
**not** add a confirmed memory-corruption vector to this research. The confirmed defect remains the
FMOD FSB5 bug (absent from `halo2.dll`).
