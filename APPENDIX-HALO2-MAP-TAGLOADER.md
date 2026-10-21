# Appendix — Halo 2 (classic) `.map` tag-cache loader: memory-corruption audit

**Scope.** A *separate* surface from the FMOD/FSB5 work. Halo 2 (classic) in MCC
does **not** use FMOD — it uses the RAD Miles Sound System — so the FSB5 bug does
not apply here. But Halo 2's custom maps are server-delivered to clients and
parsed by `halo2.dll`'s Blam cache/tag loader, a large C++ parser that is its own
memory-corruption candidate surface. This appendix audits that loader.

**Target binary.** `halo2/halo2.dll`, PE32+ x64, image base `0x180000000`.
`sha256 de65b4f4fdbf3f0a5eab7431fe530da17dd815599182dfd6ae9b7e21cf171946`.
Install path: `…/ReclaimerMac/prefix/drive_c/…/Halo The Master Chief Collection/halo2/halo2.dll`.
Maps: sibling `h2_maps_win64_dx11/*.map` (+ `shared.map`).

**Method.** Static triage with a hand-rolled PE parser + capstone (no symbols),
then a **from-scratch Unicorn loader** that maps `halo2.dll` and drives the *real*
tag-loader function on crafted header bytes, stubbing only the OS/allocator
boundary — the same methodology that proved the FMOD FSB5 bug
(`poc-fsb5/harness/rawload.py`). All harness + inputs + logs are under
[`halo2-taghunt/`](halo2-taghunt/).

---

## 1. Verified `.map` header layout (first `0x380` bytes)

The loader reads the first `0x380` bytes of the file verbatim into a fixed static
buffer and treats them as the cache header. Fields relevant to this audit
(offsets confirmed against `ascension.map` and cross-checked against
lockout/midship/zanzibar/shared/mainmenu):

| off | ascension | meaning (inferred) | validated? |
|-----|-----------|--------------------|------------|
| `+0x000` | `'head'` (`64 61 65 68`) | magic | **yes** (==`head`) |
| `+0x004` | `0x0d` (13) | version | **yes** (==13) |
| `+0x008` | `0x433200` | file length | yes (`>= 0`, signed) |
| `+0x00c` | `1` | map kind/flag byte | yes (==1) |
| `+0x018` | `1` | type (1=mp map, 2=mainmenu, 3=shared) | yes (word `<= 4`) |
| `+0x01c` | `…0x19` | **compression flag** (bit0) + fields | bit0 gates §4 table |
| `+0x010` | `0x25b200` | **section-A file offset** | **NO** |
| `+0x014` | `0x1d8000` | **section-A size → allocation** | **NO** |
| `+0x090` | `"ascension"` | origin name (32) | yes (`strlen<0x20`) |
| `+0x0b0` | `"ascension"` | map name (32) | yes (`strlen<0x20`) |
| `+0x2d0` | `0x3200000` | **tag "virtual base" offset** (0 for shared/mainmenu) | **NO** |
| `+0x2d4` | `0x5b000` | **tag-data read size** | **NO** |
| `+0x2d8` | `0x17d000` | section-B split | **NO** |
| `+0x20`  | `0x5a5b` | string-id / count (`<<2` later) | **NO** |
| `+0x310` | `0x262600` | compression block-table file offset | §4 |
| `+0x314` | `0x11` | compression block **count** (`<<3` later) | **NO** |
| `+0x37c` | `'foot'` (`74 6f 6f 66`) | footer magic | **yes** (==`foot`) |

The bolded **NO** rows are the file-controlled size/offset/count fields that reach
allocation sizing and copy/index math with no bounds check — the subject of §3–§5.

## 2. Located parse entry and call chain

```
0x35b60                      (map-load state)
  -> 0x678090                cache-load driver
       -> 0x6c9900           header-verify wrapper
            -> 0x67bdf0       open (plain CreateFileW @0x6c8d80) + read 0x380 hdr
            |                 into g_cache_hdr buffer; validators 0x6c95c0/0x6c9800
            |                 handle only the §4 compression table (gated by +0x1c bit0)
            -> 0x6c9970       ***TAG/INDEX LOADER*** — validates magic/ver/name,
                              then allocates tag memory and reads file sections
```

`cache_file_open_secure` and `shared.map` strings sit in this region
(`.rdata 0xb0d5d0 / 0xb0d5e8`), confirming it is the cache loader. The open
(`0x6c8d80`) is a plain `CreateFileW(GENERIC_READ, OPEN_EXISTING)` — **no inline
hash/signature verification on this parse path** (the engine links OpenSSL RSA,
but it is not invoked here; any integrity gate lives in a separate
content-delivery layer — see §7).

Key globals (all in `.data`): `g_cache_hdr` ptr @ `0x15e4b50` → the `0x380` header
buffer; `g_tagmem` ptr @ `0x15e4b48` → the allocation made at `0x6c9a64`;
`g_tags` @ `0x15e4b58` → the in-buffer `'tags'` index header.

## 3. Primary defect — allocation / copy size mismatch (CONFIRMED)

Disassembly of `0x6c9970` after header validation (helpers resolved:
`0x67c730`=`align128`, `0x67ba60`=alloc(rcx=size), `0x67bbb0`=section read
`(id, file_off, size, dst)` → raw `ReadFile`, bounded only by file content):

```
A          = align128([hdr+0x14])            ; 0x6c9a35/0x67c730
V          = sign_extend32([hdr+0x2d0])      ; 0x6c9a56  movsxd r15,[rcx+0x2d0]
alloc_size = V + A                            ; 0x6c9a5d  lea esi,[r15+rax]   (32-bit)
g_tagmem   = alloc(alloc_size)                ; 0x6c9a64/0x6c9a67
dst1       = g_tagmem + V                      ; 0x6c9aad  lea rbx,[r15+rax]
sz1        = align128([hdr+0x2d4])            ; 0x6c9ac3/0x67c730
read(off=[hdr+0x10], size=sz1, dst=dst1)      ; 0x6c9ad5  call 0x67bbb0   <-- fault site
```

**The allocation is sized from `+0x14` and `+0x2d0`; the first section read is
sized from `+0x2d4` and placed at offset `+0x2d0`. Nothing checks
`align128(+0x2d4) <= align128(+0x14)`** (nor that `+0x2d0`+`sz1` ≤ `alloc_size`).
`0x67bbb0` issues a raw `ReadFile` of `size` bytes into `dst` and has no knowledge
of `dst`'s allocation size, so the file bytes overflow the tag-memory buffer. A
second read (`0x6c9b21`) has the same shape using `+0x2d8`/`+0x2d4`+`+0x10`.

### Dynamic proof (real `halo2.dll` under Unicorn)

The harness [`h2load.py`](halo2-taghunt/harness/h2load.py) maps the real DLL,
points `g_cache_hdr` at a crafted `0x380` header, backs `g_tagmem` with a mapping
of exactly the loader-requested size followed by an **unmapped guard page**, and
lets the real code compute `(dst,size)`. Full log:
[`evidence/h2load-runs.log`](halo2-taghunt/evidence/h2load-runs.log).

**Control — unmodified `ascension` header** (`hdr_baseline.bin`): loads cleanly,
both reads fit *exactly*, function returns:
```
[alloc] size=0x33d8000 -> base=0x300000000           ; = V 0x3200000 + A 0x1d8000
[read]  off=0x25b200 size=0x5b000  dst=0x303200000    ; dst_off 0x3200000  (in bounds)
[read]  off=0x2b6200 size=0x17d000 dst=0x30325b000    ; dst_off 0x325b000  (ends exactly at alloc end)
[done] function returned, rax=0x0
```

**Candidate #1** (`hdr_oob1.bin` / `poc_oob1.map`, 16 KB): `+0x14=0`,
`+0x2d0=0x1000`, `+0x2d4=0x4000`:
```
[alloc] size=0x1000  -> base=0x300000000  guard@0x300001000
[read]  off=0x0 size=0x4000 dst=0x300001000  dst_off=0x1000  *** READ OVERRUNS ALLOC BY 0x4000 BYTES ***
[FAULT] Invalid memory write (UC_ERR_WRITE_UNMAPPED) @ rip=0x1806c9ad5   insn: call 0x18067bbb0
```

**Candidate #1b** (`hdr_oob1b.bin`; `poc_oob1b_small.map`, 128 KB keeps the real
`V=0x3200000` layout): `align128(+0x2d4)` bytes land at the realistic tag-data
boundary and overrun by `0x3ff000` (full) / `0x1f000` (small map). Same fault at
`0x6c9ad5`.

This is a **controlled heap buffer overflow**: destination pointer and copy length
are both computed by the real loader from attacker-controlled header fields, the
overflowing bytes are the attacker's file bytes (from offset `+0x10`), and the
copy overruns an allocation whose size came from a *different* header field.

### 3a. Register control (the write primitive)

The primitive is a **controlled write**: at the section-read call `0x6c9ad5` the
argument registers are derived directly from `.map` header fields, so the attacker
controls the destination, length and source of the copy. Driving the real loader
with sentinel field values (`hdr_regctl.bin`: `+0x2d0=0x00414140`, `+0x14=0`,
`+0x2d4=0x2000`, `+0x10=0x11223300`) shows each field landing verbatim in a
register at `0x6c9ad5`:
```
--- REGISTER STATE at section-read call 0x6c9ad5 (controlled write) ---
  r9  (dst)  = 0x300414140   = g_tagmem(0x300000000) + 0x414140   <- attacker +0x2d0
  r8d (size) = 0x2000        = align128(hdr[+0x2d4])              <- attacker +0x2d4
  edx (foff) = 0x11223300    = hdr[+0x10]                          <- attacker +0x10
  r14 = r15  = 0x414140      = sign_extend32(hdr[+0x2d0])          (the dest offset)
[read] dst=0x300414140 size=0x2000  *** READ OVERRUNS ALLOC BY 0x2000 BYTES ***
[FAULT] Invalid memory write (UC_ERR_WRITE_UNMAPPED) @ rip=0x1806c9ad5
```
So: **write-dest offset-from-heap-base = attacker `+0x2d0`** (and via the `movsxd`
sign-extension in §6 the offset can also be *negative* — a write *below* the heap
base), **write length = attacker `align128(+0x2d4)`**, **write content = attacker
file bytes at `+0x10`**. The one entropic unknown is the `g_tagmem` base itself
(heap ASLR). Escalation to RIP (steer the controlled write onto a later-called
tag/vtable function pointer) is **plausible but not demonstrated here** — this is a
controlled-write register-control proof, not a PC-control proof.

## 4. Secondary — compression block table (CANDIDATE)

For compressed maps (`+0x1c` bit0 = 1; all shipped maps), `0x67bdf0` calls
`0x6c9800`/`0x6c95c0` which allocate/read a block table of **`[hdr+0x314] << 3`**
bytes (`0x6c9800 @ 0x6c984e: shl r8d,3`). `+0x314` is the file-supplied block
count, 32-bit — `count >= 0x20000000` makes `count<<3` wrap to a small/zero size,
under-allocating the table that is then indexed per block → OOB. Not dynamically
driven (needs the decompression context set up); graded candidate.
**Clearing `+0x1c` bit0 skips both validators entirely** (`al=1` fast path), which
is also what makes the §3 uncompressed-map model clean.

## 5. Deeper tag-table math — reached via a crafted `'tags'` block

After the first two reads land in `g_tagmem`, the loader validates an in-buffer
`'tags'` index header at `g_tagmem+V` (`0x6c9b31`: `[+0x1c]=='tags'`, `[+8]!=0`,
`[+0x18]>0`) and then does the tag-table work. A **targeted** PoC
(`poc_tagcount.map`, built by [`mk_tagcount.py`](halo2-taghunt/harness/mk_tagcount.py):
valid non-overflowing sizes + a crafted `'tags'` header at the first read's
destination carrying tag count `0x20000000`) drives the real loader cleanly past
the `'tags'` validation into the pointer math:

```
[read] off=0x1000 size=0x1000 dst=0x300001000      ; 'tags' header lands here, in bounds
[read] off=0x2000 size=0x100  dst=0x300002f00      ; in bounds
[be240] register ptr=0x300001020 (rip rva 0x6c9c3e)                g_tagmem+0x1020
[be240] register ptr=0x480001020 (rip rva 0x6c9c5c)  g_tagmem+0x180001020   <-- WILD
```

Located fields:
* **`0x6c9c4c  movsxd rax,[g_tags+4]; lea rcx,[rax+4]; lea rcx,[rax+rcx*2]; lea
  rcx,[g_tags+rcx*4]`** → `rcx = g_tags + 12*tagcount + 32`. With `tagcount =
  0x20000000` the real code computes `rcx = 0x480001020` (`g_tags + 0x180000000 +
  0x20`) — a **wild pointer built from the unbounded, sign-extended tag count**,
  confirmed on real halo2.dll (the `be240` line above). This pointer is registered
  (`0x6be240`) for later tag-table use; a huge count yields an out-of-range entry
  pointer.
* `0x6c9bdf  shl ecx,2` — the offset-table count `+0x20` is shifted `<<2` (32-bit)
  to size its buffer (`alloc(align128(+0x20<<2))`, read of the *same* size — so the
  read itself is self-consistent), **but the raw count `+0x20` is stored alongside
  the buffer in a global struct** (`0x6c9c0b`→`0x15e4b60`). `+0x20 >= 0x40000000`
  makes `+0x20<<2` wrap to a small buffer while the retained count stays huge → a
  **count/buffer-size desync**: any later consumer that iterates `+0x20` entries
  over that buffer reads/writes OOB. Exact trigger: `+0x20 >= 0x40000000`.

**Honesty on §5:** the wild-pointer *computation* from the tag count is confirmed
on real code (`0x6c9c5c`). The subsequent crash my harness showed
(`0x6c9d50 movsxd rax,[r8+rcx*8+8]`) is a **harness stub artifact** — `r8=NULL`
because the real tag-registration list (`0x6be240`'s backing store) is not modeled
— so it is *not* counted as a confirmed OOB. The genuine OOB dereference of the
wild pointer, and the offset-table count/size desync, live in the tag-relocation
code that needs full engine state; both are well-argued static candidates with the
exact trigger conditions above. (The string-id read at `0x6c9b7a`, `alloc` and
`read` both sized `align128(+0x28)`, is **self-consistent — not a defect**.)

## 6. Sign-extension wild-write (CANDIDATE, gated)

`+0x2d0` is consumed by `movsxd` (`0x6c9a56`). `hdr_oob2.bin` (`+0x2d0=0xf0000000`)
drives `dst1 = g_tagmem + 0xfffffffff0000000` → a write **256 MB below** the heap
base (`dst=0x2f0000000`), faulting at `0x6c9ad5`. **However**, the same field also
makes `alloc_size` negative/huge, so a real allocator returns NULL and the loader
bails (`0x6c9a6c test rax,rax; je`). So the wild-write is latent but gated by the
huge allocation succeeding → graded lower than §3.

---

## 7. Delivery relevance

Halo 2 custom maps are **server-delivered to clients** and parsed by exactly this
loader. The parse path we traced performs **no signature/hash check** (plain
`CreateFileW`); the header's size/offset/count fields are consumed directly. This
matches the project's established threat model (see `TECHNICAL-ANALYSIS.md` /
`APPENDIX-NETCODE-PROTOCOL.md`): official + Steam-Workshop content is integrity-
verified against Steam's manifest, so tampering *subscribed* content is blocked,
but a **server-shared, non-Workshop custom map is the un-mitigated vector** — a
malicious custom server serves a map whose bytes (and header) it authored. A
client that joins and loads it runs §3 on attacker-controlled fields.

## 8. HONESTY — confirmed vs. candidate, and what blocked a full repro

**CONFIRMED (within from-scratch emulation of the real `halo2.dll` + static RE):**
* The parse entry, call chain, field semantics, and the **absence of a bound**
  linking the allocation size (`+0x14`,`+0x2d0`) to the section-read size
  (`+0x2d4`) — proven by the baseline-fits-exactly vs. mutated-overruns contrast,
  with the real loader computing `(dst,size)` and the write faulting at the real
  call site `0x6c9ad5`. Concrete crashing inputs: `hdr_oob1.bin`/`poc_oob1.map`,
  `hdr_oob1b*`/`poc_oob1b_small.map`.
* **Register control (§3a):** the real loader places attacker header fields
  verbatim into the write-primitive registers at `0x6c9ad5` (`r9`=dest offset from
  `+0x2d0`, `r8d`=len from `+0x2d4`, `edx`=source offset from `+0x10`) — sentinel
  input `hdr_regctl.bin`.
* **Tag-count → wild pointer (§5):** with a crafted valid `'tags'` block
  (`poc_tagcount.map`) the real code at `0x6c9c5c` computes a tag-array entry
  pointer `g_tags + 12*tagcount + 32 = 0x480001020` from an attacker tag count —
  confirmed *computation* on real code.

**NOT a full live/native crash — honest limits:**
1. **The byte-copy is stubbed.** `0x67bbb0`/`ReadFile` is replaced by a harness
   `mem_write` of the loader's own `(dst,size)`. The *corruption decision* is real
   halo2.dll code; the memcpy mechanism is not emulated. In the live binary the
   identical `(dst,size)` go to `ReadFile`, which copies file bytes into the same
   undersized buffer — the overflow is in halo2.dll's logic, independent of who
   copies. The faulting PC (`0x6c9ad5`) is the real call site. (Same class of
   caveat as the FMOD track's Unicorn/peload proofs.)
2. **No Windows MCC run.** This is the macOS/Reclaimer loader; a native in-game
   repro (like the FMOD `live-crash-ingame.log`) needs Windows MCC + a custom
   server serving the crafted map and was not performed here. Grade the §3 result
   as *emulation-confirmed, live-unconfirmed*.
3. **§4/§5/§6 are candidates (one partial).** §5's tag-count **wild-pointer
   computation** is confirmed on real code (`0x6c9c5c`), but the *dereference*
   crash is not: the fault my harness reached (`0x6c9d50 movsxd rax,[r8+rcx*8+8]`)
   is a **stub artifact** (`r8=NULL`, the tag-registration list is unmodeled) and
   is explicitly NOT counted. §4 (compression table) needs the decompression
   context; §6 is alloc-gated. The offset-table count/size desync (§5) and the
   genuine tag-count deref need full tag-relocation engine state.
4. **Integrity gate for a given delivery path is un-audited.** The parser has no
   signature check, but whether a specific matchmaking/custom-server path verifies
   a hash before handing the file to this loader was not reverse-engineered; §7 is
   the threat model, not a demonstrated end-to-end network repro.

## 9. Ranked candidate table

| # | grade | RVA | field(s) | why |
|---|-------|-----|----------|-----|
| 1 | **CONFIRMED (emu)** | alloc `0x6c9a64`, read `0x6c9ad5` | `+0x14`,`+0x2d0` vs `+0x2d4`,`+0x10` | alloc sized by one field, file read sized by another into offset `+0x2d0`; no `sz<=alloc` check → controlled heap overflow (file-content bytes). Driven on real code; faults at `0x6c9ad5`. |
| 1b| **CONFIRMED (emu)** | `0x6c9ad5` | `+0x14`,`+0x2d4` | same defect at the realistic `V=0x3200000` tag-data boundary; 0x3ff000-byte overrun. |
| 1c| **CONFIRMED (emu)** register control | `0x6c9ad5` | `+0x2d0`,`+0x2d4`,`+0x10` | write dest(r9)/len(r8)/src(edx) are attacker fields verbatim → controlled heap write (dest offset can be negative via §2). |
| 5a| **PARTIAL (emu)** wild ptr | `0x6c9c4c`/`0x6c9c5c` | tag count `[g_tags+4]` | `g_tags + 12*count + 32` computed from attacker count = `0x480001020` on real code (`poc_tagcount.map`); deref crash needs real tag state (not confirmed). |
| 2 | CANDIDATE | `0x6c9a56` | `+0x2d0` | `movsxd` sign-extend → wild write below heap base; gated by huge-alloc success. |
| 3 | CANDIDATE | `0x6c9800 @ 0x6c984e` | `+0x314` | `count<<3` (32-bit) block-table size; overflow → undersized table then per-block OOB. Trigger: `+0x314 >= 0x20000000`. |
| 4 | CANDIDATE | `0x6c9bdf`→`0x6c9c0b` | `+0x20` | offset-table buffer sized by `+0x20<<2` (32-bit wrap) while raw count `+0x20` retained in global `0x15e4b60` → count/size desync; later iterate-by-count → OOB. Trigger: `+0x20 >= 0x40000000`. |

## 10. Reproduce

```bash
cd halo2-taghunt
python3 -m venv venv && ./venv/bin/pip install unicorn pefile capstone
H2='…/Halo The Master Chief Collection/halo2/halo2.dll'
# re-craft inputs from a real map (only the first 0x380 bytes are used):
python3 harness/mk_header.py   '…/h2_maps_win64_dx11/ascension.map' inputs
python3 harness/mk_map.py      '…/h2_maps_win64_dx11/ascension.map' inputs
python3 harness/mk_tagcount.py '…/h2_maps_win64_dx11/ascension.map' inputs/poc_tagcount.map
# control (clean) vs confirmed overflow (faults at 0x6c9ad5):
./venv/bin/python harness/h2load.py "$H2" inputs/hdr_baseline.bin
./venv/bin/python harness/h2load.py "$H2" inputs/poc_oob1.map
# register control (sentinel fields -> registers at 0x6c9ad5):
./venv/bin/python harness/h2load.py "$H2" inputs/hdr_regctl.bin
# tag-count wild pointer at 0x6c9c5c (crafted 'tags' block):
./venv/bin/python harness/h2load.py "$H2" inputs/poc_tagcount.map --fileimg inputs/poc_tagcount.map
```

Static helpers: `harness/pe.py` (PE64 parser), `harness/func.py` (.pdata function
disasm), `harness/xref2.py` (clean per-function xref).
