#!/usr/bin/env python3
# Parse FMOD revision-history page text (from get_page_text JSON dumps or .txt)
# into version blocks, then flag entries matching security/parse keywords.
import json, re, sys, os

KW = re.compile(r'fsb|sound ?bank|createsound|createstream|out.?of.?bounds|'
                r'overflow|underflow|buffer over|memory corrupt|security|'
                r'malformed|corrupt|invalid (file|data|bank|handle)|heap|'
                r'access violation|out of range|bounds|sanity|robust|truncat|'
                r'read (past|beyond)|parse|parsing', re.I)

VER = re.compile(r'^(\d{1,2}/\d{1,2}/\d{2,4})\s+(\d+\.\d+\.\d+)\s*-\s*(.*)$')

def load_text(path):
    if path.endswith('.json'):
        data = json.load(open(path))
        return ''.join(b.get('text','') for b in data)
    return open(path).read()

def parse(txt):
    blocks = []  # (date, ver, header, [lines])
    cur = None
    for raw in txt.splitlines():
        line = raw.strip()
        m = VER.match(line)
        if m:
            if cur: blocks.append(cur)
            cur = [m.group(1), m.group(2), m.group(3), []]
        elif cur is not None and line:
            cur[3].append(line)
    if cur: blocks.append(cur)
    return blocks

def main():
    all_hits = {}   # ver -> (date, [entries])
    seen_ver = {}
    for path in sys.argv[1:]:
        txt = load_text(path)
        for date, ver, hdr, lines in parse(txt):
            seen_ver[ver] = date
            for ln in lines:
                if KW.search(ln) and not ln.lower().startswith('fsbank api reference'):
                    all_hits.setdefault(ver, (date, []))
                    if ln not in all_hits[ver][1]:
                        all_hits[ver][1].append(ln)
    # sort versions ascending
    def key(v):
        return tuple(int(x) for x in v.split('.'))
    print("### ALL VERSIONS SEEN (ascending): %d" % len(seen_ver))
    for v in sorted(seen_ver, key=key):
        print("   %-9s %s" % (v, seen_ver[v]))
    print()
    print("### ENTRIES MATCHING KEYWORDS (ascending by version):")
    for v in sorted(all_hits, key=key):
        date, entries = all_hits[v]
        print("\n== %s  (%s) ==" % (v, date))
        for e in entries:
            print("   - " + e)

if __name__ == '__main__':
    main()
