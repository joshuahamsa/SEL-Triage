"""Check every extracted row against the cited PDF page: command tokens and all description words must exist on that page."""
import json, pathlib, re, sys, random
import pymupdf

pdfdir = pathlib.Path(sys.argv[1])
bad = 0
total = 0
for jf in sorted(pathlib.Path(sys.argv[2]).glob("*.json")):
    d = json.load(open(jf))
    doc = pymupdf.open(pdfdir / d["manual"])
    cache = {}
    nb = 0
    for c in d["commands"]:
        total += 1
        p = c["page"]
        if p not in cache:
            words = [w[4] for w in doc[p - 1].get_text("words")]
            cache[p] = set(words) | set(x.rstrip("-") for x in words)
        ws = cache[p]
        missing = [t for t in c["command"].replace(",", " ").split() if t not in ws and t + "," not in ws]
        dmiss = [t for t in c["description"].split() if t not in ws and t + "-" not in ws and not any(t.startswith(x.rstrip("-")) and x.endswith("-") for x in ws)]
        if missing or len(dmiss) > 0:
            nb += 1
            print(f"{jf.stem} p{p} {c['command']!r} missing cmd={missing} desc={dmiss[:5]}")
    for f in d["firmware"]:
        words = set(w[4] for w in doc[f["page"] - 1].get_text("words"))
        if f["fid"] not in words and not any(f["fid"].startswith(w) for w in words):
            print(f"{jf.stem} fw p{f['page']} {f['fid']} not on page")
            nb += 1
    bad += nb
    print(f"== {jf.stem}: {len(d['commands'])} cmds, {len(d['firmware'])} fw, issues={nb}")
print("total rows", total, "issues", bad)
