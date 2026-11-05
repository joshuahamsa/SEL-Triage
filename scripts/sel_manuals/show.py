import json, sys
d = json.load(open(sys.argv[1]))
what = sys.argv[2] if len(sys.argv) > 2 else "cmd"
if what == "cmd":
    for c in d["commands"]:
        print(f"{c['page']:>5} {c['min_access_level'] or '?':>2} {c['kind']:<7} {c['command']:<28} | {c['description'][:110]}")
else:
    for f in d["firmware"]:
        print(f"{f['revision']} {f['date']} p{f['page']} n={f['n_change_bullets']} {f['fid']}")
        for b in f["command_changes"]:
            print("     *", b[:160])
