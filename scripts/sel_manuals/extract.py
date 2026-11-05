"""Extract SEL ASCII command summaries + firmware revision history from SEL instruction manuals.

usage: python -I extract.py <pdf_dir> <out_dir>
Coordinates-based (PyMuPDF words). Every emitted row comes from words on the cited page.
"""
import collections, json, pathlib, re, sys
import pymupdf

PDF_DIR = pathlib.Path(sys.argv[1])
OUT = pathlib.Path(sys.argv[2])

H_351 = ["0", "1", "B", "2"]
H_700 = ["0", "1", "2"]
H_735 = ["0", "1", "E", "2"]

MANUALS = [
    # model, pdf, manual_date, mode, cmd pages, fw pages, hierarchy, extra
    dict(model="SEL-351", docs_url="https://selinc.com/products/351/docs/", latest_im_url='https://selinc.com/api/download/5530/', pdf="351-5-6-7_PS_IM_20170818 Manual.pdf", date="2017-08-18", mode="prompt", order="LPCD",
         cmd=(501, 503), fw=(644, 651), hier=H_351,
         table="Table 10.19 ASCII Command Summary (Section 10, Communications)",
         covers="SEL-351-5, SEL-351-6, SEL-351-7"),
    dict(model="SEL-351A", docs_url="https://selinc.com/products/351A/docs/", latest_im_url='https://selinc.com/api/download/5520/', pdf="351A_PS_IM_20171023 Manual.pdf", date="2017-10-23", mode="prompt", order="LPCD",
         cmd=(481, 483), fw=(607, 615), hier=H_351, table="Table 10.19 Serial Port Command Summary"),
    dict(model="SEL-351S", docs_url="https://selinc.com/products/351S/docs/", latest_im_url='https://selinc.com/api/download/5512/', pdf="351S_Manual.pdf", date="2008-01-03", mode="prompt", order="LPCD",
         cmd=(476, 477), fw=(601, 605), hier=H_351, table="Table 10.5 Serial Port Command Summary"),
    dict(model="SEL-651R", docs_url="https://selinc.com/products/651R/docs/", latest_im_url=None, pdf="651R_IM_20160715.pdf", date="2016-07-15", mode="prompt", order="CLPD",
         cmd=(727, 730), fw=(611, 614), hier=H_351,
         table="SEL-651R Recloser Control Command Summary (end of manual)"),
    dict(model="SEL-651R-2", docs_url="https://selinc.com/products/651R/docs/", latest_im_url='https://selinc.com/api/download/100136/?lang=en-us', pdf="651R-2_IM_20240725.pdf", date="2024-07-25", mode="prompt", order="CLPD",
         cmd=(688, 694), fw=(842, 853), hier=H_351, table="Table 10.19 ASCII Command Summary"),
    dict(model="SEL-651RA", docs_url="https://selinc.com/products/651RA/docs/", latest_im_url='https://selinc.com/api/download/113968/?lang=en-us', pdf="651RA_IM_20240516.pdf", date="2024-05-16", mode="prompt", order="CLPD",
         cmd=(614, 620), fw=(752, 756), hier=H_351, table="Table 10.19 ASCII Command Summary"),
    dict(model="SEL-700G", docs_url="https://selinc.com/products/700G/docs/", latest_im_url=None, pdf="SEL-700G Instruction Manual.pdf", date="2024-03-29", mode="heading",
         cmd=(1143, 1150), fw=(770, 782), hier=H_700, spanish=300,
         table="SEL-700G Relay Command Summary (end of manual, English column)", covers="SEL-700G, SEL-700GT, SEL-700GW"),
    dict(model="SEL-751", docs_url="https://selinc.com/products/751/docs/", latest_im_url=None, pdf="[SEL MANUAL] 751_IM_20250214.pdf", date="2025-02-14", mode="heading",
         cmd=(1171, 1178), fw=(762, 784), hier=H_700, spanish=300,
         table="SEL-751 Relay Command Summary (end of manual, English column)"),
    dict(model="SEL-751A", docs_url="https://selinc.com/products/751A/docs/", latest_im_url='https://selinc.com/api/download/3656/?lang=en-us', pdf="751A_Instruction Manual_20190513.pdf", date="2019-05-13", mode="heading",
         cmd=(679, 682), fw=(431, 440), hier=H_700, table="SEL-751A Relay Command Summary (end of manual)"),
    dict(model="SEL-851", docs_url="https://selinc.com/products/851/docs/", latest_im_url=None, pdf="SEL-851 Manual_IM_20230821.pdf", date="2023-08-21", mode="heading",
         cmd=(513, 516), fw=(326, 326), hier=H_700, table="SEL-851 Command Summary (end of manual)"),
    dict(model="SEL-735", docs_url="https://selinc.com/products/735/docs/", latest_im_url=None, pdf="SEL-735 Manual - 735_IM_20250711.pdf", date="2025-07-11", mode="level",
         cmd=(579, 582), fw=(364, 374), hier=H_735, table="SEL-735 Meter Command Summary (end of manual)"),
    dict(model="SEL-735_IM20190828", docs_url="https://selinc.com/products/735/docs/", latest_im_url=None, pdf="SEL-735 Manual - 735_IM_20190828.pdf", date="2019-08-28", mode="level",
         cmd=(429, 431), fw=(260, 266), hier=H_735, table="SEL-735 Meter Command Summary (end of manual)",
         note="older SEL-735 manual edition, kept for comparison"),
]

PROMPT_RE = re.compile(r"^(=|=>|==>|=>>)$")
LEVEL_RE = re.compile(r"^(0|1|2|B|C|E|P|A|O)$")
HEADING_RE = re.compile(r"^Access Level (\S+) Commands")
SKIP_RE = re.compile(r"Description|Descripción|Comando del|Command Summary|^Table |Pushbutton|Corresponding|^Access$|^Level$|^Prompt$|^Access Level$|^Serial Port$|Instruction Manual|Date Code|Commands \(Sheet")
GAP = 12.6


def page_lines(page):
    words = [w for w in page.get_text("words")]
    words.sort(key=lambda w: (w[1], w[0]))
    lines = []
    for w in words:
        if lines and abs(lines[-1]["y"] - w[1]) < 3:
            lines[-1]["w"].append(w)
        else:
            lines.append({"y": w[1], "w": [w]})
    for ln in lines:
        ln["w"].sort(key=lambda w: w[0])
        ln["text"] = " ".join(w[4] for w in ln["w"])
    return lines


def clean(words):
    s = " ".join(words)
    s = re.sub(r"(\w)- (\w)", lambda m: m.group(1) + ("-" if m.group(2).isupper() else "") + m.group(2), s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def mode_x(xs):
    c = collections.Counter(round(x) for x in xs)
    if not c:
        return None
    top = max(c.values())
    # smallest x among strong candidates (merge +-1 jitter)
    cands = sorted(x for x, n in c.items() if n >= 0.6 * top)
    return cands[0]


def expand(level, hier):
    lv = level.upper().rstrip("?")
    if lv in ("C", "CAL"):
        return ["C"]
    if lv in hier:
        return hier[hier.index(lv):]
    return [lv]


def parse_commands(cfg, doc):
    rows = []
    cur = None
    level = None
    seen_heading = False
    for pno in range(cfg["cmd"][0], cfg["cmd"][1] + 1):
        page = doc[pno - 1]
        H = page.rect.height
        lines = [l for l in page_lines(page) if 45 < l["y"] < H - 45]
        sp = cfg.get("spanish")
        if sp:
            for l in lines:
                l["w"] = [w for w in l["w"] if w[0] < sp]
                l["text"] = " ".join(w[4] for w in l["w"])
            lines = [l for l in lines if l["w"]]
        # column geometry
        if cfg["mode"] == "prompt":
            anchors = [l for l in lines if any(PROMPT_RE.match(w[4]) for w in l["w"])]
            if not anchors:
                continue
            px = mode_x([w[0] for l in anchors for w in l["w"] if PROMPT_RE.match(w[4])])
            pline_x1 = px + 18
            # description column = mode of x0 of words right of prompt
            if cfg["order"] == "LPCD":
                starts = []
                for l in anchors:
                    ws_ = l["w"]
                    pi_ = next(i for i, w in enumerate(ws_) if PROMPT_RE.match(w[4]))
                    rest = ws_[pi_ + 1:]
                    for i in range(len(rest) - 1):
                        if rest[i + 1][0] - rest[i][2] > 9:
                            starts.append(rest[i + 1][0])
                            break
                desc_x = mode_x(starts) or 999
            else:
                desc_x = mode_x([w[0] for l in lines for w in l["w"] if w[0] > pline_x1])
        elif cfg["mode"] == "level":
            anchors = [l for l in lines if LEVEL_RE.match(l["w"][0][4]) and l["w"][0][0] < 110 and len(l["w"]) > 1]
            if not anchors:
                continue
            starts = []
            for l in anchors:
                rest = l["w"][1:]
                for i in range(len(rest) - 1):
                    if rest[i + 1][0] - rest[i][2] > 9:
                        starts.append(rest[i + 1][0])
                        break
            desc_x = mode_x(starts) or 999
        else:  # heading
            hi = next((i for i, l in enumerate(lines) if re.search(r"Description", l["text"])), None)
            geo = lines[hi:] if hi is not None else lines
            cmd_x = min(l["w"][0][0] for l in geo)
            desc_x = mode_x([w[0] for l in geo for w in l["w"] if w[0] > cmd_x + 15])
        prev_y = None
        for l in lines:
            text = l["text"]
            if "intentionally left blank" in text:
                cur = None
                continue
            hm = HEADING_RE.match(text)
            if hm:
                level = hm.group(1)
                seen_heading = True
                cur = None
                prev_y = l["y"]
                continue
            if SKIP_RE.search(text) and not (cfg["mode"] == "prompt" and any(PROMPT_RE.match(w[4]) for w in l["w"])):
                if cfg["mode"] != "heading" or cur is None or SKIP_RE.search(text):
                    cur = None if cfg["mode"] != "heading" else cur
                    prev_y = l["y"]
                    continue
            ws = l["w"]
            gap = (l["y"] - prev_y) if prev_y is not None else 99
            prev_y = l["y"]
            is_anchor = False
            lvl = prm = None
            cmdw, descw = [], []
            if cfg["mode"] == "prompt":
                pi = next((i for i, w in enumerate(ws) if PROMPT_RE.match(w[4]) and abs(w[0] - px) < 12), None)
                if pi is not None and (pi >= 1 and LEVEL_RE.match(ws[pi - 1][4]) or cfg["order"] == "CLPD" and pi >= 1):
                    is_anchor = True
                    prm = ws[pi][4]
                    if LEVEL_RE.match(ws[pi - 1][4]):
                        lvl = ws[pi - 1][4]
                    else:  # level column blank in the manual: infer from the prompt
                        lvl = {"=": "0", "=>": "1", "==>": "B", "=>>": "2"}[prm] + "?"
                        ws = ws[:pi] + [(0, 0, 0, 0, "")] + ws[pi:]
                        pi += 1
                    if cfg["order"] == "LPCD":
                        rest = ws[pi + 1:]
                        k = len(rest)
                        for i in range(len(rest) - 1):
                            if rest[i + 1][0] - rest[i][2] > 9:
                                k = i + 1
                                break
                        cmdw, descw = rest[:k], rest[k:]
                    else:
                        cmdw = ws[: pi - 1]
                        descw = ws[pi + 1:]
                else:
                    if cfg["order"] == "LPCD":
                        cmdw = [w for w in ws if px + 10 < w[0] < desc_x - 2]
                        descw = [w for w in ws if w[0] >= desc_x - 2]
                    else:
                        cmdw = [w for w in ws if w[0] < px - 10]
                        descw = [w for w in ws if w[0] >= desc_x - 2]
            elif cfg["mode"] == "level":
                if l in anchors:
                    is_anchor = True
                    lvl = ws[0][4]
                    rest = ws[1:]
                    k = len(rest)
                    for i in range(len(rest) - 1):
                        if rest[i + 1][0] - rest[i][2] > 9:
                            k = i + 1
                            break
                    cmdw, descw = rest[:k], rest[k:]
                else:
                    cmdw = [w for w in ws if 110 <= w[0] < desc_x - 2]
                    descw = [w for w in ws if w[0] >= desc_x - 2]
            else:
                if not seen_heading:
                    continue
                starts_cmd = abs(ws[0][0] - cmd_x) < 4
                cmdw = [w for w in ws if w[0] < desc_x - 2]
                descw = [w for w in ws if w[0] >= desc_x - 2]
                if starts_cmd and (gap > GAP or cur is None):
                    is_anchor = True
                    lvl = level
            # drop front-panel pushbutton column words (351 family)
            if cfg["mode"] == "prompt" and cfg["order"] == "LPCD":
                descw = [w for w in descw if not (w[0] >= 465 and re.match(r"^\{?[A-Z]+\}?$", w[4]))]
            if is_anchor:
                cur = {"cmd": [w[4] for w in cmdw], "desc": [w[4] for w in descw], "level": lvl, "prompt": prm, "page": pno}
                rows.append(cur)
            elif cur is not None and gap <= GAP:
                cur["cmd"] += [w[4] for w in cmdw]
                cur["desc"] += [w[4] for w in descw]
            else:
                cur = None
    out = []
    for r in rows:
        cmd = clean(r["cmd"])
        desc = clean(r["desc"])
        if not cmd:
            continue
        out.append({
            "command": cmd,
            "min_access_level": ("C" if r["level"] == "CAL" else r["level"].rstrip("?")) if r["level"] else None,
            **({"note": "access-level column blank in manual; level inferred from prompt"} if r["level"] and r["level"].endswith("?") else {}),
            "access_levels": expand(r["level"], cfg["hier"]),
            "prompt": r["prompt"],
            "description": desc,
            "kind": classify(cmd, desc),
            "page": r["page"],
        })
    return out


SESSION = {"ACC", "2AC", "BAC", "CAL", "QUI", "EXI", "EAC", "PAC", "AAC", "OAC", "EZA"}
WRITE_BASE = {"SET", "PAS", "OPE", "CLO", "TRI", "PUL", "CON", "COP", "LOO", "L_D", "R_S", "89C", "89O", "TES",
              "SWI", "RES", "BLI", "CLE", "ARC", "STR", "INI", "MAN"}
WRITE_DESC = re.compile(r"^(Clear|Clears|Reset|Resets|Preload|Preloads|Set |Sets |Change|Changes|Copy|Copies|Pulse|Pulses|"
                        r"Open|Opens|Close|Closes|Trigger|Triggers|Modify|Modifies|Initiate|Initiates|Force a|Load|Loads|"
                        r"Restore|Restores|Reboot|Restart|Enter date|Enter time|Momentarily|Control|Controls|Enable|Disable|"
                        r"Save|Saves|Write|Writes|Delete|Deletes|Erase|Erases|Upgrade|Assign|Assigns|Apply|Applies|Execute|Executes|"
                        r"Bypass|Block|Blocks|Start|Starts|Stop|Stops|Perform|Performs|Arm|Arms|Remove|Removes|Activate|Deactivate|"
                        r"Auto Start|Auto Stop|Download|Downloads|Begin|Begins|Manually trigger|Toggle|Toggles|Transfer settings|Transfers settings|Test |Tests |Allows for updates|Synchroniz|Forces? synchroniz)", re.I)
WRITE_ANY = re.compile(r"View/change|\bpreload|\breset\b|\bclear(s)?\b(?! *to send)|View or change|Display or change|Show or set|Display or set",
                       re.I)
READ_DESC = re.compile(r"^(Display|Displays|Show|Shows|Return|Returns|View|Views|List|Lists|Report|Reports|Determine|Determines|"
                       r"Read|Reads|Print|Prints|Compressed|Binary|Relay identification|Event|Metering|Breaker monitor|"
                       r"Sequential|Load profile|Relay self-test|Quick|Retrieve|Retrieves|Transfer data|Transfers data|"
                       r"Transfers? .* from the (relay|meter|recloser|device)|Summary|Fundamental|Latest|Ethernet|COMTRADE|Audit|"
                       r"ASCII|Names|Information|Lists?|Get|Gets|Provide|Provides|Queries|Query|Check|MIRRORED|Voltage Sag|Appends|Filename displays|Help|Ping|.*\bdisplays?\b)", re.I)
READ_BASE = {"EVE", "MET", "SHO", "HIS", "SER", "STA", "TAR", "CEV", "CHI", "SUM", "LDP", "COM", "BRE", "VER", "SSI", "CST", "CSU"}
OTHER_BASE = {"IRI", "PIN", "SNT"}


def classify(cmd, desc):
    toks = re.split(r"[\s,]+", cmd.upper())
    base = toks[0]
    b3 = base[:3]
    # long-form names in the old SEL-651R summary (2ACCESS, BACCESS, BREAKER, ...)
    if b3 in SESSION and not (b3 == "CAL" and len(toks) > 1):
        return "session"
    if base in ("ID",):
        return "read"
    if b3 == "FIL" and any(t.startswith("WRI") for t in toks):
        return "write"
    if re.match(r"^(Same as|For all)\b", desc):
        return "write" if b3 in WRITE_BASE else "read"
    if b3 in ("TES", "TIM", "DAT", "TRI", "GRO") and re.match(r"^(Displays?|Shows?)\b(?! or)", desc):
        return "read"
    if b3 == "TES" and re.match(r"^Displays? ", desc):
        return "read"
    if b3 in WRITE_BASE:
        return "write"
    if b3 in OTHER_BASE:
        return "other"
    if b3 in ("GRO",) and len(toks) > 1 and toks[1] not in ("?",):
        return "write"
    if b3 in ("DAT", "TIM") and len(toks) > 1:
        return "write"
    if re.search(r"from the (relay|meter|recloser control|recloser|device|control) to (the|a) (PC|computer)", desc, re.I):
        return "read"
    if re.search(r"^(Load profile|Loopback)", desc, re.I) and b3 == "LDP":
        return "read"
    if re.search(r"files? from (the )?(meter|relay|device|recloser|control)\b", desc, re.I):
        return "read"
    if re.search(r"from (a|the) (PC|computer)|to the (relay|meter|recloser control|device)\b", desc, re.I):
        return "write"
    if re.search(r"\bor (clear|modify|change|set|reset)\b|/change", desc, re.I):
        return "write"
    if WRITE_DESC.search(desc) or (WRITE_ANY.search(desc) and not READ_DESC.search(desc)):
        return "write"
    if WRITE_ANY.search(desc) and re.search(r"View/change|or change|or set|preload", desc, re.I):
        return "write"
    if b3 in OTHER_BASE:
        return "other"
    if READ_DESC.search(desc):
        return "read"
    if b3 in READ_BASE:
        return "read"
    return "other"


FID_RE = re.compile(r"(SEL-[0-9A-Za-z]+(?:-[0-9A-Za-z]+)*?-R(\d{3})[0-9A-Za-z-]*)")
DATE8 = re.compile(r"^(19|20)\d{6}$")


def parse_firmware(cfg, doc):
    revs = []
    cur = None
    in_table = False
    for pno in range(cfg["fw"][0], cfg["fw"][1] + 1):
        page = doc[pno - 1]
        H = page.rect.height
        lines = [l for l in page_lines(page) if 45 < l["y"] < H - 45]
        for l in lines:
            t = l["text"]
            if re.match(r"^Table A\.\d+", t):
                in_table = bool(re.search(r"Firmware Revision History", t)) and not re.search(r"SELBOOT|ICD|Display", t)
                cur = None
                continue
            if not in_table:
                continue
            ws = l["w"]
            fid = None
            for w in ws[:2]:
                m = FID_RE.match(w[4])
                if m and w[0] < 200:
                    fid = m
                    break
            datew = [w[4] for w in ws if DATE8.match(w[4]) and w[0] > 420]
            body = [w for w in ws if (fid is None or w[4] != fid.group(1)) and not (DATE8.match(w[4]) and w[0] > 420)]
            if fid:
                fid_s = fid.group(1)
                dm = re.search(r"-D(\d{8})", fid_s)
                cur = {"fid": fid_s, "revision": "R" + fid.group(2), "date": None, "bullets": [], "page": pno,
                       "_dcode": datew[0] if datew else None, "_fid_date": dm.group(1) if dm else None}
                revs.append(cur)
            elif cur is not None and datew and cur["_dcode"] is None:
                cur["_dcode"] = datew[0]
            if cur is None:
                continue
            # FID strings may wrap onto the next line in the FID column
            fidcol = [w for w in body if w[0] < 200 and not w[4].startswith("➤")]
            if fidcol and not fid and re.match(r"^[0-9A-Za-z-]+$", fidcol[0][4]) and "-" in fidcol[0][4] and len(fidcol) == 1:
                cur["fid"] += fidcol[0][4]
                body = [w for w in body if w is not fidcol[0]]
                dm = re.search(r"-D(\d{8})", cur["fid"])
                if dm:
                    cur["_fid_date"] = dm.group(1)
            txt = " ".join(w[4] for w in body)
            if not txt.strip():
                continue
            if txt.lstrip().startswith("➤") or not cur["bullets"]:
                for part in re.split(r"➤", txt):
                    if part.strip():
                        cur["bullets"].append(part.strip())
                    elif not cur["bullets"]:
                        pass
                if txt.lstrip().startswith("➤") and txt.count("➤") == 1 and not cur["bullets"]:
                    cur["bullets"].append("")
            else:
                cur["bullets"][-1] = (cur["bullets"][-1] + " " + txt).strip()
    merged = {}
    order = []
    for r in revs:
        if r["fid"] in merged:
            merged[r["fid"]]["bullets"] += r["bullets"]
            merged[r["fid"]]["_dcode"] = merged[r["fid"]]["_dcode"] or r["_dcode"]
        else:
            merged[r["fid"]] = r
            order.append(r["fid"])
    revs = [merged[f] for f in order]
    out = []
    for r in revs:
        d = r["_fid_date"] or r["_dcode"]
        date = f"{d[:4]}-{d[4:6]}-{d[6:]}" if d else None
        bullets = [clean(b.split()) for b in r["bullets"] if b.strip()]
        cmd_b = [b for b in bullets if re.search(r"\bcommand", b, re.I) or re.search(r"\bASCII\b", b)]
        out.append({"revision": r["revision"], "fid": r["fid"], "date": date,
                    "manual_date_code": r["_dcode"], "page": r["page"],
                    "command_changes": cmd_b, "n_change_bullets": len(bullets)})
    return out


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary = {}
    for cfg in MANUALS:
        doc = pymupdf.open(PDF_DIR / cfg["pdf"])
        cmds = parse_commands(cfg, doc)
        fw = parse_firmware(cfg, doc)
        rec = {
            "model": cfg["model"].split("_")[0],
            "manual": cfg["pdf"],
            "manual_date": cfg["date"],
            "source_url": cfg["docs_url"],
            "latest_manual_download_url": cfg["latest_im_url"],
            "source": "your own copy of the SEL instruction manual; selinc.com instruction-manual downloads require an SEL login",
            "covers": cfg.get("covers"),
            "command_table": cfg["table"],
            "command_pages": list(cfg["cmd"]),
            "firmware_pages": list(cfg["fw"]),
            "access_level_hierarchy": cfg["hier"] + ["C"],
            "note": cfg.get("note"),
            "commands": cmds,
            "firmware": fw,
        }
        (OUT / f"{cfg['model']}.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False))
        kinds = collections.Counter(c["kind"] for c in cmds)
        summary[cfg["model"]] = (len(cmds), dict(kinds), len(fw))
        print(cfg["model"], len(cmds), dict(kinds), "fw", len(fw))


if __name__ == "__main__":
    main()
