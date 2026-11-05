"""Dump each PDF to text/<stem>.txt with form-feed page separators and a page marker."""
import sys, pathlib, pymupdf

out = pathlib.Path(sys.argv[1])
for p in sys.argv[2:]:
    p = pathlib.Path(p)
    doc = pymupdf.open(p)
    parts = []
    for i, page in enumerate(doc, 1):
        parts.append(f"\n<<<PAGE {i}>>>\n" + page.get_text("text", sort=True))
    (out / (p.stem + ".txt")).write_text("".join(parts))
    print(p.name, len(doc))
