"""Print lines of a PDF page with x-positions of each word: usage lines.py pdf page[-page]"""
import sys, pymupdf

doc = pymupdf.open(sys.argv[1])
a, _, b = sys.argv[2].partition("-")
for pno in range(int(a), int(b or a) + 1):
    page = doc[pno - 1]
    words = page.get_text("words")
    words.sort(key=lambda w: (round(w[1]), w[0]))
    lines = []
    for w in words:
        if lines and abs(lines[-1][0] - w[1]) < 3:
            lines[-1][1].append(w)
        else:
            lines.append([w[1], [w]])
    print(f"### page {pno} width={page.rect.width:.0f}")
    for y, ws in lines:
        ws.sort(key=lambda w: w[0])
        print(f"{y:6.1f} " + " ".join(f"{w[4]}@{w[0]:.0f}" for w in ws))
