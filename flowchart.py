#!/usr/bin/env python3
"""Render the ATSGuard pipeline flowchart -> media/atsguard_flowchart.png"""
from __future__ import annotations

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.join(HERE, "media")
W, H = 1480, 900
BG = (13, 17, 23)
PANEL = (22, 27, 34)
FG = (201, 209, 217)
GRAY = (139, 148, 158)
BLUE = (88, 166, 255)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
YELLOW = (210, 168, 60)
CYAN = (86, 182, 194)
PURPLE = (188, 140, 255)

def F(sz, bold=False):
    return ImageFont.truetype(r"C:\Windows\Fonts\consola%s.ttf" % ("b" if bold else ""), sz)

def box(d, x, y, w, h, title, lines, accent):
    d.rounded_rectangle([x, y, x + w, y + h], radius=12, fill=PANEL, outline=accent, width=2)
    d.rectangle([x, y, x + 6, y + h], fill=accent)
    d.text((x + 18, y + 12), title, font=F(18, True), fill=accent)
    yy = y + 42
    for ln in lines:
        d.text((x + 18, yy), ln, font=F(14), fill=FG)
        yy += 20

def arrow(d, x1, y1, x2, y2, color=GRAY, wdt=3, label=None, lcol=None):
    d.line([x1, y1, x2, y2], fill=color, width=wdt)
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    L = 12
    d.polygon([(x2, y2),
               (x2 - L * math.cos(ang - 0.5), y2 - L * math.sin(ang - 0.5)),
               (x2 - L * math.cos(ang + 0.5), y2 - L * math.sin(ang + 0.5))], fill=color)
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        f = F(15, True)
        tw = d.textlength(label, font=f)
        d.rectangle([mx - tw / 2 - 6, my - 12, mx + tw / 2 + 6, my + 10], fill=BG)
        d.text((mx - tw / 2, my - 10), label, font=f, fill=lcol or color)

def pill(d, x, y, text, color):
    f = F(15, True)
    tw = d.textlength(text, font=f)
    d.rounded_rectangle([x, y, x + tw + 28, y + 34], radius=17, fill=PANEL, outline=color, width=2)
    d.text((x + 14, y + 8), text, font=f, fill=color)
    return tw + 28

def main():
    os.makedirs(MEDIA, exist_ok=True)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.text((40, 28), "ATSGuard — resume prompt-injection defense pipeline", font=F(26, True), fill=BLUE)
    d.text((42, 66), "OWASP LLM01 (indirect prompt injection) · defense-in-depth · the model only ever sees sanitized text",
           font=F(15), fill=GRAY)

    row_y, bw, bh = 110, 320, 168
    xs = [40, 405, 770, 1135]
    box(d, xs[0], row_y, bw, bh, "① Intake",
        [".pdf · .docx · .txt", "resume arrives from the", "career site / job board", "", "(untrusted input)"], CYAN)
    box(d, xs[1], row_y, bw, bh, "② L1 · Ingest (with style)",
        ["extract text + how it renders:", "font size, color, alpha,", "off-page bbox, DOCX w:vanish,", "document metadata",
         "→ hidden spans become visible"], PURPLE)
    box(d, xs[2], row_y, bw, bh, "③ L2 · Sanitize",
        ["keep VISIBLE-ONLY text", "strip zero-width / bidi / tag", "NFKC + confusables fold", "de-leetspeak · de-char-spacing",
         "→ payload removed + de-obfuscated"], BLUE)
    box(d, xs[3], row_y, bw, bh, "④ L3 · Detect",
        ["injection patterns scored on", "raw + skeleton + normalized", "8 families, deictic-anchored", "hidden-text + unicode signals",
         "→ risk score"], YELLOW)
    for i in range(3):
        arrow(d, xs[i] + bw, row_y + bh / 2, xs[i + 1], row_y + bh / 2)

    # verdict diamond
    cx, cy, r = xs[3] + bw / 2, 400, 66
    d.polygon([(cx, cy - r), (cx + r + 40, cy), (cx, cy + r), (cx - r - 40, cy)], fill=PANEL, outline=FG, width=2)
    d.text((cx - 44, cy - 14), "Verdict?", font=F(20, True), fill=FG)
    arrow(d, xs[3] + bw / 2, row_y + bh, cx, cy - r)

    # outcome boxes
    oy, ow, oh = 560, 380, 150
    ax, fx, bx = 40, 470, 900
    box(d, ax, oy, ow, oh, "ALLOW → ⑤ L4 · Safe prompt",
        ["build_safe_prompt(sanitized)", "resume passed as delimited", "UNTRUSTED DATA (spotlighting)", "model told: never obey it"], GREEN)
    box(d, fx, oy, ow, oh, "FLAG → human review",
        ["routed to review_queue/", "a person looks first;", "the model does NOT auto-run", "fail-closed on extract error"], YELLOW)
    box(d, bx, oy, ow, oh, "BLOCK → quarantine",
        ["routed to quarantine/", "hidden/injected text recorded", "NEVER forwarded to the model", "exit code != 0 (CI alert)"], RED)

    arrow(d, cx - 30, cy + 40, ax + ow / 2, oy, GREEN, label="ALLOW", lcol=GREEN)
    arrow(d, cx, cy + r, fx + ow / 2, oy, YELLOW, label="FLAG", lcol=YELLOW)
    arrow(d, cx + 30, cy + 40, bx + ow / 2, oy, RED, label="BLOCK", lcol=RED)

    # LLM endpoint from ALLOW
    d.rounded_rectangle([ax + 90, 748, ax + 290, 792], radius=18, fill=PANEL, outline=GREEN, width=2)
    d.text((ax + 110, 758), "→ LLM screening (safe)", font=F(15, True), fill=GREEN)
    arrow(d, ax + ow / 2, oy + oh, ax + ow / 2, 748, GREEN)

    # audit trail
    d.rounded_rectangle([fx, 748, bx + ow, 792], radius=12, fill=PANEL, outline=GRAY, width=2)
    d.text((fx + 16, 758),
           "audit.jsonl — every decision logged (file · sha256 · verdict · findings) · Local Law 144 / EU AI Act trail",
           font=F(14), fill=GRAY)
    arrow(d, fx + ow / 2, oy + oh, fx + ow / 2, 748, GRAY)
    arrow(d, bx + ow / 2, oy + oh, bx + ow / 2, 748, GRAY)

    # metric badges
    bx0 = 40
    for text, col in [("false positives  0.00%  (0 / 1200+)", GREEN),
                      ("recall  98.8%", GREEN),
                      ("unit tests  8/8", GREEN),
                      ("verified on real PDF/DOCX/TXT", CYAN)]:
        bx0 += pill(d, bx0, 828, text, col) + 16

    img.save(os.path.join(MEDIA, "atsguard_flowchart.png"))
    print("wrote media/atsguard_flowchart.png")

if __name__ == "__main__":
    main()
