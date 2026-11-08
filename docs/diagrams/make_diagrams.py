"""Render the README architecture diagrams (light and dark PNGs, plus SVG sources).

    pip install cairosvg   # and the Inter font
    python docs/diagrams/make_diagrams.py
"""
import html
import os
import sys

import cairosvg

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "images")
FONT = "Inter, Helvetica, Arial, sans-serif"
MONO = "DejaVu Sans Mono, Menlo, monospace"
BLUE, GREEN, YELLOW, RED, PURPLE = "#4285F4", "#34A853", "#F9AB00", "#EA4335", "#A142F4"
THEMES = {
    "light": dict(bg="#FFFFFF", card="#FFFFFF", text="#1F2328", muted="#59636E", line="#59636E", soft="#F6F8FA"),
    "dark": dict(bg="#0D1117", card="#161B22", text="#E6EDF3", muted="#9198A1", line="#9198A1", soft="#1C2128"),
}


class Diagram:
    def __init__(self, w, h, theme):
        self.w, self.h, self.t, self.parts = w, h, THEMES[theme], []

    def text(self, x, y, s, size=15, color=None, bold=False, anchor="start", mono=False, italic=False):
        for i, line in enumerate(str(s).split("\n")):
            self.parts.append(
                f'<text x="{x}" y="{y + i * size * 1.35:.1f}" font-family="{MONO if mono else FONT}" '
                f'font-size="{size}" fill="{color or self.t["text"]}" font-weight="{700 if bold else 400}" '
                f'font-style="{"italic" if italic else "normal"}" text-anchor="{anchor}">{html.escape(line)}</text>')

    def card(self, x, y, w, h, title, body="", accent=BLUE, dashed=False, kicker=""):
        dash = ' stroke-dasharray="7 5"' if dashed else ""
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{self.t["card"]}" '
                          f'stroke="{accent}" stroke-width="2"{dash}/>')
        if not dashed:
            self.parts.append(f'<path d="M{x+12},{y} h{w-24} a12,12 0 0 1 12,12 v-0 h-{w} a12,12 0 0 1 12,-12z" fill="{accent}"/>')
            self.parts.append(f'<rect x="{x}" y="{y+6}" width="{w}" height="6" fill="{accent}"/>')
        ty = y + 40
        if kicker:
            self.text(x + 18, y + 34, kicker, 12, accent, bold=True)
            ty = y + 56
        self.text(x + 18, ty, title, 19, bold=True)
        if body:
            self.text(x + 18, ty + 26, body, 14.5, self.t["muted"])

    def topic(self, cx, cy, name):
        w, h = 150, 46
        self.parts.append(f'<rect x="{cx-w/2}" y="{cy-h/2}" width="{w}" height="{h}" rx="23" fill="{self.t["soft"]}" '
                          f'stroke="{PURPLE}" stroke-width="2"/>')
        self.text(cx, cy - 4, "Pub/Sub", 11, PURPLE, bold=True, anchor="middle")
        self.text(cx, cy + 13, name, 14, anchor="middle", mono=True)

    def line(self, pts, label="", both=False, dashed=False, lx=None, ly=None, anchor="middle"):
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        dash = ' stroke-dasharray="7 5"' if dashed else ""
        start = ' marker-start="url(#ahs)"' if both else ""
        self.parts.append(f'<path d="{d}" fill="none" stroke="{self.t["line"]}" stroke-width="2" '
                          f'marker-end="url(#ah)"{start}{dash}/>')
        if label:
            (x1, y1), (x2, y2) = pts[0], pts[-1]
            self.text(lx if lx is not None else (x1 + x2) / 2, ly if ly is not None else (y1 + y2) / 2 - 8,
                      label, 13, self.t["muted"], anchor=anchor)

    def save(self, name):
        c = self.t["line"]
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}">'
               f'<defs><marker id="ah" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto">'
               f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
               f'<marker id="ahs" markerWidth="10" markerHeight="10" refX="1" refY="5" orient="auto">'
               f'<path d="M10,0 L0,5 L10,10 z" fill="{c}"/></marker></defs>'
               f'<rect width="{self.w}" height="{self.h}" fill="{self.t["bg"]}"/>' + "".join(self.parts) + "</svg>")
        os.makedirs(OUT, exist_ok=True)
        open(os.path.join(OUT, f"{name}.svg"), "w").write(svg)
        cairosvg.svg2png(bytestring=svg.encode(), write_to=os.path.join(OUT, f"{name}.png"), output_width=self.w * 2)


def pipeline(theme):
    d = Diagram(1660, 800, theme)
    t = d.t
    # Gmail across the top
    d.card(360, 30, 1270, 74, "Gmail", "", accent=RED)
    d.text(440, 70, "protected mailbox · push notifications through users.watch", 14.5, t["muted"])
    # Stage cards
    d.card(360, 250, 330, 200, "email_ingest",
           "pef-ingest-sa\nhistory.list sync, lease-based claim\nadds the Pending label\nparses MIME, extracts URLs", BLUE, kicker="STAGE 1")
    d.card(830, 250, 330, 200, "email_analyze",
           "pef-analyze-sa\nno Gmail or Datastore access\nSafe Browsing check, then Gemini\npublishes scores and reasoning", YELLOW, kicker="STAGE 2")
    d.card(1300, 250, 330, 200, "email_outcome",
           "pef-outcome-sa\nverdict rules\nPending → Secured / Unsecured\nidempotent audit write", GREEN, kicker="STAGE 3")
    # Gmail -> email-watch -> ingest
    d.line([(470, 104), (470, 152)], "push", lx=482, ly=134, anchor="start")
    d.topic(470, 176, "email-watch")
    d.line([(470, 199), (470, 250)])
    d.line([(640, 104), (640, 250)], "read mail,\nadd Pending", both=True, lx=652, ly=160, anchor="start")
    d.text(995, 200, "no Gmail access", 13, t["muted"], italic=True, anchor="middle")
    d.line([(1580, 250), (1580, 104)], "final\nlabel", lx=1568, ly=160, anchor="end")
    # Stage to stage through topics
    d.line([(690, 350), (830, 350)])
    d.topic(760, 350, "email-analyze")
    d.line([(1160, 350), (1300, 350)])
    d.topic(1230, 350, "email-outcome")
    # Stage 2 dependencies
    d.card(830, 520, 160, 96, "Safe Browsing", "v5 urls:search", accent=RED)
    d.card(1000, 520, 160, 96, "Gemini", "3.8 Flash\n(+ escalation)", accent=BLUE)
    d.line([(910, 450), (910, 520)], both=True)
    d.line([(1080, 450), (1080, 520)], both=True)
    # Sheets
    d.card(1450, 520, 180, 96, "Google Sheets", "audit log", accent=GREEN)
    d.line([(1540, 450), (1540, 520)])
    # Datastore
    d.card(360, 680, 1270, 74, "Firestore in Datastore mode", "", accent=BLUE)
    d.text(665, 720, "claims · history cursor · OAuth tokens · verdict audit log", 14.5, t["muted"])
    d.line([(440, 450), (440, 680)], "claims,\nhistory cursor", both=True, lx=452, ly=560, anchor="start")
    d.line([(1340, 450), (1340, 680)], "verdict +\nreasoning", lx=1352, ly=560, anchor="start")
    # Simulator and dead letters
    d.card(30, 140, 290, 76, "tools/simulator.py", "", accent=t["muted"], dashed=True)
    d.text(48, 200, "ALLOW_SIMULATED_PAYLOADS=true", 12, t["muted"], mono=True)
    d.line([(320, 176), (395, 176)], dashed=True)
    d.card(30, 300, 290, 150, "email-dlq", "every topic dead-letters\nhere after\nPEF_MAX_DELIVERY_ATTEMPTS", accent=PURPLE, dashed=True)
    d.text(48, 432, "inspect: email-dlq-inspect", 12, t["muted"], mono=True)
    d.line([(400, 196), (322, 300)], dashed=True)
    d.save(f"pipeline-{theme}")


def onboarding(theme):
    d = Diagram(1620, 450, theme)
    d.card(40, 50, 210, 100, "Mailbox owner", "opens the\nonboarding URL", accent=d.t["muted"])
    d.card(340, 30, 380, 140, "auth_init → auth_callback", "OAuth2 with CSRF state + PKCE\npef-auth-sa", accent=BLUE)
    d.card(40, 290, 210, 110, "Cloud Scheduler", "daily\npef-scheduler-sa", accent=YELLOW)
    d.card(340, 280, 380, 130, "auth_renew_watch", "pef-auth-sa\nnot publicly invokable", accent=BLUE)
    d.card(830, 175, 300, 100, "Firestore", "Datastore mode\nOAuth refresh tokens", accent=BLUE)
    d.card(1260, 30, 320, 380, "Gmail", "Pending, Secured and\nUnsecured labels\n\npush notifications\n(users.watch, 7 days)", accent=RED)
    d.line([(250, 100), (340, 100)])
    d.line([(250, 345), (340, 345)], "OIDC", ly=335)
    d.line([(720, 70), (1260, 70)], "create labels, users.watch", ly=60)
    d.line([(720, 380), (1260, 380)], "renew the 7-day watch", ly=370)
    d.line([(720, 150), (830, 205)], "refresh token", lx=790, ly=165, anchor="start")
    d.line([(720, 305), (830, 250)], "read token", both=True, lx=790, ly=300, anchor="start")
    d.save(f"onboarding-{theme}")


for th in THEMES:
    pipeline(th)
    onboarding(th)
