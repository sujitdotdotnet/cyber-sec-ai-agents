"""Generate the dashboard banner: a still PNG (idle) and an animated GIF (scanning) of the same artwork.

    python scripts/make_banner.py

Writes app/assets/banner_still.png and app/assets/banner_scan.gif. The artwork: six agent nodes linked
to a central shield, with a radar ring around it, over a backdrop of green code lines. Idle = calm
still. Scanning = radar sweep, data packets travelling from the agents into the shield, nodes pulsing
as packets arrive, and a scan bar moving top to bottom that lights up each code line it passes.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H, S = 1200, 200, 2  # output size and supersampling factor (drawn at 2x, then downscaled for smooth edges)
CX, CY = W / 2, H / 2
FRAME_MS = 45
RADAR_FRAMES = 36  # radar rotation and packet cycle: 36 frames = ~1.6 s
BAR_PASS_RATIO = 2  # the scan bar takes this many radar cycles per top-to-bottom pass (2 = half the speed)
FRAMES = RADAR_FRAMES * BAR_PASS_RATIO  # the GIF loops seamlessly after one bar pass
OUT = Path(__file__).resolve().parent.parent / "app" / "assets"

CYAN = (53, 208, 255)
NODES = [  # (x, y, colour): the five agents + the reporter
    (140, 52, (53, 208, 255)), (300, 148, (124, 140, 255)), (450, 56, (46, 229, 157)),
    (750, 56, (255, 180, 84)), (900, 148, (255, 107, 138)), (1060, 52, (199, 146, 234)),
]

GREEN, GREEN_HI = (60, 220, 120), (150, 255, 175)  # code text: resting and just-scanned
CODE_FONT_PX, CODE_LINE_PX, CODE_TOP = 11, 17, 18
CODE_BLOCKS = [  # (x, lines): vulnerable-looking snippets, like the ones the Vulnerability Scanner reports.
    # Rows 1-3 sit beside the outer agent nodes, so they are kept short enough not to run underneath them.
    (14, [
        'def login(user, pw):',
        'q = sql + user',
        'cur.execute(q)',
        'pw = "admin123"',
        'app.run(debug=True)',
        'subprocess.call(cmd, shell=True)',
        'token = md5(pw).hexdigest()',
        'return redirect(request.args["next"])',
        'API_KEY = "sk-live-9f2c..."',
        'os.chmod(path, 0o777)',
    ]),
    (930, [
        'eval(request.form["expr"])',
        'yaml.load(body)',
        'USER root',
        'FROM python:3.8',
        'pickle.loads(request.data)',
        'requests.get(url, verify=False)',
        'open(os.path.join(BASE, name))',
        'os.system("ping " + host)',
        'ENV DB_PASSWORD=hunter2',
        'chmod 777 /var/www',
    ]),
]


def code_font() -> ImageFont.ImageFont:
    for name in ("consola.ttf", "Consolas.ttf", "DejaVuSansMono.ttf", "LiberationMono-Regular.ttf", "cour.ttf", "Menlo.ttc"):
        try:
            return ImageFont.truetype(name, CODE_FONT_PX * S)
        except OSError:
            continue
    return ImageFont.load_default(CODE_FONT_PX * S)


def lerp(a: tuple, b: tuple, t: float) -> tuple[int, ...]:
    return tuple(int(x + (y - x) * t) for x, y in zip(a, b))


def code_layer(bar_y: float | None) -> Image.Image:
    """Green code lines. While scanning, a line flares as the bar passes it and fades back behind the bar."""
    layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    font = code_font()
    for x, lines in CODE_BLOCKS:
        for i, text in enumerate(lines):
            y = CODE_TOP + i * CODE_LINE_PX
            boost = 0.0
            if bar_y is not None:
                behind = bar_y - (y + CODE_FONT_PX / 2)  # >0: the bar has already passed this line
                if behind >= -6:
                    boost = max(0.0, 1 - max(behind, 0) / 70)
            alpha = int(95 + 160 * boost) if bar_y is not None else 110
            d.text(px(x, y), text, font=font, fill=lerp(GREEN, GREEN_HI, boost) + (alpha,))
    return layer


def scan_bar_layer(y: float) -> Image.Image:
    """A horizontal bar with a glowing trail above it, spanning the full width."""
    layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for k in range(48, 0, -2):  # trail fades upward
        d.rectangle([px(0, y - k - 2), px(W, y - k)], fill=GREEN + (int(70 * (1 - k / 48) ** 1.6),))
    d.rectangle([px(0, y - 4), px(W, y + 4)], fill=GREEN + (55,))  # halo
    d.rectangle([px(0, y - 1.5), px(W, y + 1.5)], fill=GREEN_HI + (255,))  # the bar itself
    return layer


def px(x: float, y: float) -> tuple[float, float]:
    return x * S, y * S


def background() -> Image.Image:
    img = Image.new("RGBA", (W * S, H * S))
    d = ImageDraw.Draw(img)
    top, bottom = (9, 15, 30), (16, 27, 52)
    for y in range(H * S):
        t = y / (H * S - 1)
        d.line([(0, y), (W * S, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    for gx in range(20, W, 40):  # faint dot grid
        for gy in range(20, H, 40):
            d.ellipse([px(gx - 1, gy - 1), px(gx + 1, gy + 1)], fill=(80, 110, 160, 60))
    return img


def glow_circle(d: ImageDraw.ImageDraw, x: float, y: float, r: float, color, strength: int = 90) -> None:
    for k in range(4, 0, -1):  # concentric translucent discs fake a glow
        rr = r + k * 3
        d.ellipse([px(x - rr, y - rr), px(x + rr, y + rr)], fill=color + (strength // (k + 1),))
    d.ellipse([px(x - r, y - r), px(x + r, y + r)], fill=color + (255,))


def shield(d: ImageDraw.ImageDraw, active: bool) -> None:
    pts = [(0, -38), (30, -28), (30, 4), (24, 20), (12, 31), (0, 38), (-12, 31), (-24, 20), (-30, 4), (-30, -28)]
    poly = [px(CX + x, CY + y) for x, y in pts]
    d.polygon(poly, fill=(14, 40, 70, 255))
    d.line(poly + [poly[0]], fill=CYAN + (255,), width=int(3.5 * S), joint="curve")
    inner = [px(CX + x * 0.78, CY + y * 0.78) for x, y in pts]
    d.line(inner + [inner[0]], fill=CYAN + (110 if active else 70,), width=S)
    tick = [px(CX - 13, CY + 2), px(CX - 4, CY + 12), px(CX + 15, CY - 11)]
    d.line(tick, fill=(46, 229, 157, 255) if active else (150, 220, 200, 255), width=int(5 * S), joint="curve")


def phase_of(step: int | None) -> float:
    return (step or 0) / FRAMES


def frame(step: int | None) -> Image.Image:
    """step=None renders the idle still; otherwise one animation frame (0..FRAMES-1)."""
    active = step is not None
    base = background()
    bar_y = -10 + phase_of(step) * (H + 20) if active else None  # sweeps top to bottom once per loop, then off-screen
    base = Image.alpha_composite(base, code_layer(bar_y))
    if active:
        base = Image.alpha_composite(base, scan_bar_layer(bar_y))
    ov = Image.new("RGBA", base.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(ov)
    phase = (step or 0) % RADAR_FRAMES / RADAR_FRAMES  # radar / packet / node cycle

    # links agent -> shield
    for i, (nx, ny, col) in enumerate(NODES):
        d.line([px(nx, ny), px(CX, CY)], fill=col + (70 if active else 45,), width=S + 1)
        if active:
            p = (phase * 2 + i / len(NODES)) % 1.0  # two packet trips per rotation, staggered per agent
            x, y = nx + (CX - nx) * p, ny + (CY - ny) * p
            glow_circle(d, x, y, 4, col, 140)

    # radar rings and crosshair
    for r in (28, 50, 72, 94):
        d.ellipse([px(CX - r, CY - r), px(CX + r, CY + r)], outline=CYAN + (80 if active else 50,), width=S)
    d.line([px(CX - 98, CY), px(CX + 98, CY)], fill=CYAN + (35,), width=S)
    d.line([px(CX, CY - 98), px(CX, CY + 98)], fill=CYAN + (35,), width=S)

    if active:  # sweep with a fading trail
        a = step % RADAR_FRAMES * 360 / RADAR_FRAMES
        for i in range(0, 70, 2):
            d.pieslice([px(CX - 94, CY - 94), px(CX + 94, CY + 94)], a - i - 2, a - i,
                       fill=CYAN + (int(120 * (1 - i / 70) ** 1.5),))
        rad = math.radians(a)
        d.line([px(CX, CY), px(CX + 94 * math.cos(rad), CY + 94 * math.sin(rad))], fill=CYAN + (255,), width=int(2.5 * S))

    shield(d, active)

    # agent nodes on top; they pulse when a packet reaches the shield
    for i, (nx, ny, col) in enumerate(NODES):
        pulse = 0.0
        if active:
            p = (phase * 2 + i / len(NODES)) % 1.0
            pulse = max(0.0, 1 - abs(p - 0.0) * 6) if p < 0.17 else (max(0.0, 1 - (1 - p) * 6) if p > 0.83 else 0.0)
        r = 15 + 4 * pulse
        d.ellipse([px(nx - r - 6, ny - r - 6), px(nx + r + 6, ny + r + 6)], fill=col + (int(30 + 60 * pulse),))
        d.ellipse([px(nx - r, ny - r), px(nx + r, ny + r)], fill=(12, 22, 42, 255), outline=col + (255,), width=int(3 * S))
        d.ellipse([px(nx - 5, ny - 5), px(nx + 5, ny + 5)], fill=col + (255 if active else 200,))

    return Image.alpha_composite(base, ov).convert("RGB").resize((W, H), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    frame(None).save(OUT / "banner_still.png", optimize=True)

    frames = [frame(i) for i in range(FRAMES)]
    # one shared palette sampled from several frames, so pulses and packets keep their colours
    picks = [frames[i] for i in range(0, FRAMES, FRAMES // 6)]
    sheet = Image.new("RGB", (W, H * len(picks)))
    for i, f in enumerate(picks):
        sheet.paste(f, (0, i * H))
    palette = sheet.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    quantized = [f.quantize(palette=palette, dither=Image.Dither.NONE) for f in frames]
    quantized[0].save(OUT / "banner_scan.gif", save_all=True, append_images=quantized[1:],
                      duration=FRAME_MS, loop=0, optimize=True, disposal=1)
    for name in ("banner_still.png", "banner_scan.gif"):
        print(f"{name}: {(OUT / name).stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
