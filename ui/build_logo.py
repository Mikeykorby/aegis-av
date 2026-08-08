"""Rebuild the Aegis logo: cleaner shield + bold A mark."""
import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))

# ── Palette ────────────────────────────────────────────────
VERM = (200, 64, 43)
VERM_D = (160, 48, 32)
WHITE = (255, 255, 255)

# ── 1) SVG — crisp inline logo ─────────────────────────────
SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#d94e36"/>
      <stop offset="1" stop-color="#a8331f"/>
    </linearGradient>
  </defs>
  <path d="M32 5 8 15v17c0 13.3 9.6 25.2 24 28.8 14.4-3.6 24-15.5 24-28.8V15L32 5Z"
        fill="url(#g)"/>
  <path d="M32 5 8 15v17c0 13.3 9.6 25.2 24 28.8 14.4-3.6 24-15.5 24-28.8V15L32 5Z"
        fill="none" stroke="#ffffff" stroke-opacity=".18" stroke-width="1.3"/>
  <path d="M25.5 43.5 32 21l6.5 22.5" fill="none" stroke="#fff" stroke-width="4.8"
        stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M27.8 34.5h8.4" stroke="#fff" stroke-width="4.8" stroke-linecap="round"/>
</svg>'''
with open(os.path.join(HERE, "aegis.svg"), "w", encoding="utf-8") as f:
    f.write(SVG)
print("wrote aegis.svg")

# ── 2) ICO for window titlebar / taskbar ───────────────────
def make(size):
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pts = [
        (s*0.5, s*0.08), (s*0.10, s*0.24), (s*0.10, s*0.50),
        (s*0.10, s*0.60), (s*0.5, s*0.95), (s*0.90, s*0.60),
        (s*0.90, s*0.50), (s*0.90, s*0.24),
    ]
    d.polygon(pts, fill=VERM)
    d.line([(s*0.10, s*0.60), (s*0.5, s*0.95), (s*0.90, s*0.60)],
           fill=VERM_D, width=max(1, s//64))
    # Bold "A" mark
    aw = max(2.4, s*0.076)
    d.line([(s*0.38, s*0.72), (s*0.5, s*0.34), (s*0.62, s*0.72)],
           fill=WHITE, width=int(aw))
    d.line([(s*0.42, s*0.56), (s*0.58, s*0.56)],
           fill=WHITE, width=int(aw))
    return img

sizes = [16, 24, 32, 48, 64, 128, 256]
frames = [make(s) for s in sizes]
ico_path = os.path.join(HERE, "aegis.ico")
frames[0].save(ico_path, sizes=[(s, s) for s in sizes],
               format="ICO", append_images=frames[1:])
print("wrote aegis.ico", os.path.getsize(ico_path), "bytes")
