import os, struct
from PIL import Image, ImageDraw

# Recreate the Aegis shield mark (matches ui/aegis.svg) at multiple sizes.
# Shield path (viewBox 0..64): M32 5 L8 15 v17 c0 13.3 9.6 25.2 24 28.8
#                               14.4-3.6 24-15.5 24-28.8 V15 Z
# Center vertical bar (checkmark-like) drawn in paper color.

def draw_shield(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size
    # scaled points (fraction of size)
    def P(x, y):
        return (x / 64.0 * s, y / 64.0 * s)
    top = P(32, 5)
    l_sh = P(8, 15)
    r_sh = P(56, 15)
    # build shield outline
    outline = [
        top,
        l_sh,
        # left side down to bottom tip
        P(8, 32),
        P(14, 45),
        P(32, 58),
        P(50, 45),
        P(56, 32),
        r_sh,
    ]
    # vertical gradient fill by drawing horizontal slices
    miny = int(P(5, 5)[1]); maxy = int(P(58, 58)[1])
    c_top = (217, 78, 54)    # #d94e36
    c_bot = (168, 51, 31)    # #a8331f
    # approximate shield polygon for clipping using bbox + mask
    # Simpler: draw filled polygon (flat middle color) then overlay gradient via mask.
    flat = (200, 64, 42)
    d.polygon(outline, fill=flat)
    # gradient: create a vertical gradient image and mask to shield shape
    grad = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grad)
    for yy in range(size):
        t = yy / max(1, size - 1)
        r = int(c_top[0] + (c_bot[0] - c_top[0]) * t)
        g = int(c_top[1] + (c_bot[1] - c_top[1]) * t)
        b = int(c_top[2] + (c_bot[2] - c_top[2]) * t)
        gd.line([(0, yy), (size, yy)], fill=(r, g, b, 255))
    # mask = shield shape
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon(outline, fill=255)
    grad.putalpha(mask)
    img = Image.alpha_composite(img, grad)
    # subtle inner border highlight
    d2 = ImageDraw.Draw(img)
    d2.line(outline + [outline[0]], fill=(255, 255, 255, 60), width=max(1, s // 64))
    # center "A" bar in paper color (#f4efe4)
    paper = (244, 239, 228, 255)
    ax = size * 0.5
    d2.line([P(32, 20), P(32, 46)], fill=paper, width=max(2, round(s * 0.12)))
    d2.line([P(22, 30), P(42, 30)], fill=paper, width=max(2, round(s * 0.12)))
    return img

sizes = [16, 32, 48, 64, 128, 256]
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "aegis.ico")
# Pillow ICO writer generates each requested size by resampling the source.
big = draw_shield(256)
big.save(out, format="ICO", sizes=[(s, s) for s in sizes])
print("wrote", out, os.path.getsize(out), "bytes")
# verify
with open(out, "rb") as f:
    data = f.read()
print("magic", data[:4].hex())
import struct
cnt = struct.unpack("<HHH", data[:6])[2]
print("sub-images", cnt)
