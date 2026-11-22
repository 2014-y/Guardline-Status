# -*- coding: utf-8 -*-
"""生成满画幅（Full-Bleed）Claude 像素吉祥物风格路由器面板高清图标（icon.ico / icon.png / icon_96.png）。"""
import io
import struct
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent


def superellipse_mask(size: int, pad: float = 1.0, n: float = 5.0) -> Image.Image:
    """2x 超采样平滑连续曲率圆角矩形蒙版（满画幅无外部空隙，四角丝滑抗锯齿）。"""
    ss = 2
    N = size * ss
    half = (size - 2.0 * pad) * ss / 2.0
    c = N / 2.0
    coords = np.abs(np.arange(N, dtype=np.float64) + 0.5 - c) / half
    val = (coords[:, None] ** n) + (coords[None, :] ** n)
    edge = np.clip((1.0 - val) * half * 0.72, 0.0, 1.0)
    hi = Image.fromarray((edge * 255.0).astype(np.uint8), mode="L")
    return hi.resize((size, size), Image.Resampling.LANCZOS)


def build_master(S: int = 1024) -> Image.Image:
    # 1. 满画幅陶土珊瑚橙立体方圆角底板（pad=1px 占满 99.8% 画幅，消除桌面留白）
    pad = 1.0
    n_exp = 5.0
    mask = superellipse_mask(S, pad=pad, n=n_exp)

    ys = np.linspace(0.0, 1.0, S, dtype=np.float32)[:, None]
    xs = np.linspace(-1.0, 1.0, S, dtype=np.float32)[None, :]
    glow = np.exp(-(xs ** 2 + (ys - 0.38) ** 2 * 2.0) * 1.4) * 11.0
    r = np.clip(250.0 - ys * 26.0 + glow, 0, 255).astype(np.uint8)
    g = np.clip(121.0 - ys * 28.0 + glow * 0.55, 0, 255).astype(np.uint8)
    b = np.clip(79.0 - ys * 24.0 + glow * 0.35, 0, 255).astype(np.uint8)
    a = np.array(mask, dtype=np.uint8)

    canvas = Image.fromarray(np.dstack([
        np.broadcast_to(r, (S, S)),
        np.broadcast_to(g, (S, S)),
        np.broadcast_to(b, (S, S)),
        a,
    ]), mode="RGBA")

    # 顶部微高光内边 + 底部微立体暗边（不占用任何画布外围空间）
    inner_mask = superellipse_mask(S, pad=pad + S * 0.013, n=n_exp)
    ring = np.clip(a.astype(np.float32) - np.array(inner_mask, dtype=np.float32), 0.0, 255.0) / 255.0

    hi_alpha = (ring * np.clip(1.0 - ys / 0.48, 0.0, 1.0) * 98.0).astype(np.uint8)
    hi_layer = Image.new("RGBA", (S, S), (255, 232, 220, 0))
    hi_layer.putalpha(Image.fromarray(hi_alpha, mode="L"))
    canvas.alpha_composite(hi_layer)

    lo_alpha = (ring * np.clip((ys - 0.65) / 0.35, 0.0, 1.0) * 68.0).astype(np.uint8)
    lo_layer = Image.new("RGBA", (S, S), (132, 36, 15, 0))
    lo_layer.putalpha(Image.fromarray(lo_alpha, mode="L"))
    canvas.alpha_composite(lo_layer)

    # 2. 在独立透明图层绘制大比例像素吉祥物 Clawd + 双层像素路由器信号波并正常 Alpha 合成
    fg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(fg)
    white = (255, 252, 249, 255)
    wave_outer = (255, 252, 249, 236)
    clear = (0, 0, 0, 0)

    # 横向 16.0 格，纵向 -5.65 .. +9.55 = 15.2 格，上下左右均衡饱满占满图标内部
    u = S * 0.0547
    gw = 16.0 * u
    gy_min, gy_max = -5.65, 9.55
    gh = (gy_max - gy_min) * u
    ox = (S - gw) / 2.0
    oy = (S - gh) / 2.0 - gy_min * u

    def prect(gx0, gy0, gx1, gy1, color):
        draw.rectangle([
            round(ox + gx0 * u),
            round(oy + gy0 * u),
            round(ox + gx1 * u) - 1,
            round(oy + gy1 * u) - 1,
        ], fill=color)

    # 顶部清晰双层像素 Wi-Fi 信号（层间净距充足，小尺寸下依然清晰分明）
    prect(7.2, -2.05, 8.8, -0.95, white)
    prect(6.1, -3.85, 9.9, -2.85, white)
    prect(4.85, -3.0, 6.1, -2.0, white)
    prect(9.9, -3.0, 11.15, -2.0, white)

    prect(5.0, -5.65, 11.0, -4.65, wave_outer)
    prect(3.6, -4.75, 5.0, -3.75, wave_outer)
    prect(11.0, -4.75, 12.4, -3.75, wave_outer)

    # 主身体：12.4 格宽 × 7.0 格高
    prect(1.8, 0.0, 14.2, 7.0, white)
    # 左右小手
    prect(0.0, 3.05, 1.8, 5.3, white)
    prect(14.2, 3.05, 16.0, 5.3, white)
    # 四只扎实小短腿
    prect(2.95, 7.0, 4.45, 9.55, white)
    prect(5.3, 7.0, 6.8, 9.55, white)
    prect(9.2, 7.0, 10.7, 9.55, white)
    prect(11.55, 7.0, 13.05, 9.55, white)

    # 镂空两只竖长方形眼睛，透出底板自然珊瑚橙渐变
    prect(4.5, 1.75, 5.95, 4.35, clear)
    prect(10.05, 1.75, 11.5, 4.35, clear)

    canvas.alpha_composite(fg)
    return canvas


def resize_crisp(master: Image.Image, sz: int) -> Image.Image:
    im = master.resize((sz, sz), Image.Resampling.LANCZOS)
    if sz <= 64:
        r, g, b, a = im.split()
        rgb = Image.merge("RGB", (r, g, b)).filter(
            ImageFilter.UnsharpMask(radius=0.75, percent=50, threshold=2)
        )
        im = Image.merge("RGBA", (*rgb.split(), a))
    return im


def _encode_ico_dib(im: Image.Image) -> bytes:
    """将小尺寸 RGBA 帧编码为标准 Windows 32-bit BGRA DIB + 1-bit AND 掩码，兼容所有 Win32/托盘 API。"""
    w, h = im.size
    arr = np.array(im.convert("RGBA"), dtype=np.uint8)
    # DIB 自底向上存储，通道顺序 B, G, R, A
    flipped = arr[::-1, :, :]
    bgra = flipped[:, :, [2, 1, 0, 3]].tobytes()

    # 1-bit AND 掩码（alpha == 0 置 1，每行按 4 字节对齐）
    trans = (flipped[:, :, 3] == 0).astype(np.uint8)
    row_bytes = ((w + 31) // 32) * 4
    padded = np.zeros((h, row_bytes * 8), dtype=np.uint8)
    padded[:, :w] = trans
    and_mask = np.packbits(padded, axis=1).tobytes()

    header = struct.pack(
        "<IIIHHIIIIII",
        40,                 # biSize
        w,                  # biWidth
        h * 2,              # biHeight (XOR + AND)
        1,                  # biPlanes
        32,                 # biBitCount
        0,                  # biCompression (BI_RGB)
        len(bgra) + len(and_mask),
        0, 0, 0, 0,
    )
    return header + bgra + and_mask


def save_windows_ico(path: Path, frames: list[Image.Image]):
    """生成符合微软官方规范的多尺寸 ICO：<256px 采用 32-bit DIB，256px 采用无损 PNG。"""
    payloads: list[tuple[int, int, bytes]] = []
    for im in frames:
        w, h = im.size
        if w >= 256 or h >= 256:
            buf = io.BytesIO()
            im.save(buf, format="PNG", optimize=True)
            payloads.append((w, h, buf.getvalue()))
        else:
            payloads.append((w, h, _encode_ico_dib(im)))

    count = len(payloads)
    out = bytearray(struct.pack("<HHH", 0, 1, count))
    offset = 6 + 16 * count
    for w, h, data in payloads:
        bw = 0 if w >= 256 else w
        bh = 0 if h >= 256 else h
        out += struct.pack("<BBBBHHII", bw, bh, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, _, data in payloads:
        out += data
    path.write_bytes(bytes(out))


def main():
    master = build_master(1024)
    img256 = resize_crisp(master, 256)
    img96 = resize_crisp(master, 96)
    img256.save(HERE / "icon.png", "PNG", optimize=True)
    img96.save(HERE / "icon_96.png", "PNG", optimize=True)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [resize_crisp(master, sz) for sz in sizes]
    save_windows_ico(HERE / "icon.ico", frames)
    save_windows_ico(HERE / "claude_router.ico", frames)
    print("Generated full-bleed Claude router icons successfully.")


if __name__ == "__main__":
    main()
