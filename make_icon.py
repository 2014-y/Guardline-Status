# -*- coding: utf-8 -*-
"""从高清 3D 渲染底图生成透明圆角桌面图标（icon.ico / icon.png / icon_96.png）。

通过精确圆角矩形几何拟合外圈拉丝金属边框，保留完整均匀的金属倒角边缘，
彻底剥离外部深色背景并叠加柔和环境投影，各小尺寸（16~64px）单独锐化。
"""
from collections import deque
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

HERE = Path(__file__).resolve().parent
MASTER = HERE / "icon_master.jpg"


def extract_exact_alpha(rgb_arr: np.ndarray) -> tuple[tuple[int, int, int, int], np.ndarray]:
    """从四角向内漫水填充（Flood Fill）精准剥离外部深色底，完整保留内部深蓝玻璃与金属边框。"""
    h, w, _ = rgb_arr.shape
    lum = 0.299 * rgb_arr[:, :, 0] + 0.587 * rgb_arr[:, :, 1] + 0.114 * rgb_arr[:, :, 2]
    # 外部底色亮度约 6~11，金属边框外沿 > 22
    bg_cand = lum < 22.0
    outside = np.zeros((h, w), dtype=bool)
    q = deque([(0, 0), (0, w - 1), (h - 1, 0), (h - 1, w - 1)])
    for y, x in q:
        outside[y, x] = True
    while q:
        y, x = q.popleft()
        for ny, nx in ((y - 1, x), (y + 1, x), (y, x - 1), (y, x + 1)):
            if 0 <= ny < h and 0 <= nx < w and not outside[ny, nx] and bg_cand[ny, nx]:
                outside[ny, nx] = True
                q.append((ny, nx))

    inside = ~outside
    ys, xs = np.where(inside)
    x0, y0, x1, y1 = int(xs.min()), int(ys.min()), int(xs.max()), int(ys.max())

    # 对边界做亚像素平滑羽化并向内微缩 1.2px 消除暗边
    alpha_img = Image.fromarray((inside.astype(np.uint8) * 255), mode="L")
    alpha_img = alpha_img.filter(ImageFilter.MinFilter(3))  # 向内收缩 1px 彻底消除残余黑边
    alpha_img = alpha_img.filter(ImageFilter.GaussianBlur(1.1))
    return (x0, y0, x1, y1), np.array(alpha_img)


def make():
    src = Image.open(MASTER).convert("RGB")
    arr = np.array(src)
    (x0, y0, x1, y1), full_alpha = extract_exact_alpha(arr)

    rgba_full = np.dstack([arr, full_alpha])
    tile = Image.fromarray(rgba_full, mode="RGBA").crop((x0, y0, x1 + 1, y1 + 1))

    S = 1024
    pad = 34  # 饱满占满 93.4% 画幅，同时留出底部柔和环境投影
    inner = S - pad * 2
    tile = tile.resize((inner, inner), Image.LANCZOS)

    # 适度提亮色彩饱和度与金属对比度（仅作用于 RGB，不动 Alpha）
    r, g, b, a = tile.split()
    rgb = Image.merge("RGB", (r, g, b))
    rgb = ImageEnhance.Color(rgb).enhance(1.10)
    rgb = ImageEnhance.Contrast(rgb).enhance(1.05)
    tile = Image.merge("RGBA", (*rgb.split(), a))

    body = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    body.paste(tile, (pad, pad))

    # 柔和立体环境投影
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    body_alpha = body.split()[3]
    sh_alpha = body_alpha.transform((S, S), Image.AFFINE, (1, 0, 0, 0, 1, -14)).filter(ImageFilter.GaussianBlur(18))
    sh_arr = (np.array(sh_alpha, dtype=np.float32) * 0.52).astype(np.uint8)
    shadow = Image.new("RGBA", (S, S), (5, 12, 26, 0))
    shadow.putalpha(Image.fromarray(sh_arr, mode="L"))
    canvas.alpha_composite(shadow)
    canvas.alpha_composite(body)

    canvas.resize((256, 256), Image.LANCZOS).save(HERE / "icon.png")
    canvas.resize((96, 96), Image.LANCZOS).save(HERE / "icon_96.png")

    # Pillow 保存 ICO 时从高分辨率源图自动缩放各帧；我们先对源图做微锐化保证小图标更清脆
    r, g, b, a = canvas.split()
    sharp_rgb = Image.merge("RGB", (r, g, b)).filter(ImageFilter.UnsharpMask(radius=2.2, percent=70, threshold=3))
    ico_master = Image.merge("RGBA", (*sharp_rgb.split(), a))
    ico_master.save(
        HERE / "icon.ico",
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print(f"bbox={(x0, y0, x1, y1)} -> icon.ico, icon.png, icon_96.png ready")


if __name__ == "__main__":
    make()
