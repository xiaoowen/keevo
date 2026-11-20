#!/usr/bin/env python3
"""应用图标（设计稿"品牌 · 应用图标"，方案 A · 盾与钥匙孔）。

由同一份几何生成：
  design/icons/app-icon.svg                     图标源文件（1024 × 1024）
  apps/macos/Resources/AppIcon.icns             macOS 应用图标（16–1024 px，含 @2x）
  apps/browser-extension/static/icons/*.png     扩展图标（16、32、48、128 px）

渲染用无头 Chrome（矢量直接按每个尺寸渲染，不缩放位图），打包用系统的 iconutil。只在图标改变时运行，
产物提交到仓库；打包与构建不依赖 Chrome。

用法：python3 -I design/build_icons.py        （Chrome 不在默认位置时用 KEEVO_CHROME 指定）
"""

from __future__ import annotations

import math
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SVG_OUT = ROOT / "design/icons/app-icon.svg"
ICNS_OUT = ROOT / "apps/macos/Resources/AppIcon.icns"
EXT_DIR = ROOT / "apps/browser-extension/static/icons"
CHROME = os.environ.get("KEEVO_CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

# 品牌色（design/tokens/base.json 的 teal）
TEAL_500, TEAL_600, TEAL_700 = "#1E9C8A", "#127F71", "#0F665B"

# 与 Keevo 标志相同的盾形（20 × 20 视图框；apps/browser-extension/src/brand.ts 的 SHIELD_PATH）
SHIELD = "M10 2.6 4.4 4.8v4.4c0 3.6 2.4 6.6 5.6 7.8 3.2-1.2 5.6-4.2 5.6-7.8V4.8L10 2.6Z"


def squircle(x: float = 100, y: float = 100, w: float = 824, h: float = 824, n: float = 5.0, steps: int = 180) -> str:
    """macOS 图标的连续曲率圆角方块（超椭圆近似）：1024 画布中居中的 824 × 824。"""
    cx, cy, a, b = x + w / 2, y + h / 2, w / 2, h / 2
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        c, s = math.cos(t), math.sin(t)
        pts.append(f"{cx + a * math.copysign(abs(c) ** (2 / n), c):.1f},{cy + b * math.copysign(abs(s) ** (2 / n), s):.1f}")
    return "M" + " L".join(pts) + " Z"


def app_icon_svg() -> str:
    sq = squircle()
    scale = 38.0
    tx, ty = 512 - 10 * scale, 512 - 9.8 * scale + 6
    # 渐变一律按画布坐标计算：竖直或水平的图形包围盒宽度为 0 时，按包围盒计算的渐变会失效
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <title>Keevo</title>
  <defs>
    <linearGradient id="bg" gradientUnits="userSpaceOnUse" x1="0" y1="100" x2="0" y2="924">
      <stop offset="0" stop-color="#2BB09C"/>
      <stop offset="0.55" stop-color="{TEAL_600}"/>
      <stop offset="1" stop-color="{TEAL_700}"/>
    </linearGradient>
    <linearGradient id="highlight" gradientUnits="userSpaceOnUse" x1="0" y1="100" x2="0" y2="924">
      <stop offset="0" stop-color="#FFFFFF" stop-opacity="0.22"/>
      <stop offset="0.5" stop-color="#FFFFFF" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="shield" gradientUnits="userSpaceOnUse" x1="0" y1="2.6" x2="0" y2="17">
      <stop offset="0" stop-color="#FFFFFF"/>
      <stop offset="1" stop-color="#D9F2EC"/>
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="12" stdDeviation="14" flood-color="#000000" flood-opacity="0.28"/>
    </filter>
    <clipPath id="tile"><path d="{sq}"/></clipPath>
  </defs>
  <path d="{sq}" fill="url(#bg)" filter="url(#shadow)"/>
  <g clip-path="url(#tile)">
    <path d="{SHIELD}" transform="translate({tx:.1f},{ty:.1f}) scale({scale})" fill="url(#shield)"/>
    <circle cx="512" cy="478" r="54" fill="{TEAL_700}"/>
    <path d="M486 506 L538 506 L556 640 Q558 652 546 652 L478 652 Q466 652 468 640 Z" fill="{TEAL_700}"/>
    <rect x="100" y="100" width="824" height="420" fill="url(#highlight)"/>
  </g>
  <path d="{sq}" fill="none" stroke="#FFFFFF" stroke-opacity="0.35" stroke-width="3"/>
</svg>
'''


def render(svg: pathlib.Path, size: int, out: pathlib.Path, work: pathlib.Path) -> None:
    page = work / f"render-{size}.html"
    page.write_text(
        f'<!doctype html><html><body style="margin:0;background:transparent">'
        f'<img src="{svg.as_uri()}" width="{size}" height="{size}" style="display:block"></body></html>',
        encoding="utf-8",
    )
    subprocess.run(
        [CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--hide-scrollbars",
         f"--user-data-dir={work / 'profile'}", "--force-device-scale-factor=1",
         "--default-background-color=00000000", f"--window-size={size},{size}",
         f"--screenshot={out}", page.as_uri()],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
    )
    if not out.exists():
        raise SystemExit(f"渲染失败：{out.name}")


def main() -> int:
    if not pathlib.Path(CHROME).exists():
        print(f"找不到 Chrome：{CHROME}（用 KEEVO_CHROME 指定）", file=sys.stderr)
        return 1
    SVG_OUT.parent.mkdir(parents=True, exist_ok=True)
    SVG_OUT.write_text(app_icon_svg(), encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        iconset = work / "AppIcon.iconset"
        iconset.mkdir()
        rendered: dict[int, pathlib.Path] = {}
        for size in (16, 32, 48, 64, 128, 256, 512, 1024):
            rendered[size] = work / f"{size}.png"
            render(SVG_OUT, size, rendered[size], work)
        for base in (16, 32, 128, 256, 512):
            shutil.copy(rendered[base], iconset / f"icon_{base}x{base}.png")
            shutil.copy(rendered[base * 2], iconset / f"icon_{base}x{base}@2x.png")
        ICNS_OUT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(ICNS_OUT)], check=True)
        EXT_DIR.mkdir(parents=True, exist_ok=True)
        for size in (16, 32, 48, 128):
            shutil.copy(rendered[size], EXT_DIR / f"icon-{size}.png")
    print(f"已生成 {SVG_OUT.relative_to(ROOT)}、{ICNS_OUT.relative_to(ROOT)}、{EXT_DIR.relative_to(ROOT)}/icon-{{16,32,48,128}}.png")
    return 0


if __name__ == "__main__":
    sys.exit(main())
