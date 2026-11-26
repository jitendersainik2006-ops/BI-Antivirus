"""
BI Antivirus - UI Screenshot Capture Utility
Captures high-resolution screenshots of all 7 primary application views:
1. Dashboard (Overview)
2. Scan Center
3. Quarantine Vault
4. Threat History
5. Protection Hub
6. Settings
7. About Screen

Converts raw Win32 bitmaps to PNG format for visual review and documentation.
"""

import os
import sys
import time
import ctypes
from ctypes import wintypes
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.ui.dashboard import AntivirusDashboard


class RECT(ctypes.Structure):
    _fields_ = [
        ('left', wintypes.LONG),
        ('top', wintypes.LONG),
        ('right', wintypes.LONG),
        ('bottom', wintypes.LONG),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ('biSize', wintypes.DWORD),
        ('biWidth', wintypes.LONG),
        ('biHeight', wintypes.LONG),
        ('biPlanes', wintypes.WORD),
        ('biBitCount', wintypes.WORD),
        ('biCompression', wintypes.DWORD),
        ('biSizeImage', wintypes.DWORD),
        ('biXPelsPerMeter', wintypes.LONG),
        ('biYPelsPerMeter', wintypes.LONG),
        ('biClrUsed', wintypes.DWORD),
        ('biClrImportant', wintypes.DWORD),
    ]


def capture_window_to_bmp(app: AntivirusDashboard, out_bmp_path: Path) -> bool:
    """Capture the live Tkinter dashboard window into a 32-bit BMP file using Win32 API."""
    app.update_idletasks()
    app.update()

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    child_hwnd = app.winfo_id()
    top_hwnd = user32.GetAncestor(child_hwnd, 2)  # GA_ROOT = 2
    if not top_hwnd:
        top_hwnd = child_hwnd

    rect = RECT()
    user32.GetWindowRect(top_hwnd, ctypes.byref(rect))
    width = max(rect.right - rect.left, 100)
    height = max(rect.bottom - rect.top, 100)

    hdc_window = user32.GetDC(top_hwnd)
    if not hdc_window:
        return False

    hdc_mem = gdi32.CreateCompatibleDC(hdc_window)
    hbm = gdi32.CreateCompatibleBitmap(hdc_window, width, height)
    gdi32.SelectObject(hdc_mem, hbm)

    # 2 = PW_RENDERFULLCONTENT
    user32.PrintWindow(top_hwnd, hdc_mem, 2)

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = width
    bmi.biHeight = -height  # Top-down DIB
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = 0

    buf_size = width * height * 4
    buf = ctypes.create_string_buffer(buf_size)
    gdi32.GetDIBits(hdc_mem, hbm, 0, height, buf, ctypes.byref(bmi), 0)

    offset = 14 + ctypes.sizeof(BITMAPINFOHEADER)
    file_size = offset + buf_size
    bmp_header = b'BM' + file_size.to_bytes(4, 'little') + b'\x00\x00\x00\x00' + offset.to_bytes(4, 'little')

    out_bmp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_bmp_path, 'wb') as f:
        f.write(bmp_header)
        f.write(bytes(bmi))
        f.write(buf)

    gdi32.DeleteObject(hbm)
    gdi32.DeleteDC(hdc_mem)
    user32.ReleaseDC(top_hwnd, hdc_window)
    return True


def convert_bmps_to_png(screenshot_dir: Path) -> None:
    """Use PowerShell .NET System.Drawing to convert BMP files to optimized PNGs."""
    import subprocess
    ps_cmd = f"""
    Add-Type -AssemblyName System.Drawing
    $files = Get-ChildItem -Path '{screenshot_dir}' -Filter '*.bmp'
    foreach ($f in $files) {{
        $pngPath = [System.IO.Path]::ChangeExtension($f.FullName, '.png')
        $img = [System.Drawing.Bitmap]::FromFile($f.FullName)
        $img.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $img.Dispose()
        Remove-Item -Force $f.FullName
        Write-Host "Converted: $($f.Name) -> $([System.IO.Path]::GetFileName($pngPath))"
    }}
    """
    subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], check=True)


def main():
    screenshot_dir = PROJECT_ROOT / "docs" / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    print("Initializing BI Antivirus Engine...")
    engine = AntivirusEngine()
    engine.initialize()

    print("Launching Desktop Dashboard...")
    app = AntivirusDashboard(engine=engine)
    app.geometry("1100x740")
    app.update_idletasks()
    app.update()

    views = [
        ("dashboard", "01_dashboard"),
        ("scan", "02_scan_center"),
        ("quarantine", "03_quarantine_vault"),
        ("history", "04_threat_history"),
        ("protection", "05_protection_hub"),
        ("settings", "06_settings"),
        ("about", "07_about_screen"),
    ]

    captured = []
    for view_key, filename in views:
        print(f"Rendering view: {view_key}...")
        app.show_view(view_key)
        # Give UI short delay to render widgets completely
        time.sleep(0.3)
        app.update_idletasks()
        app.update()

        bmp_path = screenshot_dir / f"{filename}.bmp"
        success = capture_window_to_bmp(app, bmp_path)
        if success and bmp_path.exists() and bmp_path.stat().st_size > 1000:
            print(f"  Captured: {bmp_path.name} ({bmp_path.stat().st_size / 1024:.1f} KB)")
            captured.append(bmp_path)
        else:
            print(f"  FAILED to capture: {view_key}")

    print("Closing Application...")
    app.destroy()
    engine.shutdown()

    print("Converting captured BMPs to PNG format...")
    convert_bmps_to_png(screenshot_dir)

    print("\nVerified Generated Screenshots:")
    pngs = list(screenshot_dir.glob("*.png"))
    for p in sorted(pngs):
        print(f"  {p.name} - {p.stat().st_size / 1024:.1f} KB")

    print(f"\nSuccessfully generated {len(pngs)} UI screenshots in {screenshot_dir}")


if __name__ == "__main__":
    main()
