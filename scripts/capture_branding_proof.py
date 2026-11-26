import os
import sys
import time
import ctypes
from ctypes import wintypes
from pathlib import Path
from PIL import Image

PROJECT_ROOT = Path(r"D:\bit defender")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

docs_screenshots = PROJECT_ROOT / "docs" / "screenshots"
docs_screenshots.mkdir(parents=True, exist_ok=True)

artifact_screenshots = Path(r"C:\Users\jitendersaini2006\.gemini\antigravity\brain\9c8af58a-fb69-4549-b393-ed106d7a72bf\screenshots")
artifact_screenshots.mkdir(parents=True, exist_ok=True)

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32

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

def capture_window_native(hwnd: int, out_bmp_path: Path) -> bool:
    top_hwnd = user32.GetAncestor(hwnd, 2) or hwnd
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

    user32.PrintWindow(top_hwnd, hdc_mem, 2)

    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = width
    bmi.biHeight = -height
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

def convert_bmp_to_png(bmp_path: Path, png_path: Path):
    with Image.open(bmp_path) as im:
        im.save(png_path, "PNG")
    if os.path.exists(bmp_path):
        os.remove(bmp_path)

import tkinter as tk
from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.ui.dashboard import AntivirusDashboard
from bi_antivirus.ui.splash import SplashScreen
from bi_antivirus.ui.first_run_wizard import FirstRunWizard

print("--- Capturing Upgraded Branding Screenshots via GDI PrintWindow ---")

# 1. Capture Splash Screen
root = tk.Tk()
root.withdraw()
splash = SplashScreen(root, duration_ms=5000)
splash.update()
time.sleep(0.3)
bmp1 = docs_screenshots / "branding_01_splash_screen.bmp"
png1_docs = docs_screenshots / "branding_01_splash_screen.png"
png1_art = artifact_screenshots / "branding_01_splash_screen.png"
if capture_window_native(splash.winfo_id(), bmp1):
    convert_bmp_to_png(bmp1, png1_docs)
    Image.open(png1_docs).save(png1_art)
    print("Captured: branding_01_splash_screen.png")
splash.destroy()
root.destroy()

# 2. Capture Dashboard
engine = AntivirusEngine()
engine.initialize()
app = AntivirusDashboard(engine=engine)
app.update()
time.sleep(0.3)
bmp2 = docs_screenshots / "branding_02_dashboard_sidebar.bmp"
png2_docs = docs_screenshots / "branding_02_dashboard_sidebar.png"
png2_art = artifact_screenshots / "branding_02_dashboard_sidebar.png"
if capture_window_native(app.winfo_id(), bmp2):
    convert_bmp_to_png(bmp2, png2_docs)
    Image.open(png2_docs).save(png2_art)
    print("Captured: branding_02_dashboard_sidebar.png")

# 3. Capture About View
app.show_view("about")
app.update()
time.sleep(0.3)
bmp3 = docs_screenshots / "branding_03_about_screen.bmp"
png3_docs = docs_screenshots / "branding_03_about_screen.png"
png3_art = artifact_screenshots / "branding_03_about_screen.png"
if capture_window_native(app.winfo_id(), bmp3):
    convert_bmp_to_png(bmp3, png3_docs)
    Image.open(png3_docs).save(png3_art)
    print("Captured: branding_03_about_screen.png")

# 4. Capture Welcome Wizard
wiz = FirstRunWizard(app)
wiz.update()
time.sleep(0.3)
bmp4 = docs_screenshots / "branding_04_welcome_wizard.bmp"
png4_docs = docs_screenshots / "branding_04_welcome_wizard.png"
png4_art = artifact_screenshots / "branding_04_welcome_wizard.png"
if capture_window_native(wiz.winfo_id(), bmp4):
    convert_bmp_to_png(bmp4, png4_docs)
    Image.open(png4_docs).save(png4_art)
    print("Captured: branding_04_welcome_wizard.png")
wiz.destroy()

app.destroy()
print("All branding screenshots successfully captured and saved!")
