#!/usr/bin/env python3
"""
BI Antivirus Enterprise — Universal Android Installation Engine
Black Intel Cyber Defense Platform — Multi-Platform Endpoint Security

Provides automated device detection, authorization diagnostics, hardware inspection,
and safe non-destructive installation across all Android manufacturers (Samsung,
Google Pixel, OnePlus, Xiaomi/Redmi/POCO, vivo/iQOO, OPPO, realme, Motorola, Nothing).
"""

import os
import sys
import time
import shutil
import argparse
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
APK_PATH = PROJECT_ROOT / "build" / "staging_android" / "BI_Antivirus_Enterprise_v1.1.0.apk"
if not APK_PATH.exists():
    # Fallback to direct build output
    APK_PATH = PROJECT_ROOT / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"

PACKAGE_NAME = "com.biantivirus.security"
MAIN_ACTIVITY = "com.biantivirus.security.ui.MainActivity"

def find_adb() -> str:
    """Detect ADB executable in PATH or standard Android SDK directories."""
    # 1. Check system PATH
    adb_path = shutil.which("adb")
    if adb_path:
        return adb_path

    # 2. Check standard development locations on Windows
    candidate_paths = [
        r"D:\Android\Sdk\platform-tools\adb.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expandvars(r"%ProgramFiles%\Android\platform-tools\adb.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Android\platform-tools\adb.exe"),
        r"C:\Android\platform-tools\adb.exe",
        r"D:\platform-tools\adb.exe",
    ]
    for cp in candidate_paths:
        if os.path.exists(cp):
            return cp

    return ""

def run_cmd(cmd_list: list) -> tuple:
    """Run command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=25)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -2, "", str(e)

def print_header():
    print("=" * 76)
    print("  BLACK INTEL CYBER DEFENSE PLATFORM — UNIVERSAL ANDROID INSTALLER")
    print("  Product: BI Antivirus Enterprise v1.1.0 (Target: Android API 26-34+)")
    print("  Package: com.biantivirus.security")
    print("=" * 76)
    print()

def diagnose_usb_pnp():
    """Query Windows PnP to check if any phone is physically plugged into USB."""
    ps_cmd = "Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName -match 'vivo|iQOO|Android|ADB|Phone|Pixel|Samsung|Xiaomi|OnePlus|OPPO|Realme' -or $_.Class -match 'Android|USB|WPD' } | Select-Object FriendlyName, InstanceId"
    ret, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    if ret == 0 and out:
        lines = [l.strip() for l in out.splitlines() if l.strip() and not l.startswith("FriendlyName") and not l.startswith("------------")]
        return lines
    return []

def parse_battery_level(dumpsys_output: str) -> str:
    """Parse battery level percentage from dumpsys battery output."""
    for line in dumpsys_output.splitlines():
        if "level:" in line.lower():
            parts = line.split(":")
            if len(parts) > 1:
                return parts[1].strip() + "%"
    return "Unknown"

def main():
    parser = argparse.ArgumentParser(description="BI Antivirus Universal Android Installer")
    parser.add_argument("--check-only", action="store_true", help="Audit ADB and device presence without installing")
    parser.add_argument("--non-interactive", action="store_true", help="Run without interactive confirmation prompts")
    parser.add_argument("--device", type=str, default="", help="Explicit ADB device serial/identifier")
    args = parser.parse_args()

    print_header()

    adb = find_adb()
    if not adb:
        print("[!] ADB (Android Debug Bridge) was NOT detected on this system.")
        print("    To install ADB automatically, run in PowerShell:")
        print("      winget install Google.PlatformTools")
        print("    Or download Android SDK Platform-Tools from Google:")
        print("      https://developer.android.com/studio/releases/platform-tools")
        print()
        if not args.non_interactive and not args.check_only:
            input("Press Enter to exit...")
        return 1

    print(f"[*] Detected ADB Toolchain: {adb}")

    if not APK_PATH.exists():
        print(f"[!] Error: Release APK not found at: {APK_PATH}")
        print("    Please compile the release APK first (gradle assembleRelease).")
        if not args.non_interactive and not args.check_only:
            input("Press Enter to exit...")
        return 1

    apk_size_mb = APK_PATH.stat().st_size / (1024 * 1024)
    print(f"[*] Target APK: {APK_PATH.name} ({apk_size_mb:.2f} MB)")
    print()

    # Query connected devices
    print("[*] Querying connected Android devices...")
    ret, out, err = run_cmd([adb, "devices", "-l"])
    
    device_lines = []
    if ret == 0:
        lines = out.splitlines()
        for l in lines[1:]: # Skip 'List of devices attached'
            if l.strip():
                device_lines.append(l.strip())

    if not device_lines:
        print("\n[-] NO ANDROID DEVICE DETECTED VIA ADB.")
        print("-" * 76)
        print("DIAGNOSTIC GUIDANCE:")
        pnp_devices = diagnose_usb_pnp()
        if pnp_devices:
            print("  Windows detected the following device presence:")
            for d in pnp_devices:
                print(f"    • {d}")
            print()

        print("To connect your Android phone or tablet for 1-click installation:")
        print("  1. Connect your phone to your PC using a USB DATA cable (not charge-only).")
        print("  2. In your phone's notification shade, tap USB Notification -> Select 'File Transfer'.")
        print("  3. Enable Developer Options:")
        print("     • Settings -> About Phone -> Tap 'Build Number' 7 times until Developer is unlocked.")
        print("  4. Enable USB Debugging:")
        print("     • Settings -> System / Developer Options -> Toggle 'USB Debugging' ON.")
        print("  5. Authorize Connection:")
        print("     • When the phone prompts 'Allow USB debugging?', check 'Always allow' and tap 'Allow'.")
        print("-" * 76)
        print()
        print("ALTERNATIVE INSTALLATION OPTIONS:")
        print("  • Wireless / Local Network QR Transfer: Run 'START_QR_INSTALLATION.bat'")
        print("  • Manual Installation: Copy APK directly to phone and tap in File Manager.")
        print("    Full Bilingual Guide: D:\\bit defender\\docs\\UNIVERSAL_ANDROID_INSTALLATION_GUIDE.md")
        print()
        if args.check_only:
            return 0
        if not args.non_interactive:
            input("Press Enter to exit...")
        return 2

    # Select target device
    selected_device_line = device_lines[0]
    if args.device:
        matching = [l for l in device_lines if l.startswith(args.device)]
        if matching:
            selected_device_line = matching[0]
        else:
            print(f"[!] Warning: Specified device '{args.device}' not found. Available devices:")
            for l in device_lines:
                print(f"    • {l}")
            return 1
    elif len(device_lines) > 1:
        print(f"[*] Multiple devices detected ({len(device_lines)}):")
        for idx, l in enumerate(device_lines):
            print(f"    [{idx + 1}] {l}")
        if not args.non_interactive and not args.check_only:
            choice = input(f"Select device index [1-{len(device_lines)}] (default 1): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(device_lines):
                selected_device_line = device_lines[int(choice) - 1]
            else:
                selected_device_line = device_lines[0]
        else:
            selected_device_line = device_lines[0]

    dev_parts = selected_device_line.split()
    dev_id = dev_parts[0]
    dev_status = dev_parts[1] if len(dev_parts) > 1 else "unknown"

    print(f"[*] Selected Target Device: {dev_id} (Status: {dev_status})")

    if args.check_only:
        print(f"[+] Device query check completed: {dev_id} is {dev_status}")
        return 0

    if dev_status == "unauthorized":
        print("\n[!] DEVICE STATUS: UNAUTHORIZED (RSA Key Approval Pending)")
        print("-" * 76)
        print("ACTION REQUIRED ON YOUR PHONE SCREEN:")
        print("  1. Unlock your phone now.")
        print("  2. A prompt titled 'Allow USB debugging?' should be visible.")
        print("  3. Check the box: [x] 'Always allow from this computer'.")
        print("  4. Tap 'ALLOW'.")
        print("-" * 76)
        print()
        if not args.non_interactive:
            input("Once approved on your phone, press Enter to re-check...")
            return main()
        return 2

    if dev_status == "offline":
        print("\n[!] DEVICE STATUS: OFFLINE")
        print("    Please unplug and re-plug your USB cable or restart USB debugging.")
        if not args.non_interactive:
            input("Press Enter to exit...")
        return 3

    if dev_status == "device":
        # Authorized! Query device details
        _, mfg, _ = run_cmd([adb, "-s", dev_id, "shell", "getprop", "ro.product.manufacturer"])
        _, model, _ = run_cmd([adb, "-s", dev_id, "shell", "getprop", "ro.product.model"])
        _, os_ver, _ = run_cmd([adb, "-s", dev_id, "shell", "getprop", "ro.build.version.release"])
        _, sdk_ver, _ = run_cmd([adb, "-s", dev_id, "shell", "getprop", "ro.build.version.sdk"])
        _, abi, _ = run_cmd([adb, "-s", dev_id, "shell", "getprop", "ro.product.cpu.abi"])
        _, batt_out, _ = run_cmd([adb, "-s", dev_id, "shell", "dumpsys", "battery"])
        battery_level = parse_battery_level(batt_out)

        print("-" * 76)
        print(f"  TARGET DEVICE DETAILS:")
        print(f"  • Manufacturer:      {mfg}")
        print(f"  • Model:             {model}")
        print(f"  • Android OS:        Android {os_ver} (API {sdk_ver})")
        print(f"  • Architecture:      {abi}")
        print(f"  • Battery Level:     {battery_level}")
        print("-" * 76)

        # Check existing installation
        _, pkg_list, _ = run_cmd([adb, "-s", dev_id, "shell", "pm", "list", "packages", PACKAGE_NAME])
        if PACKAGE_NAME in pkg_list:
            _, installed_ver, _ = run_cmd([adb, "-s", dev_id, "shell", "dumpsys", "package", PACKAGE_NAME])
            ver_name = "installed"
            for line in installed_ver.splitlines():
                if "versionName=" in line:
                    ver_name = line.strip()
                    break
            print(f"[*] Existing Installation Detected: {ver_name}")
            print("[*] Safe non-destructive upgrade mode enabled (-r flag preserves all local settings & quarantine data).")
        else:
            print("[*] Performing fresh production installation.")

        print()
        if not args.non_interactive:
            confirm = input(f"Install BI Antivirus Enterprise v1.1.0 on {mfg} {model}? [Y/n]: ").strip().lower()
            if confirm and confirm != 'y':
                print("Installation cancelled by user.")
                return 0

        print("\n[*] Transferring and installing APK on device...")
        ret, out, err = run_cmd([adb, "-s", dev_id, "install", "-r", str(APK_PATH)])
        if ret == 0 and "Success" in out:
            print("[+] INSTALLATION SUCCESSFUL!")
            print(f"    Package '{PACKAGE_NAME}' successfully deployed.")

            if not args.non_interactive:
                launch = input("\nLaunch BI Antivirus Enterprise on device now? [Y/n]: ").strip().lower()
                if not launch or launch == 'y':
                    print("[*] Launching main activity...")
                    run_cmd([adb, "-s", dev_id, "shell", "am", "start", "-n", f"{PACKAGE_NAME}/{MAIN_ACTIVITY}"])
                    print("[+] Application launched on device screen.")
            else:
                run_cmd([adb, "-s", dev_id, "shell", "am", "start", "-n", f"{PACKAGE_NAME}/{MAIN_ACTIVITY}"])
            
            print("\n[+] Setup complete. BI Antivirus Enterprise is active and protecting your device.")
            if not args.non_interactive:
                input("Press Enter to close...")
            return 0
        else:
            print(f"[-] Installation failed: {out} {err}")
            if not args.non_interactive:
                input("Press Enter to close...")
            return 4

    print(f"[-] Unexpected device status: {dev_status}")
    if not args.non_interactive:
        input("Press Enter to close...")
    return 5

if __name__ == "__main__":
    sys.exit(main())
