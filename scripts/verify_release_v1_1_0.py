#!/usr/bin/env python3
"""
BI Antivirus Enterprise — Verification of Public GitHub Release v1.1.0-enterprise
Black Intel Cyber Defense Platform
"""

import os
import sys
import json
import hashlib
import urllib.request
import subprocess
from pathlib import Path

REPO = "jitendersainik2006-ops/BI-Antivirus"
LOCAL_HANDOVER = Path(r"D:\bit defender\handover\v1.1.0")

def get_token() -> str:
    p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input='protocol=https\nhost=github.com\n\n')
    for line in out.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    return ""

def main():
    token = get_token()
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BIAntivirus-Release-Verifier"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    print("=" * 76)
    print("  VERIFYING GITHUB PUBLIC RELEASES: v1.0.0-enterprise & v1.1.0-enterprise")
    print("=" * 76)

    # 1. Verify v1.0.0-enterprise is unchanged
    print("\n[*] Auditing existing published v1.0.0-enterprise release...")
    req_v100 = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/tags/v1.0.0-enterprise", headers=headers)
    with urllib.request.urlopen(req_v100) as resp:
        v100_data = json.loads(resp.read().decode('utf-8'))
        print(f"  [PASS] v1.0.0 Release ID: {v100_data['id']}")
        print(f"  [PASS] v1.0.0 Release Name: {v100_data['name']}")
        print(f"  [PASS] v1.0.0 Asset Count: {len(v100_data['assets'])}")
        assert len(v100_data['assets']) == 4, "v1.0.0 assets were altered!"

    # 2. Verify v1.1.0-enterprise
    print("\n[*] Auditing new published v1.1.0-enterprise release...")
    req_v110 = urllib.request.Request(f"https://api.github.com/repos/{REPO}/releases/tags/v1.1.0-enterprise", headers=headers)
    with urllib.request.urlopen(req_v110) as resp:
        v110_data = json.loads(resp.read().decode('utf-8'))
        print(f"  [PASS] v1.1.0 Release ID: {v110_data['id']}")
        print(f"  [PASS] v1.1.0 Release Title: {v110_data['name']}")
        print(f"  [PASS] v1.1.0 Target: {v110_data['target_commitish']}")
        print(f"  [PASS] v1.1.0 Draft: {v110_data['draft']}, Prerelease: {v110_data['prerelease']}")
        print(f"  [PASS] Release Page URL: {v110_data['html_url']}")
        print(f"  [PASS] Asset Count: {len(v110_data['assets'])}")
        assert len(v110_data['assets']) == 4, f"Expected 4 assets, found {len(v110_data['assets'])}"

    expected_assets = {
        "BI_Antivirus_Enterprise_v1.1.0.apk": 2324777,
        "BI_Antivirus_Enterprise_v1.1.0_Setup.exe": 6584986,
        "BI_Antivirus_Enterprise_v1.1.0_Portable.zip": 4390578,
        "SHA256_MANIFEST_v1.1.0.txt": 926
    }

    print("\n[*] Auditing published asset dimensions and download endpoints...")
    apk_download_url = None
    for a in v110_data['assets']:
        aname = a['name']
        asize = a['size']
        adownload = a['browser_download_url']
        print(f"  • {aname} ({asize:,} bytes)")
        print(f"    URL: {adownload}")
        if aname == "BI_Antivirus_Enterprise_v1.1.0.apk":
            apk_download_url = adownload

        assert aname in expected_assets, f"Unexpected asset: {aname}"
        assert asize == expected_assets[aname], f"Size mismatch for {aname}: {asize} vs {expected_assets[aname]}"
        print(f"    [PASS] Dimension verified.")

    # 3. Download the published APK and independently recompute SHA-256
    print(f"\n[*] Downloading published APK from GitHub to verify cryptographic parity...")
    print(f"    Endpoint: {apk_download_url}")
    dl_req = urllib.request.Request(apk_download_url, headers=headers)
    with urllib.request.urlopen(dl_req, timeout=120) as dl_resp:
        dl_bytes = dl_resp.read()

    dl_size = len(dl_bytes)
    dl_hash = hashlib.sha256(dl_bytes).hexdigest().upper()
    print(f"    Downloaded Size: {dl_size:,} bytes")
    print(f"    Downloaded SHA-256: {dl_hash}")

    local_apk = LOCAL_HANDOVER / "BI_Antivirus_Enterprise_v1.1.0.apk"
    local_hash = hashlib.sha256(local_apk.read_bytes()).hexdigest().upper()
    print(f"    Local Verified SHA-256: {local_hash}")

    assert dl_hash == local_hash, f"Hash mismatch: remote {dl_hash} != local {local_hash}"
    print("\n[+] 100% CRYPTOGRAPHIC MATCH! Remote published APK is bit-for-bit identical to local verified build.")

    print("\n" + "=" * 76)
    print("  PUBLIC RELEASE VERIFICATION COMPLETE: ALL CHECKS PASSED")
    print("=" * 76)
    return 0

if __name__ == "__main__":
    sys.exit(main())
