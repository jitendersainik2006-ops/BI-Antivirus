import os
import subprocess
import urllib.request
import urllib.parse
import json
import ssl

def get_github_token():
    p = subprocess.Popen(
        ['git', 'credential', 'fill'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    out, _ = p.communicate(input="protocol=https\nhost=github.com\n\n")
    for line in out.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    return None

token = get_github_token()
if not token:
    raise RuntimeError("Failed to retrieve GitHub token")

release_id = "459122502"
repo = "jitendersainik2006-ops/BI-Antivirus"

assets = [
    {
        "name": "BI_Antivirus_Enterprise_v1.0.0_Setup.exe",
        "path": r"D:\bit defender\releases\Windows\Installer\BI_Antivirus_Enterprise_v1.0.0_Setup.exe",
        "content_type": "application/vnd.microsoft.portable-executable"
    },
    {
        "name": "BI_Antivirus_Enterprise_v1.0.0_Portable.zip",
        "path": r"D:\bit defender\releases\Windows\BI_Antivirus_Enterprise_v1.0.0_Portable.zip",
        "content_type": "application/zip"
    },
    {
        "name": "BI_Antivirus_Enterprise_v1.0.0.apk",
        "path": r"D:\bit defender\releases\Android\BI_Antivirus_Enterprise_v1.0.0.apk",
        "content_type": "application/vnd.android.package-archive"
    },
    {
        "name": "SHA256_MANIFEST.txt",
        "path": r"D:\bit defender\releases\Checksums\SHA256_MANIFEST.txt",
        "content_type": "text/plain"
    }
]

for asset in assets:
    name = asset["name"]
    path = asset["path"]
    ct = asset["content_type"]
    size = os.path.getsize(path)
    print(f"\nUploading {name} ({size:,} bytes)...")
    
    url = f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets?name={urllib.parse.quote(name)}"
    
    with open(path, "rb") as f:
        data = f.read()
    
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", ct)
    req.add_header("User-Agent", "BIAntivirus-Release-Agent")
    
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            resp_body = resp.read().decode('utf-8')
            res = json.loads(resp_body)
            print(f"SUCCESS: {name} uploaded! Asset ID: {res.get('id')}, Size: {res.get('size'):,} bytes")
            print(f"Download URL: {res.get('browser_download_url')}")
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8', errors='ignore')
        print(f"FAILED to upload {name}: HTTP {e.code} - {err}")
        raise

print("\nAll 4 distribution assets successfully uploaded to GitHub Release!")
