import os, sys, zipfile, hashlib
from pathlib import Path

root = Path(r"D:\bit defender")
out_dir = root / "build" / "staging_portable"
out_dir.mkdir(parents=True, exist_ok=True)
zip_path = out_dir / "BI_Antivirus_Enterprise_v1.1.0_Portable.zip"

include_roots = [
    "bi_antivirus",
    "docs",
    "shared",
    "config",
]

include_files = [
    "main.py",
    "Launch_BIAntivirus.bat",
    "Launch_BIAntivirus.vbs",
    "run_gui.bat",
    "run_demo.bat",
    "requirements.txt",
    "README.md",
    "installer_script.iss",
    "setup_windows.bat",
    "uninstall_windows.bat",
]

data_files = [
    "data/settings.json",
    "data/signatures.db",
]

excluded_patterns = [
    "__pycache__", ".pyc", ".git", ".log", "biantivirus-release.jks",
    "secure_credentials_vault", "test_vault", "vault"
]

print(f"Creating Portable Zip: {zip_path}")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for f in include_files:
        src = root / f
        if src.exists():
            zf.write(src, arcname=f)
            
    for f in data_files:
        src = root / f
        if src.exists():
            zf.write(src, arcname=f)
            
    for d in include_roots:
        src_dir = root / d
        if src_dir.exists():
            for p in src_dir.rglob("*"):
                if p.is_file():
                    # check exclusion
                    if any(ex in str(p) for ex in excluded_patterns):
                        continue
                    arcname = p.relative_to(root)
                    zf.write(p, arcname=str(arcname))

# Compute sha256
h = hashlib.sha256(zip_path.read_bytes()).hexdigest()
size = zip_path.stat().st_size
print(f"Portable Zip Created Successfully: {zip_path}")
print(f"Size: {size:,} bytes | SHA-256: {h}")
