"""
BI Antivirus - Central Configuration Module
Defines system paths, security constants, UI color palette, and default settings.
All storage paths (databases, logs, quarantine, reports) are kept on D: drive.
"""

from pathlib import Path
import os
import json

# Base Project Path on D: Drive (Canonical Workspace Root)
PROJECT_ROOT = Path(r"D:\bit defender").resolve()
if not PROJECT_ROOT.exists():
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Dedicated Storage Directories on D: Drive
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
QUARANTINE_VAULT_DIR = QUARANTINE_DIR / "vault"
REPORTS_DIR = PROJECT_ROOT / "reports"
TEMPLATES_DIR = PROJECT_ROOT / "integrations" / "templates"
SCRATCH_DIR = DATA_DIR / "crypto_test_scratch"
CONFIG_FILE = DATA_DIR / "settings.json"

# Database Paths
SIGNATURES_DB_PATH = DATA_DIR / "signatures.db"
HISTORY_DB_PATH = DATA_DIR / "history.db"
QUARANTINE_DB_PATH = DATA_DIR / "quarantine.db"
FLEET_DB_PATH = DATA_DIR / "fleet.db"
EVENT_LOG_PATH = LOGS_DIR / "bi_security.log"
WEBHOOK_LOG_PATH = LOGS_DIR / "webhook_events.log"
API_KEY_FILE = DATA_DIR / "api_key.txt"
VAULT_KEY_PATH = DATA_DIR / "vault_master.dpapi"

# Ensure all directories exist on D: drive
for _directory in (DATA_DIR, LOGS_DIR, QUARANTINE_DIR, QUARANTINE_VAULT_DIR, REPORTS_DIR, TEMPLATES_DIR, SCRATCH_DIR):
    _directory.mkdir(parents=True, exist_ok=True)

# Application Meta
APP_NAME = "BI Antivirus"
APP_SUBTITLE = "Black Intel Cyber Defense Platform"
APP_VERSION = "1.1.0-PRO"
ENGINE_VERSION = "2026.11-RELEASE"
SIGNATURE_DB_VERSION = "2026.11.02.1"

# Threat Severity Constants
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_CLEAN = "CLEAN"

# Scan Types
SCAN_TYPE_QUICK = "QUICK"
SCAN_TYPE_FULL = "FULL"
SCAN_TYPE_CUSTOM = "CUSTOM"
SCAN_TYPE_REALTIME = "REALTIME"

# Threat Families
FAMILY_TROJAN = "Trojan"
FAMILY_RANSOMWARE = "Ransomware"
FAMILY_WORM = "Worm"
FAMILY_SPYWARE = "Spyware"
FAMILY_ADWARE = "Adware"
FAMILY_DROPPER = "Dropper"
FAMILY_TEST_VIRUS = "TestVirus"
FAMILY_HEURISTIC = "SuspiciousHeuristic"

# UI Theme - Bitdefender-inspired Modern Cyber Dark Palette
THEME = {
    "bg_darkest": "#090d12",       # Background deep space
    "bg_dark": "#0f1621",          # Sidebar & card deep navy/charcoal
    "bg_panel": "#141e2e",         # Card background
    "bg_panel_hover": "#1c2a3f",   # Interactive hover
    "bg_input": "#0c131d",         # Form fields & tables
    "border": "#21324a",           # Borders and dividers
    "border_highlight": "#355075", # Highlight borders
    
    # Accent & Status
    "accent_primary": "#00d285",   # Clean Emerald - Bitdefender-style safe green
    "accent_secondary": "#00b4d8", # Secondary Cyber Cyan
    "accent_cyan": "#00b4d8",      # Cyber cyan
    "accent_hover": "#00f59b",     # Glowing emerald
    
    # Severity Colors
    "status_safe": "#00d285",      # Emerald Green
    "status_warning": "#ffb020",   # Warm Amber
    "status_threat": "#ff385c",    # Threat Crimson
    "status_critical": "#ff385c",  # Critical Alert Crimson
    "status_info": "#00b4d8",      # Info Cyan
    
    # Typography
    "text_primary": "#f0f4f8",     # Bright foreground
    "text_secondary": "#94a3b8",   # Subtle muted silver
    "text_muted": "#5c6b82",       # Dim captions
    
    # Fonts
    "font_family": "Segoe UI",
    "font_mono": "Consolas",
}

# Default System Configuration
DEFAULT_SETTINGS = {
    "realtime_protection_enabled": True,
    "web_protection_enabled": True,
    "heuristic_analysis_enabled": True,
    "entropy_threshold": 7.2,
    "max_file_size_scan_mb": 150,
    "scan_archive_contents": True,
    "auto_quarantine_threats": False,  # Safety rule: require explicit approval
    "exclusions_paths": [],
    "exclusions_extensions": [".iso", ".vmdk", ".vdi"],
    "quarantine_retention_days": 60,
    
    # Local API & Automation Settings
    "api_enabled": True,
    "api_host": "127.0.0.1",
    "api_port": 8765,
    "webhook_enabled": False,  # Disabled by default until user configures/approves
    "webhook_url": "http://127.0.0.1:5678/webhook/bi-threat-alert",
    
    # Voice Alert Settings
    "voice_alerts_enabled": True,
    "voice_engine": "SAPI",    # Options: "SAPI" (Windows Native), "VoiceStudio"
    "voice_volume": 85,
    "voice_muted": False,
    "voice_studio_url": "http://127.0.0.1:8000/v1/audio/speech",
    
    # Notification & Integration Approval
    "integration_approved": False,
    "telegram_configured": False,
    "email_configured": False,
    "scheduled_scans": [
        {
            "id": "sched_daily_quick",
            "name": "Daily Quick Scan",
            "type": "QUICK",
            "frequency": "daily",
            "time": "12:00",
            "enabled": True,
            "last_run": None,
        }
    ],
    "monitored_directories": [
        os.path.expanduser(r"~\Downloads"),
        os.path.expanduser(r"~\Desktop"),
        os.environ.get("TEMP", r"C:\Windows\Temp"),
    ],
}


def load_settings() -> dict:
    """Load settings from JSON file or create with defaults."""
    if not CONFIG_FILE.exists():
        save_settings(DEFAULT_SETTINGS)
        return dict(DEFAULT_SETTINGS)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure any missing default keys are preserved
            for k, v in DEFAULT_SETTINGS.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> bool:
    """Save configuration safely to JSON."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
        return True
    except Exception:
        return False
