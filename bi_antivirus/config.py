"""
BI Antivirus - Central Configuration Module
Defines system paths, security constants, UI color palette, and default settings.
All storage paths (databases, logs, quarantine, reports) are kept on D: drive.
"""

from pathlib import Path
import os
import json

# Base Project Path (Dynamically Resolved with D: Drive Canonical Fallback)
_ENV_ROOT = os.environ.get("BI_PROJECT_ROOT")
if _ENV_ROOT and Path(_ENV_ROOT).exists():
    PROJECT_ROOT = Path(_ENV_ROOT).resolve()
else:
    _detected = Path(__file__).resolve().parent.parent
    if (_detected / "bi_antivirus").exists():
        PROJECT_ROOT = _detected
    elif Path(r"D:\bit defender").exists():
        PROJECT_ROOT = Path(r"D:\bit defender").resolve()
    else:
        PROJECT_ROOT = _detected

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

# UI Theme - Black Intel Official Black & Gold Visual Identity
THEME = {
    # Deep Black & Charcoal/Graphite Backgrounds
    "bg_darkest": "#0a0a0c",       # Primary background: Deep Black
    "bg_dark": "#121318",          # Secondary background: Charcoal / Dark Graphite
    "bg_panel": "#181a22",         # Card background: Charcoal Graphite
    "bg_card": "#181a22",          # Reusable Card alias
    "bg_panel_hover": "#222530",   # Card hover state
    "bg_input": "#0f1015",         # Form fields & tables background
    
    # Borders & Dividers
    "border": "#272a36",           # Subtle structural border
    "border_highlight": "#d4af37", # Gold highlight border
    "border_gold": "#c5a059",      # Subtle gold border for cards
    
    # Accents - Black Intel Official Gold Palette
    "accent_primary": "#d4af37",   # Primary accent: Premium Metallic Gold
    "accent_secondary": "#aa8c2c", # Secondary accent: Muted Antique Gold
    "accent_hover": "#f3cf65",     # Glowing radiant gold for active/hover states
    "accent_gold": "#d4af37",      # Reusable Gold alias
    "accent_gold_muted": "#8c701e",# Deep muted gold
    "accent_cyan": "#38bdf8",      # Subtle sky blue for diagnostic telemetry
    
    # Accessible Status Colors
    "status_safe": "#10b981",      # Accessible Emerald Green (Safe / Clean)
    "status_warning": "#f59e0b",   # Warm Amber (Warning / Attention)
    "status_threat": "#ef4444",    # Threat Crimson (Threat / Critical)
    "status_critical": "#ef4444",  # Critical Alert Crimson
    "status_info": "#d4af37",      # Info Gold / Status Info
    
    # Typography
    "text_primary": "#ffffff",     # Primary text: Pure White
    "text_secondary": "#9ca3af",   # Secondary text: Soft Grey
    "text_muted": "#6b7280",       # Muted text: Deep Slate Grey
    "text_gold": "#d4af37",        # Gold highlight text
    
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
