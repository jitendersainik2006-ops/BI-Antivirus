# BI Antivirus — Configuration Guide

This guide details all configuration options for BI Antivirus without exposing private secrets, tokens, or credentials.

---

## 1. Primary Configuration Files

All configuration files reside strictly within `D:\bit defender`:

| File | Purpose | Security Handling |
| :--- | :--- | :--- |
| `data/settings.json` | Core engine settings and toggle states | Auto-created on startup; user editable |
| `config/n8n/n8n.env.example` | Template for n8n Community Edition environment variables | Public template (no real keys) |
| `data/api_key.txt` | Local REST API authentication token (64-character hex) | Excluded by `.gitignore`; NTFS permissions restricted |
| `data/vault_master.dpapi` | DPAPI-wrapped 256-bit vault master key | Excluded by `.gitignore`; Windows DPAPI machine-encrypted |

---

## 2. Engine Settings Schema (`data/settings.json`)

The following settings control runtime behavior:

```json
{
  "realtime_protection_enabled": true,
  "web_protection_enabled": true,
  "heuristic_analysis_enabled": true,
  "entropy_threshold": 7.2,
  "max_file_size_scan_mb": 150,
  "scan_archive_contents": true,
  "auto_quarantine_threats": false,
  "exclusions_paths": [],
  "exclusions_extensions": [".iso", ".vmdk", ".vdi"],
  "quarantine_retention_days": 60,
  "monitored_directories": [
    "C:\\Users\\<User>\\Downloads",
    "C:\\Users\\<User>\\Desktop",
    "C:\\Users\\<User>\\AppData\\Local\\Temp"
  ],
  "api_enabled": true,
  "api_host": "127.0.0.1",
  "api_port": 8765,
  "webhook_enabled": true,
  "webhook_url": "http://127.0.0.1:5678/webhook/bi-threat-alert",
  "voice_alerts_enabled": true,
  "voice_engine": "SAPI",
  "voice_volume": 85,
  "voice_muted": false
}
```

### Key Parameter Explanations:
- `auto_quarantine_threats`: Set to `false` by default. Requires explicit user confirmation in the UI before any file is moved into the quarantine vault.
- `entropy_threshold`: Shannon entropy limit (0.0 to 8.0). Binaries with entropy above `7.2` are flagged for suspicious packing or obfuscation.
- `max_file_size_scan_mb`: Skips scanning files larger than 150 MB during fast scans to prevent CPU thrashing.
- `exclusions_paths`: Array of directory paths exempt from real-time monitoring and on-demand scans.

---

## 3. Network & Service Binding Safety

All network listeners are strictly bound to IPv4 Loopback (`127.0.0.1`). 
Under no circumstances should any service configuration be modified to bind to `0.0.0.0` or external network adapters.
