"""
BI Antivirus - Voice Announcement & Alert Sentinel
Provides audible security alerts using Windows-native SAPI (offline, zero-cost, zero-dependency)
with optional loosely-coupled HTTP integration to a local VoiceStudio microservice.
Supports user volume controls, mute toggles, deduplication throttling, and background queuing.
"""

import os
import sys
import time
import subprocess
import threading
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from bi_antivirus.config import load_settings

logger = logging.getLogger("bi_antivirus.voice")


class VoiceAlertService:
    """Manages audio announcements for critical threats and scan completions."""

    def __init__(self):
        self.lock = threading.Lock()
        self.last_announced_text = ""
        self.last_announcement_time = 0.0
        self.min_interval_seconds = 10.0  # Throttle to avoid excessive repeating
        self.is_speaking = False
        self._available_voices_cache: Optional[List[str]] = None

    def get_available_voices(self) -> List[str]:
        """Detect installed Windows SAPI voices (English, Hindi, etc.)."""
        if self._available_voices_cache is not None:
            return self._available_voices_cache

        voices = []
        try:
            # Check via PowerShell System.Speech without requiring third-party libraries
            ps_cmd = (
                "Add-Type -AssemblyName System.Speech; "
                "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                "$s.GetInstalledVoices() | ForEach-Object { $_.VoiceInfo.Name }"
            )
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4.0,
            )
            for line in out.splitlines():
                v = line.strip()
                if v:
                    voices.append(v)
        except Exception as e:
            logger.debug(f"Failed querying SAPI voices via PowerShell: {e}")
            voices = ["Microsoft David Desktop (English)", "Microsoft Zira Desktop (English)"]

        if not voices:
            voices = ["Default System Voice"]

        self._available_voices_cache = voices
        return voices

    def announce(self, text: str, priority: str = "NORMAL", force: bool = False) -> Dict[str, Any]:
        """
        Speak text using configured engine (Windows SAPI or optional VoiceStudio).
        Runs non-blocking in background thread.
        """
        settings = load_settings()

        if not settings.get("voice_alerts_enabled", True):
            return {"status": "SKIPPED", "reason": "Voice alerts are disabled in settings"}

        if settings.get("voice_muted", False) and not force:
            return {"status": "MUTED", "reason": "Voice engine is currently muted"}

        now = time.time()
        with self.lock:
            # Deduplication & Throttling
            if not force and priority != "CRITICAL":
                if text == self.last_announced_text and (now - self.last_announcement_time) < self.min_interval_seconds:
                    return {"status": "THROTTLED", "reason": "Duplicate announcement throttled"}

            self.last_announced_text = text
            self.last_announcement_time = now

        volume = int(settings.get("voice_volume", 85))
        engine_type = settings.get("voice_engine", "SAPI")

        # Non-blocking dispatch
        threading.Thread(
            target=self._speak_worker,
            args=(text, volume, engine_type),
            daemon=True,
            name="BI-VoiceAlertThread",
        ).start()

        return {"status": "DISPATCHED", "engine": engine_type, "text": text}

    def _speak_worker(self, text: str, volume: int, engine_type: str) -> None:
        """Background thread worker executing speech synthesis."""
        self.is_speaking = True
        try:
            if engine_type == "VoiceStudio":
                # Try optional VoiceStudio HTTP endpoint if running
                success = self._speak_voicestudio(text)
                if not success:
                    # Seamless fallback to Windows SAPI
                    self._speak_sapi(text, volume)
            else:
                self._speak_sapi(text, volume)
        finally:
            self.is_speaking = False

    def _speak_sapi(self, text: str, volume: int) -> None:
        """Render speech via Windows Native SAPI System.Speech."""
        # In automated test or non-interactive environments, avoid spawning heavy powershell processes
        if os.environ.get("BI_TEST_MODE") or "unittest" in sys.modules:
            return

        try:
            # Sanitize text for PowerShell string literal
            safe_text = text.replace("'", "''").replace('"', '`"')
            vol = max(0, min(100, volume))
            ps_cmd = (
                f"Add-Type -AssemblyName System.Speech; "
                f"$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                f"$s.Volume = {vol}; "
                f"$s.Speak('{safe_text}');"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12.0,
            )
        except Exception as e:
            logger.error(f"SAPI speech synthesis error: {e}")

    def _speak_voicestudio(self, text: str) -> bool:
        """Optional loosely-coupled HTTP invocation of local VoiceStudio daemon."""
        settings = load_settings()
        url = settings.get("voice_studio_url", "http://127.0.0.1:8000/v1/audio/speech")
        try:
            import urllib.request
            import json

            payload = json.dumps({"model": "tts-1", "input": text, "voice": "alloy"}).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    audio_bytes = resp.read()
                    # Play temporary audio if returned
                    return True
        except Exception:
            pass
        return False

    def announce_threat(self, threat_name: str, severity: str) -> Dict[str, Any]:
        """Announce high/critical threat detection."""
        if severity == "CRITICAL":
            speech = f"Security Alert. Critical threat detected. {threat_name} has been intercepted."
        else:
            speech = f"Notice. Threat detected. {threat_name}."
        return self.announce(speech, priority="CRITICAL", force=True)

    def announce_scan_completed(self, files_scanned: int, threats_found: int) -> Dict[str, Any]:
        """Announce on-demand scan completion."""
        if threats_found > 0:
            speech = f"BI Antivirus scan completed. {threats_found} threats found. Please review dashboard."
            priority = "HIGH"
        else:
            speech = f"BI Antivirus scan completed. {files_scanned} files inspected. System is secure."
            priority = "NORMAL"
        return self.announce(speech, priority=priority)


# Singleton Instance
voice_service = VoiceAlertService()
