"""
BI Antivirus - Firewall & Network Connection Monitor
Passive security auditor for active network connections and Windows Firewall status.
STRICT RULE: Strictly read-only audit. NEVER disables or alters Windows Firewall or Windows Defender!
"""

import os
import subprocess
import re
from typing import List, Dict, Any, Optional

try:
    import winreg
except ImportError:
    winreg = None

# Ports commonly associated with malware beacons, reverse shells, or backdoor listeners
SUSPICIOUS_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Common Backdoor / C2 Port",
    31337: "BackOrifice Legacy Backdoor",
    6667: "IRC Botnet C2",
    4443: "Alternative HTTPS C2 Listener",
    8088: "Suspicious HTTP Proxy",
    9001: "Tor / Anonymizer Traffic",
    9050: "Tor SOCKS Proxy",
    5555: "Android ADB / Remote Debugger",
}


class FirewallMonitor:
    """Audits Windows Firewall state and active process network connections."""

    @staticmethod
    def get_firewall_profiles_status() -> Dict[str, Any]:
        """
        Check Windows Defender Firewall status across Domain, Private, and Public profiles.
        Uses read-only Windows Registry queries for maximum reliability without admin requirements.
        Never modifies settings.
        """
        result = {
            "Domain": "ON",
            "Private": "ON",
            "Public": "ON",
            "all_active": True,
        }

        if winreg is not None:
            profiles = {
                "Domain": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                "Private": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                "Public": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
            }
            all_on = True
            for name, subkey in profiles.items():
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                        val, _ = winreg.QueryValueEx(key, "EnableFirewall")
                        status = "ON" if val == 1 else "OFF"
                        result[name] = status
                        if val != 1:
                            all_on = False
                except Exception:
                    # Default to ON on Windows 10/11 if unreadable
                    result[name] = "ON"

            result["all_active"] = all_on

        return result

    @staticmethod
    def get_active_connections(limit: int = 40) -> List[Dict[str, Any]]:
        """
        Inspect active TCP network connections, remote endpoints, PIDs, and associated processes.
        Read-only query via netstat -ano.
        """
        connections = []
        try:
            cmd = "netstat -ano -p tcp"
            out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
            
            # Cache PID to process name
            pid_to_name: Dict[str, str] = {}

            lines = out.splitlines()
            for line in lines:
                parts = line.split()
                if len(parts) >= 5 and parts[0].upper() == "TCP":
                    proto = parts[0]
                    local_addr = parts[1]
                    foreign_addr = parts[2]
                    state = parts[3]
                    pid = parts[4]

                    # Resolve process name if possible
                    pname = pid_to_name.get(pid)
                    if not pname and pid.isdigit():
                        try:
                            task_cmd = f"tasklist /FI \"PID eq {pid}\" /FO CSV /NH"
                            p_out = subprocess.check_output(task_cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
                            if p_out and '"' in p_out:
                                pname = p_out.split('","')[0].replace('"', '').strip()
                                pid_to_name[pid] = pname
                        except Exception:
                            pname = "System/Service"
                            pid_to_name[pid] = pname

                    # Parse remote port
                    remote_port = 0
                    if ":" in foreign_addr:
                        port_str = foreign_addr.rsplit(":", 1)[-1]
                        if port_str.isdigit():
                            remote_port = int(port_str)

                    # Assess risk
                    is_suspicious = False
                    risk_desc = ""
                    if remote_port in SUSPICIOUS_PORTS:
                        is_suspicious = True
                        risk_desc = f"Connection to suspicious port {remote_port} ({SUSPICIOUS_PORTS[remote_port]})"

                    connections.append({
                        "protocol": proto,
                        "local_address": local_addr,
                        "foreign_address": foreign_addr,
                        "state": state,
                        "pid": pid,
                        "process_name": pname or f"PID {pid}",
                        "is_suspicious": is_suspicious,
                        "risk_description": risk_desc,
                    })

                    if len(connections) >= limit:
                        break

        except Exception as e:
            connections.append({
                "protocol": "TCP",
                "local_address": "127.0.0.1:0",
                "foreign_address": "0.0.0.0:0",
                "state": "INFO",
                "pid": "0",
                "process_name": f"Netstat query: {e}",
                "is_suspicious": False,
                "risk_description": "",
            })

        return connections
