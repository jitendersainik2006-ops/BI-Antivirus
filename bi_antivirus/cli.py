"""
BI Antivirus - Command Line Interface (CLI)
Provides full headless control over scanning, quarantine, updates, web defense,
firewall monitoring, and report generation.
"""

import sys
import argparse
import time
from pathlib import Path
from typing import Optional

from bi_antivirus.config import APP_NAME, APP_VERSION, ENGINE_VERSION
from bi_antivirus.core.engine import AntivirusEngine
from bi_antivirus.core.authenticode import verify_authenticode


def print_banner():
    banner = f"""
========================================================================
    {APP_NAME} - Enterprise Cyber Defense Platform
    Version: {APP_VERSION} | Engine: {ENGINE_VERSION}
    Storage Root: D:\\BI-Antivirus (Secure D: Drive)
========================================================================
"""
    print(banner)


def cli_progress_callback(p: dict):
    file_display = p.get("current_file", "")
    if len(file_display) > 55:
        file_display = "..." + file_display[-52:]
    sys.stdout.write(
        f"\r[*] Scanned: {p.get('files_scanned', 0):<5} | Threats: {p.get('threats_count', 0):<3} | Rate: {p.get('scan_rate_fps', 0):<4} f/s | File: {file_display:<55}"
    )
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(
        prog="bi-av",
        description=f"{APP_NAME} - Original Windows Antivirus & Threat Protection Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Command: status
    subparsers.add_parser("status", help="Display current protection and database status")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run file scan")
    scan_group = scan_parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument("--quick", action="store_true", help="Run Quick Scan of Windows hotspots")
    scan_group.add_argument("--full", action="store_true", help="Run Full System Scan")
    scan_group.add_argument("--path", type=str, help="Scan a custom directory or file")

    # Command: quarantine
    q_parser = subparsers.add_parser("quarantine", help="Manage quarantine vault")
    q_sub = q_parser.add_subparsers(dest="q_action", help="Quarantine action")
    q_sub.add_parser("list", help="List all quarantined items")
    res_parser = q_sub.add_parser("restore", help="Restore a quarantined file")
    res_parser.add_argument("id", type=str, help="Quarantine ID to restore")
    res_parser.add_argument("--to", type=str, default=None, help="Optional custom restore destination")
    purge_parser = q_sub.add_parser("purge", help="Permanently delete a quarantined file")
    purge_parser.add_argument("id", type=str, help="Quarantine ID to purge")

    # Command: web
    web_parser = subparsers.add_parser("web", help="Web protection and reputation queries")
    web_parser.add_argument("url", type=str, help="URL or domain to audit")

    # Command: firewall
    fw_parser = subparsers.add_parser("firewall", help="Audit Windows Firewall and network connections")
    fw_parser.add_argument("--connections", action="store_true", help="List active network connections")

    # Command: update
    upd_parser = subparsers.add_parser("update", help="Check or apply malware definition updates")
    upd_parser.add_argument("--check", action="store_true", help="Check definition database status")
    upd_parser.add_argument("--apply", type=str, help="Path to JSON definition update pack")

    # Command: report
    subparsers.add_parser("report", help="Generate security audit report on D: drive")

    # Command: vulnerability
    subparsers.add_parser("vulnerability", help="Audit Windows system posture and security vulnerabilities")

    # Command: usb
    usb_parser = subparsers.add_parser("usb", help="Inspect and audit removable USB storage drives")
    usb_parser.add_argument("--scan", type=str, help="Specific drive letter to audit (e.g., E:)")

    # Command: behavior
    beh_parser = subparsers.add_parser("behavior", help="Inspect running processes for anomalous or malicious behavior")
    beh_parser.add_argument("--limit", type=int, default=25, help="Number of processes to inspect")

    # Command: ransomware
    subparsers.add_parser("ransomware", help="Check ransomware shield status and honeypot canary traps")

    # Command: authenticode
    auth_parser = subparsers.add_parser("authenticode", help="Verify Authenticode digital signature of a Windows PE binary")
    auth_parser.add_argument("file", type=str, help="Path to executable or DLL to verify")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    engine = AntivirusEngine()

    if args.command == "status":
        print_banner()
        summary = engine.get_dashboard_summary()
        print(f"System Status:         {summary['status']}")
        print(f"Real-Time Guard:       {'ACTIVE' if summary['realtime_active'] else 'INACTIVE'}")
        print(f"Behavioral Sentinel:   {'ACTIVE' if summary.get('behavioral_active') else 'INACTIVE'}")
        print(f"Ransomware Shield:     {'ACTIVE' if summary.get('ransomware_shield_active') else 'INACTIVE'} ({summary.get('canaries_deployed', 0)} Canaries)")
        print(f"USB Removable Sentinel:{'ACTIVE' if summary.get('usb_sentinel_active') else 'INACTIVE'}")
        print(f"Malware Signatures:    {summary['total_signatures']}")
        print(f"Definition Version:    {summary['definition_version']}")
        print(f"Definitions Up to Date:{summary['definitions_up_to_date']}")
        print(f"Total Files Scanned:   {summary['total_files_scanned']}")
        print(f"Total Threats Found:   {summary['total_threats_found']}")
        print(f"Quarantined in Vault:  {summary['quarantined_items_count']}")
        print(f"Last Scan Run:         {summary['last_scan_time']}")

    elif args.command == "scan":
        print_banner()
        if args.quick:
            print("[+] Starting Quick Scan of Windows security hotspots...")
            res = engine.scanner.scan_quick(progress_cb=cli_progress_callback)
        elif args.full:
            print("[+] Starting Full System Scan...")
            res = engine.scanner.scan_full(progress_cb=cli_progress_callback)
        elif args.path:
            target = Path(args.path)
            print(f"[+] Starting Custom Scan on: {target}...")
            res = engine.scanner.scan_path(target, progress_cb=cli_progress_callback)

        print("\n\n" + "=" * 60)
        print(f"Scan Finished: {res['status']}")
        print(f"Duration:      {res['duration_seconds']} seconds")
        print(f"Files Scanned: {res['files_scanned']}")
        print(f"Threats Found: {res['threats_count']}")
        if res['threats']:
            print("-" * 60)
            print("DETECTED THREATS:")
            for idx, t in enumerate(res['threats'], 1):
                print(f"  {idx}. [{t['severity']}] {t['threat_name']}")
                print(f"     Path: {t['file_path']}")
                print(f"     Hash: {t.get('file_hash')}")
                print(f"     Risk Score: {t.get('risk_score', 0)}/100")
            print("-" * 60)
            print("[!] Notice: Threats were NOT deleted automatically. Use 'bi-av quarantine' or Dashboard to review.")
        else:
            print("[+] No threats detected. System is clean.")

    elif args.command == "quarantine":
        if args.q_action == "list" or not args.q_action:
            print_banner()
            items = engine.quarantine_mgr.list_quarantine(status="ALL")
            if not items:
                print("[*] Quarantine vault is empty.")
            else:
                print(f"{'QUARANTINE ID':<26} {'STATUS':<12} {'SEVERITY':<10} {'THREAT NAME':<25} {'ORIGINAL PATH'}")
                print("-" * 100)
                for item in items:
                    print(
                        f"{item['quarantine_id']:<26} {item['status']:<12} {item['severity']:<10} {item['threat_name'][:24]:<25} {item['original_path']}"
                    )

        elif args.q_action == "restore":
            target = Path(args.to) if args.to else None
            ok, msg = engine.restore_threat(args.id, custom_target=target)
            print(f"[{'+' if ok else '!'}] {msg}")

        elif args.q_action == "purge":
            ok, msg = engine.purge_quarantined_threat(args.id)
            print(f"[{'+' if ok else '!'}] {msg}")

    elif args.command == "web":
        print_banner()
        print(f"[*] Auditing URL/Domain: {args.url}")
        res = engine.web_shield.check_url(args.url)
        print(f"Result:       {'THREAT DETECTED' if res['is_threat'] else 'CLEAN'}")
        print(f"Severity:     {res['severity']}")
        print(f"Category:     {res.get('category', 'Standard')}")
        print(f"Reason:       {res.get('reason', '')}")
        print(f"Risk Score:   {res.get('risk_score', 0)}/100")

    elif args.command == "firewall":
        print_banner()
        status = engine.firewall_monitor.get_firewall_profiles_status()
        print("[+] Windows Defender Firewall Status:")
        print(f"    Domain Profile:  {status.get('Domain')}")
        print(f"    Private Profile: {status.get('Private')}")
        print(f"    Public Profile:  {status.get('Public')}")
        print("    (Firewall rules and Windows Defender are monitored passively without alteration)")

        if args.connections:
            print("\n[+] Active Network Connections:")
            conns = engine.firewall_monitor.get_active_connections(limit=25)
            print(f"{'PROTO':<6} {'LOCAL ADDRESS':<22} {'FOREIGN ADDRESS':<22} {'STATE':<14} {'PID':<8} {'PROCESS'}")
            print("-" * 90)
            for c in conns:
                flag = " [!] " if c.get("is_suspicious") else ""
                print(
                    f"{c['protocol']:<6} {c['local_address']:<22} {c['foreign_address']:<22} {c['state']:<14} {c['pid']:<8} {c['process_name'][:20]}{flag}"
                )

    elif args.command == "update":
        print_banner()
        if args.apply:
            with open(args.apply, "r", encoding="utf-8") as f:
                pack_content = f.read()
            res = engine.updater.apply_update_pack(pack_content)
            print(f"[{'+' if res['success'] else '!'}] {res.get('message', res.get('error'))}")
        else:
            status = engine.updater.check_definition_status()
            print("[+] Signature Database Status:")
            print(f"    Version:           {status['version']}")
            print(f"    Total Indicators:  {status['total_signatures']}")
            print(f"    Hash Signatures:   {status['hash_signatures']}")
            print(f"    Pattern Rules:     {status['pattern_signatures']}")
            print(f"    Web Reputations:   {status['web_reputations']}")
            print(f"    Last Updated:      {status['last_updated']}")
            print(f"    Database Age:      {status['age_days']} days ({status['status']})")

    elif args.command == "report":
        print_banner()
        path = engine.generate_current_report()
        print(f"[+] Security report generated on D: drive: {path}")

    elif args.command == "vulnerability":
        print_banner()
        print("[*] Running 5-Control Windows Baseline Security Assessment...")
        rep = engine.run_vulnerability_audit()
        print(f"\n[+] 5-CONTROL BASELINE ASSESSMENT: {rep['passed_checks']}/{rep['total_checks']} CONTROLS PASSED ({rep['posture_score']}/100 [{rep['posture_rating']}])")
        print("    (Evaluates 5 Windows security baseline controls: UAC, SMBv1, Firewall, RDP NLA, Updates)")
        print(f"    Controls Checked:       {rep['total_checks']}")
        print(f"    Controls Passed:        {rep['passed_checks']}")
        print(f"    Vulnerabilities Found:  {rep['vulnerabilities_found']}")
        print("-" * 75)
        print(f"{'STATUS':<8} {'CONTROL NAME':<28} {'SEVERITY':<10} {'DETAILS'}")
        print("-" * 75)
        for c in rep.get("checks", []):
            mark = f"[{c.get('status', 'INFO')}]"
            print(f"{mark:<8} {c.get('check', '')[:26]:<28} {c.get('severity', ''):<10} {c.get('details')}")
            if c.get("status") != "PASS" and c.get("recommendation"):
                print(f"         Remediation: {c.get('recommendation')}")
        print("-" * 75)

    elif args.command == "usb":
        print_banner()
        if args.scan:
            target = args.scan
            print(f"[*] Auditing Removable Drive Root: {target}...")
            res = engine.usb_sentinel.audit_drive_root(target)
            print(f"Drive:          {res.get('drive')}")
            print(f"Autorun Status: {res.get('autorun_status')}")
            print(f"Threats Found:  {len(res.get('threats', []))}")
            for t in res.get("threats", []):
                print(f"  [!] {t.get('threat_name')} ({t.get('severity')}): {t.get('file_path')}")
        else:
            print("[*] Enumerating Mounted Removable USB Storage Drives...")
            drives = engine.usb_sentinel.get_removable_drives()
            if not drives:
                print("[+] No removable USB drives currently mounted.")
            else:
                print(f"{'DRIVE':<8} {'TYPE':<12} {'VOLUME NAME':<20} {'FS TYPE'}")
                print("-" * 55)
                for d in drives:
                    print(f"{d['drive']:<8} {'REMOVABLE':<12} {d.get('volume_name', ''):<20} {d.get('fs_type', '')}")
                print("\n[*] Auditing all mounted removable drives...")
                for d in drives:
                    res = engine.usb_sentinel.audit_drive_root(d["drive"])
                    print(f"  [>] {d['drive']} - Autorun: {res.get('autorun_status')} | Threats: {len(res.get('threats', []))}")

    elif args.command == "behavior":
        print_banner()
        print(f"[*] Capturing running process telemetry...")
        procs = engine.behavioral_monitor.get_process_snapshot()
        pid_map = {p["pid"]: p["name"] for p in procs}
        anomalies = []
        for p in procs:
            parent_name = pid_map.get(p.get("parent_pid"), "")
            res = engine.behavioral_monitor.evaluate_process_behavior(p, parent_name=parent_name)
            if res.get("is_anomaly"):
                anomalies.append(res)

        print(f"Total Processes Tracked: {len(procs)}")
        if anomalies:
            print(f"\n[!] DETECTED BEHAVIORAL ANOMALIES ({len(anomalies)}):")
            for a in anomalies[:args.limit]:
                print(f"  PID: {a.get('pid')} | Process: {a.get('process_name')} | Severity: {a.get('severity')}")
                print(f"  Summary: {a.get('summary')}")
        else:
            print("\n[+] No suspicious process anomalies detected. Process tree integrity verified.")

    elif args.command == "ransomware":
        print_banner()
        status = engine.ransomware_shield.get_shield_status()
        print(f"Ransomware Shield:    {'ACTIVE' if status.get('is_running') else 'INACTIVE'}")
        print(f"Canary Traps Active:  {status.get('canaries_count', 0)}")
        print(f"Mutations Tracked:    {status.get('mutations_tracked', 0)}")
        print(f"Burst Alert Count:    {status.get('burst_alerts', 0)}")
        print("\nDeployed Canary Integrity Traps:")
        for c in status.get("canaries", []):
            st = "[DEPLOYED]" if Path(c).exists() else "[MISSING]"
            print(f"  {st} {c}")

    elif args.command == "authenticode":
        print_banner()
        target = Path(args.file)
        if not target.exists():
            print(f"[!] File not found: {target}")
            sys.exit(1)
        print(f"[*] Auditing Authenticode Digital Signature: {target}...")
        res = verify_authenticode(target)
        print(f"Trust Status:    {res.get('status')}")
        print(f"Is Signed:       {res.get('is_signed')}")
        print(f"Is Trusted:      {res.get('is_trusted')}")
        print(f"Status Code:     {hex(res.get('status_code', 0))}")
        print(f"Description:     {res.get('description', '')}")


if __name__ == "__main__":
    main()
