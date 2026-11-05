"""
BI Antivirus - Comprehensive E2E Workflow Test Suite
Tests all positive and negative scenarios using genuine n8n execution engine
with an isolated loopback mock server. Strictly operates on D: drive.
Never damages or stops real BI Antivirus services.
"""

import os
import sys
import json
import time
import socket
import sqlite3
import threading
import subprocess
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

PROJECT_ROOT = Path(r"D:\bit defender")
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config" / "n8n"
ENV_FILE = CONFIG_DIR / "n8n.env"
DB_FILE = DATA_DIR / "n8n" / ".n8n" / "database.sqlite"
WORKFLOW_TEMPLATE_FILE = PROJECT_ROOT / "bi_antivirus_health_monitor.json"

NODE_EXE = r"D:\Program Files\nodejs\node.exe"
N8N_BIN = str(PROJECT_ROOT / "n8n" / "node_modules" / "n8n" / "bin" / "n8n")

MOCK_PORT = 8769
TEST_WF_ID = "TEST_HEALTH_MONITOR_E2E"

# Global mock server response controller
mock_state = {
    "status_code": 200,
    "body": "{}",
    "content_type": "application/json",
    "delay": 0.0,
}

class MockAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Quiet logs during test

    def do_GET(self):
        delay = mock_state.get("delay", 0.0)
        if delay > 0:
            time.sleep(delay)

        status_code = mock_state.get("status_code", 200)
        body = mock_state.get("body", "{}")
        content_type = mock_state.get("content_type", "application/json")

        response_bytes = body.encode("utf-8") if isinstance(body, str) else body
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception:
            pass

def load_env(env_path: Path) -> dict:
    env = {}
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env

WORKFLOW_ID = "ZIsNBbDMmjbASuu6"

def set_test_workflow_in_db(target_url: str):
    with open(WORKFLOW_TEMPLATE_FILE, "r", encoding="utf-8") as f:
        wf = json.load(f)

    # Modify the URL of node-http-status
    for node in wf["nodes"]:
        if node["id"] == "node-http-status":
            node["parameters"]["url"] = target_url

    conn = sqlite3.connect(str(DB_FILE), timeout=30.0)
    try:
        cur = conn.cursor()
        nodes_json = json.dumps(wf["nodes"])
        cur.execute("""
            UPDATE workflow_entity 
            SET nodes = ?, updatedAt = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')
            WHERE id = ?
        """, (nodes_json, WORKFLOW_ID))
        conn.commit()
    finally:
        conn.close()

def cleanup_test_workflow():
    if DB_FILE.exists() and WORKFLOW_TEMPLATE_FILE.exists():
        with open(WORKFLOW_TEMPLATE_FILE, "r", encoding="utf-8") as f:
            wf = json.load(f)
        conn = sqlite3.connect(str(DB_FILE), timeout=30.0)
        try:
            cur = conn.cursor()
            nodes_json = json.dumps(wf["nodes"])
            cur.execute("""
                UPDATE workflow_entity 
                SET nodes = ?, updatedAt = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')
                WHERE id = ?
            """, (nodes_json, WORKFLOW_ID))
            conn.commit()
        finally:
            conn.close()

def run_n8n_execute():
    proc_env = os.environ.copy()
    proc_env.update(load_env(ENV_FILE))
    proc_env["N8N_RUNNERS_BROKER_PORT"] = "5682"  # Isolated runner port

    cmd = [NODE_EXE, N8N_BIN, "execute", f"--id={WORKFLOW_ID}"]
    res = subprocess.run(cmd, env=proc_env, capture_output=True, text=True, timeout=30)
    stdout = res.stdout

    start = stdout.find("{")
    end = stdout.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(stdout[start:end+1])
        except Exception as e:
            return {"error": f"JSON parse error: {e}", "raw": stdout[start:end+1]}
    return {"error": "Could not locate JSON in output", "raw": stdout, "stderr": res.stderr}

def run_test_suite():
    print("======================================================================")
    print("      BI ANTIVIRUS HEALTH MONITOR — END-TO-END TEST SUITE")
    print("======================================================================")

    # Start mock server
    mock_server = HTTPServer(("127.0.0.1", MOCK_PORT), MockAPIHandler)
    server_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[*] Mock test server listening on http://127.0.0.1:{MOCK_PORT}")

    tests = [
        {
            "name": "Scenario 1: PROTECTED + realtime_guard_active=True",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": json.dumps({
                    "engine": "BI Antivirus",
                    "status": "PROTECTED",
                    "realtime_guard_active": True,
                    "engine_version": "2026.11-RELEASE",
                    "total_signatures": 19
                }),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Healthy Assessment",
            "expected_status": "PASSED - SECURE"
        },
        {
            "name": "Scenario 2: PROTECTED + realtime_guard_active=False",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": json.dumps({
                    "engine": "BI Antivirus",
                    "status": "PROTECTED",
                    "realtime_guard_active": False,
                    "engine_version": "2026.11-RELEASE",
                    "total_signatures": 19
                }),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "GUARD_INACTIVE"
        },
        {
            "name": "Scenario 3: Non-PROTECTED Status (DEGRADED)",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": json.dumps({
                    "engine": "BI Antivirus",
                    "status": "DEGRADED",
                    "realtime_guard_active": True,
                    "engine_version": "2026.11-RELEASE"
                }),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "STATUS_DEGRADED"
        },
        {
            "name": "Scenario 4: Missing Fields (Empty JSON Object)",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": "{}",
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED"
        },
        {
            "name": "Scenario 5: Invalid Non-JSON Response",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": "<html><body>502 Bad Gateway</body></html>",
                "content_type": "text/html",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED"
        },
        {
            "name": "Scenario 6: HTTP 401 Unauthorized Response",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 401,
                "body": json.dumps({"error": "Unauthorized", "message": "Invalid key"}),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "UNAUTHORIZED"
        },
        {
            "name": "Scenario 7: HTTP 403 Forbidden Response",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 403,
                "body": json.dumps({"error": "Forbidden", "message": "Loopback only"}),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "UNAUTHORIZED"
        },
        {
            "name": "Scenario 8: HTTP 500 Internal Server Error",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 500,
                "body": json.dumps({"error": "Internal Server Error"}),
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "API_ERROR"
        },
        {
            "name": "Scenario 9: Connection Refused (Closed Port 127.0.0.1:59998)",
            "url": "http://127.0.0.1:59998/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": "{}",
                "content_type": "application/json",
                "delay": 0.0
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "CONNECTION_REFUSED"
        },
        {
            "name": "Scenario 10: API Timeout Simulation (6s delay vs 5s limit)",
            "url": f"http://127.0.0.1:{MOCK_PORT}/api/v1/status",
            "mock": {
                "status_code": 200,
                "body": json.dumps({"status": "PROTECTED", "realtime_guard_active": True}),
                "content_type": "application/json",
                "delay": 6.5
            },
            "expected_node": "Record Warning Assessment",
            "expected_status": "ATTENTION NEEDED",
            "expected_category": "TIMEOUT"
        }
    ]

    passed = 0
    failed = 0

    try:
        for idx, t in enumerate(tests, 1):
            print(f"\n[{idx}/10] Testing: {t['name']}...")
            mock_state["status_code"] = t["mock"]["status_code"]
            mock_state["body"] = t["mock"]["body"]
            mock_state["content_type"] = t["mock"]["content_type"]
            mock_state["delay"] = t["mock"]["delay"]

            set_test_workflow_in_db(t["url"])
            result = run_n8n_execute()

            run_data = result.get("data", {}).get("resultData", {}).get("runData", {})
            last_node = result.get("data", {}).get("resultData", {}).get("lastNodeExecuted")

            # Extract output payload from the last node executed
            node_output = []
            if last_node and last_node in run_data:
                node_runs = run_data[last_node]
                if node_runs and "data" in node_runs[0] and "main" in node_runs[0]["data"]:
                    node_output = node_runs[0]["data"]["main"][0]

            output_json = node_output[0].get("json", {}) if node_output else {}
            health_status = output_json.get("health_status")
            error_cat = output_json.get("error_category")

            ok = True
            reasons = []

            if last_node != t["expected_node"]:
                ok = False
                reasons.append(f"Last node was '{last_node}' (expected '{t['expected_node']}')")

            if health_status != t["expected_status"]:
                ok = False
                reasons.append(f"health_status was '{health_status}' (expected '{t['expected_status']}')")

            if "expected_category" in t and error_cat != t["expected_category"]:
                ok = False
                reasons.append(f"error_category was '{error_cat}' (expected '{t['expected_category']}')")

            if ok:
                passed += 1
                cat_info = f" [Category: {error_cat}]" if error_cat else ""
                print(f"  -> PASS: Routed to '{last_node}' with '{health_status}'{cat_info}")
            else:
                failed += 1
                print(f"  -> FAIL: {', '.join(reasons)}")
                print(f"     Payload: {output_json}")

    finally:
        cleanup_test_workflow()
        mock_server.shutdown()
        mock_server.server_close()
        print("\n[*] Cleaned up test workflow and shut down mock server.")

    print("\n======================================================================")
    print(f"Total Scenarios Tested: {len(tests)}")
    print(f"Passed:                 {passed}")
    print(f"Failed:                 {failed}")
    print(f"Result:                 {'SUCCESS - ALL TESTS PASSED' if failed == 0 else 'FAILURE'}")
    print("======================================================================")

    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    run_test_suite()
