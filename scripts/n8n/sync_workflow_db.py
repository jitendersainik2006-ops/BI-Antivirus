"""
BI Antivirus - Synchronize Hardened Health Monitor Workflow to n8n SQLite DB
Preserves workflow ID ZIsNBbDMmjbASuu6, active=0, execution history, and credentials.
Strictly runs on D: drive.
"""

import json
import sqlite3
import sys
from pathlib import Path

WORKFLOW_FILE = Path(r"D:\bit defender\bi_antivirus_health_monitor.json")
DB_FILE = Path(r"D:\bit defender\data\n8n\.n8n\database.sqlite")
WORKFLOW_ID = "ZIsNBbDMmjbASuu6"

def sync_workflow():
    if not WORKFLOW_FILE.exists():
        print(f"[!] Workflow file not found: {WORKFLOW_FILE}", file=sys.stderr)
        sys.exit(1)

    if not DB_FILE.exists():
        print(f"[!] n8n Database not found: {DB_FILE}", file=sys.stderr)
        sys.exit(1)

    with open(WORKFLOW_FILE, "r", encoding="utf-8") as f:
        wf = json.load(f)

    name = wf.get("name", "BI Antivirus Health Monitor")
    nodes_json = json.dumps(wf.get("nodes", []))
    connections_json = json.dumps(wf.get("connections", {}))
    settings_json = json.dumps(wf.get("settings", {"executionOrder": "v1"}))
    active = 0  # Inactive by requirement

    conn = sqlite3.connect(str(DB_FILE))
    cur = conn.cursor()

    cur.execute("SELECT id FROM workflow_entity WHERE id = ?", (WORKFLOW_ID,))
    exists = cur.fetchone()

    if exists:
        cur.execute("""
            UPDATE workflow_entity 
            SET name = ?, nodes = ?, connections = ?, settings = ?, active = 0, updatedAt = STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW')
            WHERE id = ?
        """, (name, nodes_json, connections_json, settings_json, WORKFLOW_ID))
        print(f"[*] Updated existing workflow ID {WORKFLOW_ID} in database.")
    else:
        cur.execute("""
            INSERT INTO workflow_entity (id, name, active, nodes, connections, settings, createdAt, updatedAt)
            VALUES (?, ?, 0, ?, ?, ?, STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'), STRFTIME('%Y-%m-%d %H:%M:%f', 'NOW'))
        """, (WORKFLOW_ID, name, nodes_json, connections_json, settings_json))
        print(f"[*] Inserted workflow ID {WORKFLOW_ID} into database.")

    conn.commit()

    # Verify inactive state and preserved execution history
    cur.execute("SELECT id, name, active FROM workflow_entity WHERE id = ?", (WORKFLOW_ID,))
    row = cur.fetchone()
    print(f"[*] Verified workflow record: ID={row[0]}, Name='{row[1]}', Active={row[2]} (0=INACTIVE)")

    cur.execute("SELECT COUNT(*) FROM execution_entity WHERE workflowId = ?", (WORKFLOW_ID,))
    exec_count = cur.fetchone()[0]
    print(f"[*] Preserved execution history records for workflow: {exec_count}")

    conn.close()
    print("[*] Workflow synchronization completed successfully.")

if __name__ == "__main__":
    sync_workflow()
