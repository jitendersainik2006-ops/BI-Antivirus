"""
BI Antivirus - Enterprise Performance & Reliability Benchmark Utility
Measures core endpoint engine performance metrics:
- Streaming cryptographic hash throughput (SHA-256 in MB/s)
- Pattern matching evaluation throughput (Files/s using compiled cache)
- SQLite database query & write operations per second (IOPS)
- Memory and execution responsiveness
- Outputs empirical metrics for verification reports.
"""

import os
import sys
import time
import json
import tempfile
import statistics
from pathlib import Path

# Ensure root path is in sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from bi_antivirus.core.detector import ThreatDetector
from bi_antivirus.database.signatures import SignatureDatabase
from bi_antivirus.database.history import HistoryDatabase
from bi_antivirus.core.quarantine import QuarantineManager


def benchmark_hashing_throughput(size_mb: int = 50) -> dict:
    """Benchmark streaming SHA-256 / MD5 hashing throughput in MB/s."""
    data = b"A" * (1024 * 1024)  # 1 MB block
    detector = ThreatDetector()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp_path = Path(tmp.name)
        for _ in range(size_mb):
            tmp.write(data)

    try:
        start_time = time.perf_counter()
        sha256, md5, bytes_read = detector.calculate_file_hash(tmp_path, max_bytes=size_mb * 1024 * 1024 * 2)
        elapsed = time.perf_counter() - start_time
        mb_read = bytes_read / (1024 * 1024)
        throughput_mb_s = round(mb_read / max(elapsed, 0.0001), 2)

        return {
            "test": "hashing_throughput",
            "file_size_mb": size_mb,
            "elapsed_seconds": round(elapsed, 4),
            "throughput_mb_s": throughput_mb_s,
            "sha256_sample": sha256[:16] + "...",
        }
    finally:
        tmp_path.unlink(missing_ok=True)


def benchmark_pattern_matching(iterations: int = 2000) -> dict:
    """Benchmark pattern matching throughput on file sample bytes."""
    sig_db = SignatureDatabase()
    sample_text = (
        b"Standard harmless system log content. "
        b"Process id 4120 spawned normally. "
        b"Configuration parameter verified. "
        b"No suspicious token found in execution context."
    )

    # Prime cache
    sig_db.match_patterns(sample_text)

    start_time = time.perf_counter()
    for _ in range(iterations):
        sig_db.match_patterns(sample_text)
    elapsed = time.perf_counter() - start_time

    rate_fps = round(iterations / max(elapsed, 0.0001), 1)
    return {
        "test": "pattern_matching_throughput",
        "iterations": iterations,
        "elapsed_seconds": round(elapsed, 4),
        "evaluations_per_second": rate_fps,
    }


def benchmark_database_performance(records_count: int = 500) -> dict:
    """Benchmark SQLite WAL mode write & index-assisted query performance."""
    import gc
    bench_dir = PROJECT_DIR / "data" / "bench_temp"
    bench_dir.mkdir(parents=True, exist_ok=True)
    db_path = bench_dir / "bench_history.db"
    if db_path.exists():
        db_path.unlink(missing_ok=True)

    history_db = HistoryDatabase(db_path=db_path)

    try:
        # Measure Write Throughput
        start_write = time.perf_counter()
        for i in range(records_count):
            history_db.record_threat(
                session_id=f"BENCH-SESS-{i % 10}",
                file_path=f"D:\\test\\sample_file_{i}.exe",
                file_hash=f"hash_{i:08x}" * 4,
                file_size=1024 * (i + 1),
                threat_name=f"Threat.Sample.{i}",
                threat_family="Trojan",
                severity="HIGH" if i % 2 == 0 else "MEDIUM",
                action_taken="FLAGGED",
                details="Benchmark inserted record",
            )
        write_elapsed = time.perf_counter() - start_write
        write_iops = round(records_count / max(write_elapsed, 0.0001), 1)

        # Measure Indexed Query Throughput
        start_query = time.perf_counter()
        query_hits = 0
        with history_db._get_connection() as conn:
            cursor = conn.cursor()
            for i in range(records_count):
                cursor.execute(
                    "SELECT threat_name, severity FROM threat_detections WHERE file_hash = ?",
                    (f"hash_{i:08x}" * 4,)
                )
                row = cursor.fetchone()
                if row:
                    query_hits += 1
        query_elapsed = time.perf_counter() - start_query
        query_iops = round(records_count / max(query_elapsed, 0.0001), 1)

        # Test PRAGMA integrity check
        ok, msg = history_db.check_integrity()

        return {
            "test": "database_iops",
            "records": records_count,
            "write_elapsed_seconds": round(write_elapsed, 4),
            "write_iops": write_iops,
            "query_elapsed_seconds": round(query_elapsed, 4),
            "query_iops": query_iops,
            "integrity_verified": ok,
        }
    finally:
        del history_db
        gc.collect()
        for p in bench_dir.glob("bench_history*"):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            bench_dir.rmdir()
        except Exception:
            pass


def run_all_benchmarks() -> dict:
    print("=" * 70)
    print("       BI ANTIVIRUS - PERFORMANCE & RELIABILITY BENCHMARK")
    print("=" * 70)

    hash_res = benchmark_hashing_throughput(size_mb=30)
    print(f"[+] Hashing Throughput:    {hash_res['throughput_mb_s']} MB/s ({hash_res['file_size_mb']}MB in {hash_res['elapsed_seconds']}s)")

    pat_res = benchmark_pattern_matching(iterations=2500)
    print(f"[+] Pattern Evaluation:    {pat_res['evaluations_per_second']} files/sec ({pat_res['iterations']} evals in {pat_res['elapsed_seconds']}s)")

    db_res = benchmark_database_performance(records_count=400)
    print(f"[+] SQLite Write IOPS:     {db_res['write_iops']} writes/sec ({db_res['records']} records)")
    print(f"[+] SQLite Index Query:    {db_res['query_iops']} queries/sec ({db_res['records']} queries)")
    print(f"[+] DB Integrity Check:    {'PASSED' if db_res['integrity_verified'] else 'FAILED'}")

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hashing": hash_res,
        "pattern_matching": pat_res,
        "database": db_res,
    }

    # Save benchmark report on D:
    bench_out = PROJECT_DIR / "bi_antivirus_benchmark_results.json"
    with open(bench_out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("=" * 70)
    print(f"Benchmark results saved to: {bench_out}")
    print("=" * 70)
    return results


if __name__ == "__main__":
    run_all_benchmarks()
