import os, json, sqlite3, subprocess, shlex
from pathlib import Path
from datetime import datetime

# --------- CONFIG ---------
REPO = Path(__file__).parent.resolve()
CANDIDATES_DIR = REPO / "candidate"
DATABASE_DIR = REPO / "database"
DB_PATH = DATABASE_DIR / "benchmark_results.db"
TESTS_DIR = REPO / "tests"
REPORT_JSON = REPO / "report.json"           # pytest-json-report output
CONFTEST_RESULT = REPO / "conftest_result.json"

# list your candidate files here (5 files)
CANDIDATE_FILES = [
    CANDIDATES_DIR / "app_1.py",
    CANDIDATES_DIR / "app_2.py",
    CANDIDATES_DIR / "app_3.py",
    CANDIDATES_DIR / "app_4.py",
    CANDIDATES_DIR / "app_5.py",
]
# --------------------------

def ensure_db():
    DATABASE_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS results (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   candidate TEXT NOT NULL,
                   solution TEXT NOT NULL,
                   result_conftest TEXT NOT NULL,
                   result_test_auth_api TEXT NOT NULL,
                   created_at TEXT DEFAULT CURRENT_TIMESTAMP
               )"""
        )
        conn.commit()

def save_result(candidate_name: str, solution: str, conftest_json: dict, tests_json: dict):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO results (candidate, solution, result_conftest, result_test_auth_api, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                candidate_name,
                solution,
                json.dumps(conftest_json, ensure_ascii=False),
                json.dumps(tests_json, ensure_ascii=False),
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
            ),
        )
        conn.commit()

def run_pytest_for_candidate(candidate_path: Path):
    # Clean previous artifacts
    if REPORT_JSON.exists():
        REPORT_JSON.unlink()
    if CONFTEST_RESULT.exists():
        CONFTEST_RESULT.unlink()

    env = os.environ.copy()
    env["CANDIDATE_APP"] = str(candidate_path)
    env["CONFTEST_RESULT_FILE"] = str(CONFTEST_RESULT)
    # Isolate the app DB used inside tests (doesn't affect our results DB)
    env.setdefault("JWT_SECRET", "test-secret")

    # Only run the API tests file to keep result_test_auth_api focused
    cmd = f'pytest "{TESTS_DIR / "test_auth_api.py"}" --json-report --json-report-file="{REPORT_JSON}" -q --timeout=10'
    print(f"\n=== Running tests for {candidate_path.name} ===")
    print(cmd)
    completed = subprocess.run(shlex.split(cmd), cwd=str(REPO), env=env, capture_output=True, text=True)

    # Load exported mini result from conftest
    conftest_result = {}
    if CONFTEST_RESULT.exists():
        conftest_result = json.loads(CONFTEST_RESULT.read_text(encoding="utf-8"))

    # Load pytest JSON report
    tests_result = {}
    if REPORT_JSON.exists():
        tests_result = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
    else:
        # Fallback if plugin failed; at least store stdout/stderr
        tests_result = {
            "summary": {"note": "json-report missing"},
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }

    return completed.returncode, conftest_result, tests_result, completed.stdout, completed.stderr

def main():
    ensure_db()
    missing = [p for p in CANDIDATE_FILES if not p.exists()]
    if missing:
        print("Missing candidate files:", ", ".join(str(p) for p in missing))
        return

    for path in CANDIDATE_FILES:
        # Read raw code for the DB
        solution_code = path.read_text(encoding="utf-8", errors="replace")
        rc, conf_json, tests_json, out, err = run_pytest_for_candidate(path)
        candidate_name = path.stem  # e.g., app_1

        # Keep result_test_auth_api compact but useful:
        # derive a mini summary (passed/failed/total) alongside full JSON
        try:
            total = tests_json.get("summary", {}).get("total", None)
            passed = tests_json.get("summary", {}).get("passed", None)
            failed = tests_json.get("summary", {}).get("failed", None)
            tests_json["mini_summary"] = {"total": total, "passed": passed, "failed": failed, "returncode": rc}
        except Exception:
            pass

        save_result(candidate_name, solution_code, conf_json, tests_json)
        print(f"Saved result for {candidate_name}: rc={rc}")

if __name__ == "__main__":
    main()
