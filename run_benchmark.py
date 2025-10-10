import os, json, sqlite3, subprocess, shlex
from pathlib import Path
from datetime import datetime
from glob import glob

REPO = Path(__file__).parent.resolve()
CANDIDATES_DIR = REPO / "candidates"
DATABASE_DIR = REPO / "database"
DB_PATH = DATABASE_DIR / "benchmark_results.db"
TESTS_DIR = REPO / "tests"
REPORT_JSON = REPO / "report.json"
CONFTEST_RESULT = REPO / "conftest_result.json"

def discover_candidates():
    return [Path(p) for p in sorted(glob(str(CANDIDATES_DIR / "app_*.py")))]

def ensure_db():
    DATABASE_DIR.mkdir(exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate TEXT NOT NULL,
            solution TEXT NOT NULL,
            result_conftest TEXT NOT NULL,
            result_test_auth_api TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()

def save_result(candidate_name: str, solution: str, conftest_json: dict, tests_json: dict):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO results (candidate, solution, result_conftest, result_test_auth_api, created_at) VALUES (?, ?, ?, ?, ?)",
            (candidate_name, solution,
             json.dumps(conftest_json, ensure_ascii=False),
             json.dumps(tests_json, ensure_ascii=False),
             datetime.utcnow().isoformat(timespec='seconds') + 'Z')
        )
        conn.commit()

def run_pytest_for_candidate(candidate_path: Path):
    if REPORT_JSON.exists(): REPORT_JSON.unlink()
    if CONFTEST_RESULT.exists(): CONFTEST_RESULT.unlink()

    env = os.environ.copy()
    env["CANDIDATE_APP"] = str(candidate_path)
    env["CONFTEST_RESULT_FILE"] = str(CONFTEST_RESULT)
    env.setdefault("JWT_SECRET", "test-secret")

    cmd = f'pytest "{TESTS_DIR / "test_auth_api.py"}" --json-report --json-report-file="{REPORT_JSON}" -q --timeout=10'
    print(f"\n=== Running tests for {candidate_path.name} ===")
    print(f"Working dir: {REPO}")
    print(f"Command    : {cmd}")
    print(f"ENV        : CANDIDATE_APP={env['CANDIDATE_APP']}  JWT_SECRET={env['JWT_SECRET']}")
    rc = subprocess.call(shlex.split(cmd), cwd=str(REPO), env=env)
    print(f"pytest return code: {rc}")

    conftest_result = {}
    if CONFTEST_RESULT.exists():
        conftest_result = json.loads(CONFTEST_RESULT.read_text(encoding="utf-8"))

    tests_result = {}
    if REPORT_JSON.exists():
        tests_result = json.loads(REPORT_JSON.read_text(encoding="utf-8"))
    else:
        tests_result = {"summary": {"note": "json-report missing"}, "returncode": rc}

    return rc, conftest_result, tests_result

def main():
    print(f"ROOT       : {REPO}")
    print(f"CANDIDATES : {CANDIDATES_DIR}")
    print(f"TESTS      : {TESTS_DIR}")

    ensure_db()

    candidates = discover_candidates()
    print("Discovered:", [str(p) for p in candidates])
    if not candidates:
        print("No candidate files found. Expected: candidates/app_*.py")
        return

    for path in candidates:
        solution_code = path.read_text(encoding="utf-8", errors="replace")
        rc, conf_json, tests_json = run_pytest_for_candidate(path)

        s = tests_result_summary = tests_json.get("summary", {})
        tests_json["mini_summary"] = {
            "total": s.get("total"),
            "passed": s.get("passed"),
            "failed": s.get("failed"),
            "returncode": rc,
        }

        save_result(path.stem, solution_code, conf_json, tests_json)
        print(f"Saved result for {path.stem}: rc={rc}")

if __name__ == "__main__":
    main()
