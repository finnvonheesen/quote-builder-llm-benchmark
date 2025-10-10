import os
import json
import importlib.util
from pathlib import Path
import pytest
import tempfile

# Candidate path (runner should set CANDIDATE_APP). Fallback points to repo-root /candidates/app.py
CANDIDATE_APP = os.getenv(
    "CANDIDATE_APP",
    str(Path(__file__).resolve().parents[1] / "candidates" / "app.py")
)

# Optional: dump a small JSON sanity summary for the benchmark runner
CONFTEST_RESULT_FILE = os.getenv("CONFTEST_RESULT_FILE", "")


def _load_app_module(module_path: Path):
    spec = importlib.util.spec_from_file_location("candidate_app", str(module_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


@pytest.fixture(scope="session")
def sanity_report():
    module_path = Path(CANDIDATE_APP)
    assert module_path.exists(), f"candidate app.py not found at {module_path}"
    mod = _load_app_module(module_path)
    report = {
        "module_path": str(module_path),
        "import_ok": True,
        "has_create_app": hasattr(mod, "create_app"),
    }
    if CONFTEST_RESULT_FILE:
        try:
            Path(CONFTEST_RESULT_FILE).write_text(json.dumps(report), encoding="utf-8")
        except Exception:
            pass
    assert report["has_create_app"], "create_app() missing in candidate"
    return {"module_path": module_path, "mod": mod}


@pytest.fixture()
def client(sanity_report, monkeypatch):
    tmp = tempfile.TemporaryDirectory()
    db_path = Path(tmp.name) / "test_auth.db"
    monkeypatch.setenv("AUTH_DB_PATH", str(db_path))
    monkeypatch.setenv("JWT_SECRET", os.getenv("JWT_SECRET", "test-secret"))

    # Fresh app per test ensures clean state for property-based tests
    app = sanity_report["mod"].create_app()
    app.testing = True
    try:
        with app.test_client() as c:
            yield c
    finally:
        tmp.cleanup()
