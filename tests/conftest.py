import os
import json
import importlib.util
from pathlib import Path
import pytest

# Allow selecting a specific candidate file via env var.
# Fallback to repo-root /candidate/app.py
CANDIDATE_APP = os.getenv(
    "CANDIDATE_APP",
    str(Path(__file__).resolve().parents[1] / "candidate" / "app.py")
)

# Optional: path where we dump a small JSON summary that the runner can store in the DB
CONFTEST_RESULT_FILE = os.getenv("CONFTEST_RESULT_FILE", "")


def _load_app_module(module_path: Path):
    spec = importlib.util.spec_from_file_location("candidate_app", str(module_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


@pytest.fixture(scope="session")
def test_env(tmp_path_factory):
    tmpdir = tmp_path_factory.mktemp("data")
    db_path = tmpdir / "test_auth.db"
    os.environ["AUTH_DB_PATH"] = str(db_path)
    os.environ.setdefault("JWT_SECRET", "test-secret")
    return {"db_path": db_path, "tmpdir": tmpdir}


@pytest.fixture(scope="session")
def flask_app(test_env):
    module_path = Path(CANDIDATE_APP)
    assert module_path.exists(), f"candidate app.py not found at {module_path}"

    # Prepare a small sanity report for DB storage
    sanity = {"module_path": str(module_path), "import_ok": False, "has_create_app": False}

    mod = _load_app_module(module_path)
    sanity["import_ok"] = True
    sanity["has_create_app"] = hasattr(mod, "create_app")

    # Persist the sanity result if requested
    if CONFTEST_RESULT_FILE:
        try:
            Path(CONFTEST_RESULT_FILE).write_text(json.dumps(sanity), encoding="utf-8")
        except Exception:
            pass

    assert sanity["has_create_app"], "create_app() missing in candidate"
    app = mod.create_app()
    return app


@pytest.fixture()
def client(flask_app, test_env):
    # Fast & reliable Flask test client
    with flask_app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def clean_db(test_env):
    # Fresh DB per test
    db_path = test_env["db_path"]
    if db_path.exists():
        db_path.unlink()
    yield
    if db_path.exists():
        db_path.unlink()
