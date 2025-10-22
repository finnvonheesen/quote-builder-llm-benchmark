import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import Flask, jsonify, request, g


def create_app() -> Flask:
    app = Flask(__name__)

    email_regex = re.compile(r'^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$')

    def ensure_schema(db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
        )
        db.commit()

    def get_db() -> sqlite3.Connection:
        db = getattr(g, "_db", None)
        if db is None:
            path = os.environ.get("AUTH_DB_PATH", "auth.db")
            db = sqlite3.connect(path)
            db.row_factory = sqlite3.Row
            ensure_schema(db)
            g._db = db
        return db

    @app.teardown_appcontext
    def close_db(exception):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    def validate_email(raw: str) -> str | None:
        if not isinstance(raw, str):
            return None
        e = raw.strip().lower()
        if ".." in e or not email_regex.fullmatch(e):
            return None
        return e

    def validate_password(pw: str) -> bool:
        if not isinstance(pw, str):
            return False
        # The regex was too permissive and allowed empty strings.
        # Let's stick to a more explicit check.
        if not pw:
            return False
        if len(pw) < 8:
            return False
        has_letter = any(c.isalpha() for c in pw)
        has_digit = any(c.isdigit() for c in pw)
        return has_letter and has_digit

    def hash_password(pw: str) -> str:
        rounds = int(os.environ.get("BCRYPT_ROUNDS", 12))
        return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")

    def check_password(pw: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

    def create_token(email: str) -> str:
        secret = os.environ.get("JWT_SECRET", "dev-secret")
        now = datetime.now(timezone.utc)
        payload = {
            "sub": email,
            "iat": now,
            "exp": now + timedelta(seconds=900),
        }
        return jwt.encode(payload, secret, algorithm="HS256")

    def parse_bearer_token(header_value: str | None) -> str | None:
        if not header_value or not isinstance(header_value, str):
            return None
        parts = header_value.strip().split()
        if len(parts) != 2:
            return None
        if parts[0].lower() != "bearer":
            return None
        return parts[1]

    @app.post("/signup")
    def signup():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "invalid_request"}), 400
        email = validate_email(data.get("email"))
        password = data.get("password")
        if not email or not validate_password(password):
            return jsonify({"error": "invalid_request"}), 400
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hash_password(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "email_exists"}), 409
        return jsonify({"status": "created"}), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "invalid_request"}), 400
        email = validate_email(data.get("email"))
        password = data.get("password")
        if not email or not isinstance(password, str):
            return jsonify({"error": "invalid_request"}), 400
        db = get_db()
        row = db.execute(
            "SELECT email, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row or not check_password(password, row["password_hash"]):
            return jsonify({"error": "invalid_credentials"}), 401
        token = create_token(email)
        return jsonify({"access_token": token}), 200

    @app.get("/me")
    def me():
        auth_header = request.headers.get("Authorization")
        token = parse_bearer_token(auth_header)
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        secret = os.environ.get("JWT_SECRET", "dev-secret")
        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token_expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid_token"}), 401
        email = payload.get("sub")
        if not isinstance(email, str):
            return jsonify({"error": "invalid_token"}), 401
        db = get_db()
        row = db.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            return jsonify({"error": "unauthorized"}), 401
        return jsonify({"email": row["email"]}), 200

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=8000, debug=False)
