import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, g
import bcrypt
import jwt

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def is_valid_email(email):
    return isinstance(email, str) and bool(EMAIL_REGEX.match(email))


def is_valid_password(password):
    return isinstance(password, str) and len(password) >= 8 and re.search(r"[A-Za-z]", password) and re.search(r"\d", password)


def get_bearer_token(header_value):
    if not header_value or not isinstance(header_value, str):
        return None
    parts = header_value.strip().split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def create_app():
    app = Flask(__name__)
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "dev-secret")
    app.config["AUTH_DB_PATH"] = os.environ.get("AUTH_DB_PATH", "auth.db")

    def init_db():
        path = app.config["AUTH_DB_PATH"]
        conn = sqlite3.connect(path)
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
            )
            conn.commit()
        finally:
            conn.close()

    init_db()

    def get_db():
        db = getattr(g, "_db", None)
        if db is None:
            db = sqlite3.connect(app.config["AUTH_DB_PATH"])
            db.row_factory = sqlite3.Row
            g._db = db
        return db

    @app.teardown_appcontext
    def close_db(exception):
        db = getattr(g, "_db", None)
        if db is not None:
            db.close()

    def json_error(message, status):
        return jsonify({"error": message}), status

    @app.post("/signup")
    def signup():
        if not request.is_json:
            return json_error("Invalid request", 400)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Invalid request", 400)
        email = data.get("email")
        password = data.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return json_error("Invalid email or password", 400)
        email = email.strip().lower()
        if not is_valid_email(email) or not is_valid_password(password):
            return json_error("Invalid email or password format", 400)
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db = get_db()
        try:
            db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
            db.commit()
        except sqlite3.IntegrityError:
            return json_error("Email already exists", 409)
        return jsonify({}), 201

    @app.post("/login")
    def login():
        if not request.is_json:
            return json_error("Invalid request", 400)
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return json_error("Invalid request", 400)
        email = data.get("email")
        password = data.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return json_error("Invalid request", 400)
        email = email.strip().lower()
        if not is_valid_email(email):
            return json_error("Invalid credentials", 401)
        db = get_db()
        row = db.execute("SELECT password_hash FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            return json_error("Invalid credentials", 401)
        stored_hash = row["password_hash"]
        try:
            if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
                return json_error("Invalid credentials", 401)
        except Exception:
            return json_error("Invalid credentials", 401)
        now = datetime.now(timezone.utc)
        payload = {
            "sub": email,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=900)).timestamp()),
        }
        token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
        return jsonify({"access_token": token}), 200

    @app.get("/me")
    def me():
        auth_header = request.headers.get("Authorization")
        token = get_bearer_token(auth_header)
        if not token:
            return json_error("Unauthorized", 401)
        try:
            payload = jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return json_error("Token expired", 401)
        except jwt.InvalidTokenError:
            return json_error("Unauthorized", 401)
        email = payload.get("sub")
        if not isinstance(email, str) or not is_valid_email(email):
            return json_error("Unauthorized", 401)
        return jsonify({"email": email}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)
