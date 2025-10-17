
import os
import re
import sqlite3
import time
from functools import wraps
from typing import Any, Callable

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
TOKEN_EXPIRATION_SECONDS = 900
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$")
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JWT_SECRET"] = JWT_SECRET

    def ensure_schema(db: sqlite3.Connection):
        cursor = db.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """
        )
        db.commit()

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            db_path = os.environ.get("AUTH_DB_PATH", "auth.db")
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
            ensure_schema(g.db)
        return g.db

    @app.teardown_appcontext
    def close_db(e: Exception | None = None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def token_required(f: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return jsonify({"error": "Authorization header is missing"}), 401

            parts = auth_header.split()
            if parts[0].lower() != "bearer" or len(parts) != 2:
                return jsonify({"error": "Invalid Authorization header format"}), 401

            token = parts[1]
            try:
                payload = jwt.decode(
                    token, app.config["JWT_SECRET"], algorithms=["HS256"]
                )
                email = payload["sub"]
                db = get_db()
                user = db.execute(
                    "SELECT email FROM users WHERE email = ?", (email,)
                ).fetchone()
                if not user:
                    return jsonify({"error": "User not found"}), 401
                g.user = user
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token has expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401

            return f(*args, **kwargs)

        return decorated

    @app.route("/signup", methods=["POST"])
    def signup():
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "Email and password are required"}), 400

        email = str(data["email"]).strip().lower()
        password = str(data["password"])

        if not EMAIL_REGEX.fullmatch(email):
            return jsonify({"error": "Invalid email format"}), 400
        if not PASSWORD_REGEX.fullmatch(password):
            return jsonify(
                {
                    "error": "Password must be at least 8 characters long and contain at least one letter and one number"
                }
            ), 400

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hashed_password),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Email address already in use"}), 409

        return jsonify({}), 201

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"error": "Email and password are required"}), 400

        email = str(data["email"]).strip().lower()
        password = str(data["password"])

        db = get_db()
        user = db.execute(
            "SELECT email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not user or not bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"]
        ):
            return jsonify({"error": "Invalid email or password"}), 401

        payload = {
            "sub": user["email"],
            "iat": int(time.time()),
            "exp": int(time.time()) + TOKEN_EXPIRATION_SECONDS,
        }
        token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")

        return jsonify({"access_token": token})

    @app.route("/me", methods=["GET"])
    @token_required
    def me():
        return jsonify({"email": g.user["email"]})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)

