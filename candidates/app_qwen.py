import os
import re
import sqlite3
from flask import Flask, request, g, jsonify
import bcrypt
import jwt
from datetime import datetime, timedelta


def create_app():
    app = Flask(__name__)

    def get_db():
        if 'db' not in g:
            g.db = sqlite3.connect(os.environ.get("AUTH_DB_PATH", "auth.db"))
            g.db.row_factory = sqlite3.Row
            ensure_schema(g.db)
        return g.db

    def ensure_schema(db):
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        db.commit()

    @app.teardown_appcontext
    def close_db(error):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    def validate_email(email):
        email = email.strip().lower()
        pattern = r'^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$'
        return re.fullmatch(pattern, email)

    def validate_password(password):
        if len(password) < 8:
            return False
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_letter and has_digit

    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        if not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400

        if not validate_password(password):
            return jsonify({"error": "Password must be at least 8 characters with at least one letter and one digit"}), 400

        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        try:
            db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                       (email, password_hash))
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Email already registered"}), 409

        return jsonify({}), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        db = get_db()
        row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if row is None or not bcrypt.checkpw(password.encode('utf-8'), row['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401

        secret = os.environ.get("JWT_SECRET", "dev-secret")
        payload = {
            "sub": row["id"],
            "exp": datetime.utcnow() + timedelta(seconds=900)
        }
        token = jwt.encode(payload, secret, algorithm="HS256")

        return jsonify({"access_token": token}), 200

    @app.route('/me', methods=['GET'])
    def me():
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing authorization header"}), 401

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"error": "Invalid authorization header"}), 401

        token = parts[1]
        secret = os.environ.get("JWT_SECRET", "dev-secret")

        try:
            payload = jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user_id = payload.get("sub")
        if not user_id:
            return jsonify({"error": "Invalid token"}), 401

        db = get_db()
        row = db.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return jsonify({"error": "User not found"}), 401

        return jsonify({"email": row["email"]}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)
