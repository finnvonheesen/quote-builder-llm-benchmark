import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

import bcrypt
import jwt
from flask import Flask, request, jsonify, g


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET", "dev-secret")
    app.config["BCRYPT_ROUNDS"] = int(os.environ.get("BCRYPT_ROUNDS", "12"))
    
    def ensure_schema(db: sqlite3.Connection) -> None:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        db.commit()
    
    def get_db() -> sqlite3.Connection:
        if 'db' not in g:
            db_path = os.environ.get("AUTH_DB_PATH", "auth.db")
            g.db = sqlite3.connect(db_path)
            g.db.row_factory = sqlite3.Row
            ensure_schema(g.db)
        return g.db
    
    @app.teardown_appcontext
    def close_db(error):
        db = g.pop('db', None)
        if db is not None:
            db.close()
    
    def validate_email(raw_email: Any) -> Optional[str]:
        if not isinstance(raw_email, str):
            return None
        email = raw_email.strip().lower()
        pattern = r'^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$'
        if re.fullmatch(pattern, email):
            if ".." in email: # Disallow consecutive dots anywhere in the email
                return None
            return email
        return None
    
    def validate_password(password: str) -> bool:
        if len(password) < 8:
            return False
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_letter and has_digit
    
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"])
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except (ValueError, TypeError):
            return False
    
    def generate_jwt(email: str) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": email, "iat": now, "exp": now + timedelta(seconds=900)
        }
        return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")
    
    def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
        try:
            return jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return None
    
    def extract_bearer_token() -> Optional[str]:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None
        
        parts = auth_header.split(' ', 1)
        if len(parts) != 2:
            return None
        
        if parts[0].lower() != 'bearer':
            return None
        
        return parts[1]
    
    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        email = validate_email(data.get("email"))
        password = data.get("password")

        if not email:
            return jsonify({"error": "Invalid email format"}), 400
        
        if not isinstance(password, str) or not validate_password(password):
            return jsonify({"error": "Password must be at least 8 characters with at least one letter and one digit"}), 400
        
        db = get_db()
        try:
            password_hash = hash_password(password)
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, password_hash)
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Email already exists"}), 409

        return jsonify({"message": "User created successfully"}), 201
    
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        email = validate_email(data.get("email"))
        password = data.get("password")

        if not email or not isinstance(password, str):
            return jsonify({"error": "Invalid credentials"}), 401

        db = get_db()
        user = db.execute(
            "SELECT email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
        
        if not user or not verify_password(password, user['password_hash']):
            return jsonify({"error": "Invalid credentials"}), 401
        
        access_token = generate_jwt(user['email'])
        return jsonify({"access_token": access_token}), 200
    
    @app.route('/me', methods=['GET'])
    def me():
        token = extract_bearer_token()
        if not token:
            return jsonify({"error": "Authorization header required"}), 401
        
        payload = decode_jwt(token)
        if not payload or "sub" not in payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        email = payload["sub"]
        db = get_db()
        user = db.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
        if not user:
            return jsonify({"error": "Invalid request"}), 401

        return jsonify({"email": user["email"]}), 200
    
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)
