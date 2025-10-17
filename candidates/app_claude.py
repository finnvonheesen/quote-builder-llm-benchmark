import os
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import bcrypt
import jwt
from flask import Flask, request, jsonify, g


def create_app() -> Flask:
    app = Flask(__name__)
    
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
    
    def validate_email(email: str) -> bool:
        email = email.strip().lower()
        pattern = r'^[A-Za-z0-9._%+-]{1,30}@[A-Za-z0-9.-]{1,30}\.[A-Za-z]{2,10}$'
        return bool(re.match(pattern, email))
    
    def validate_password(password: str) -> bool:
        if len(password) < 8:
            return False
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_letter and has_digit
    
    def hash_password(password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def generate_jwt(email: str) -> str:
        secret = os.environ.get("JWT_SECRET", "dev-secret")
        payload = {
            "email": email,
            "exp": datetime.utcnow() + timedelta(seconds=900)
        }
        return jwt.encode(payload, secret, algorithm="HS256")
    
    def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
        try:
            secret = os.environ.get("JWT_SECRET", "dev-secret")
            return jwt.decode(token, secret, algorithms=["HS256"])
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
        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({"error": "Email and password are required"}), 400
            
            email = data['email'].strip().lower()
            password = data['password']
            
            if not validate_email(email):
                return jsonify({"error": "Invalid email format"}), 400
            
            if not validate_password(password):
                return jsonify({"error": "Password must be at least 8 characters with at least one letter and one digit"}), 400
            
            db = get_db()
            
            existing_user = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            
            if existing_user:
                return jsonify({"error": "Email already exists"}), 409
            
            password_hash = hash_password(password)
            
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, password_hash)
            )
            db.commit()
            
            return jsonify({"message": "User created successfully"}), 201
            
        except Exception:
            return jsonify({"error": "Invalid request"}), 400
    
    @app.route('/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                return jsonify({"error": "Email and password are required"}), 400
            
            email = data['email'].strip().lower()
            password = data['password']
            
            db = get_db()
            user = db.execute(
                "SELECT email, password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()
            
            if not user or not verify_password(password, user['password_hash']):
                return jsonify({"error": "Invalid credentials"}), 401
            
            access_token = generate_jwt(user['email'])
            
            return jsonify({"access_token": access_token}), 200
            
        except Exception:
            return jsonify({"error": "Invalid request"}), 400
    
    @app.route('/me', methods=['GET'])
    def me():
        try:
            token = extract_bearer_token()
            if not token:
                return jsonify({"error": "Authorization header required"}), 401
            
            payload = decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            
            return jsonify({"email": payload['email']}), 200
            
        except Exception:
            return jsonify({"error": "Invalid request"}), 401
    
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)

