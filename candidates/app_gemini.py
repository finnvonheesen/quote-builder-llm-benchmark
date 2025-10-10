
import os
import re
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, g

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
DB_PATH = os.environ.get("AUTH_DB_PATH", "auth.db")
JWT_EXPIRATION_SECONDS = 900
JWT_ALGORITHM = "HS256"

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$")

def is_valid_email(email):
    return isinstance(email, str) and EMAIL_REGEX.match(email)

def is_valid_password(password):
    return isinstance(password, str) and PASSWORD_REGEX.match(password)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            try:
                auth_header = request.headers["Authorization"]
                token_type, token = auth_header.split()
                if token_type.lower() != "bearer":
                    raise ValueError("Invalid token type")
            except ValueError:
                return jsonify({"message": "Invalid authorization header format"}), 401

        if not token:
            return jsonify({"message": "Token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            db = get_db()
            current_user = db.execute(
                "SELECT * FROM users WHERE email = ?", (data["sub"],)
            ).fetchone()
            if not current_user:
                 return jsonify({"message": "User not found"}), 401
            g.user = dict(current_user)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid"}), 401
        
        return f(*args, **kwargs)

    return decorated

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = JWT_SECRET

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)

    @app.route("/signup", methods=["POST"])
    def signup():
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"message": "Email and password are required"}), 400

        email = data.get("email")
        password = data.get("password")

        if not is_valid_email(email):
            return jsonify({"message": "Invalid email format"}), 400
        
        if not is_valid_password(password):
            return jsonify({"message": "Password must be at least 8 characters long and contain at least one letter and one number"}), 400

        db = get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            return jsonify({"message": "Email already exists"}), 409

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        
        try:
            db.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hashed_password.decode("utf-8")),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"message": "Email already exists"}), 409
        except Exception:
            return jsonify({"message": "Could not create user"}), 500

        return jsonify({"message": "User created successfully"}), 201

    @app.route("/login", methods=["POST"])
    def login():
        data = request.get_json()
        if not data or "email" not in data or "password" not in data:
            return jsonify({"message": "Invalid credentials"}), 401

        email = data.get("email")
        password = data.get("password")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return jsonify({"message": "Invalid credentials"}), 401

        payload = {
            "sub": user["email"],
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(seconds=JWT_EXPIRATION_SECONDS),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

        return jsonify({"access_token": token}), 200

    @app.route("/me", methods=["GET"])
    @token_required
    def get_me():
        if "user" not in g:
            return jsonify({"message": "Authentication error"}), 401
        
        return jsonify({"email": g.user["email"]}), 200
        
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8000, debug=False)

