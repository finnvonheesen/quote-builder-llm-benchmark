import os
import re
import sqlite3
import bcrypt
import jwt
import functools
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, g

DB_PATH = os.environ.get("AUTH_DB_PATH", "auth.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
TOKEN_EXPIRATION_SECONDS = 900
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
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

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isalpha() for char in password):
        return False
    return True

def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT email FROM users WHERE email = ?", (data['sub'],))
            current_user = cursor.fetchone()
            if not current_user:
                return jsonify({"error": "User not found"}), 401
            g.current_user_email = current_user['email']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        
        return f(*args, **kwargs)
    return decorated

def create_app():
    app = Flask(__name__)
    app.config['DATABASE'] = DB_PATH
    app.config['JWT_SECRET'] = JWT_SECRET

    init_db()
    app.teardown_appcontext(close_db)

    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password are required"}), 400

        email = data['email']
        password = data['password']

        if not isinstance(email, str) or not EMAIL_REGEX.match(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        if not isinstance(password, str) or not is_valid_password(password):
            return jsonify({"error": "Password must be at least 8 characters long and contain at least one letter and one digit"}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, hashed_password.decode('utf-8'))
            )
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Email already exists"}), 409
        
        return jsonify({"message": "User created successfully"}), 201

    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"error": "Email and password are required"}), 400

        email = data['email']
        password = data['password']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT email, password_hash FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({"error": "Invalid credentials"}), 401
        
        exp_time = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_EXPIRATION_SECONDS)
        
        token = jwt.encode({
            'sub': user['email'],
            'iat': datetime.now(timezone.utc),
            'exp': exp_time
        }, app.config['JWT_SECRET'], algorithm="HS256")

        return jsonify({"access_token": token}), 200

    @app.route('/me', methods=['GET'])
    @token_required
    def me():
        return jsonify({"email": g.current_user_email}), 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=8000, debug=False)
