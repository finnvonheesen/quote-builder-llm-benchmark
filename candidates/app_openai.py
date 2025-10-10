import os
import re
import sqlite3
import datetime
from flask import Flask, request, jsonify, g, current_app
import bcrypt
import jwt

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate_email(email):
    if not isinstance(email, str):
        return False
    return bool(EMAIL_REGEX.match(email.strip()))

def validate_password(password):
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    return has_letter and has_digit

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(current_app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(app):
    with sqlite3.connect(app.config['DATABASE']) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)")
        conn.commit()

def create_app():
    app = Flask(__name__)
    app.config['DATABASE'] = os.environ.get('AUTH_DB_PATH', 'auth.db')
    app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'dev-secret')
    init_db(app)
    app.teardown_appcontext(close_db)

    @app.post('/signup')
    def signup():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid request'}), 400
        email = data.get('email')
        password = data.get('password')
        if not validate_email(email) or not validate_password(password):
            return jsonify({'error': 'Invalid email or password'}), 400
        email_norm = email.strip().lower()
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db = get_db()
        try:
            db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email_norm, pw_hash))
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already exists'}), 409
        return jsonify({'status': 'created'}), 201

    @app.post('/login')
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid request'}), 400
        email = data.get('email')
        password = data.get('password')
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({'error': 'Invalid credentials'}), 401
        email_norm = email.strip().lower()
        db = get_db()
        cur = db.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email_norm,))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Invalid credentials'}), 401
        if not bcrypt.checkpw(password.encode('utf-8'), row['password_hash'].encode('utf-8')):
            return jsonify({'error': 'Invalid credentials'}), 401
        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            'sub': row['email'],
            'iat': now,
            'exp': now + datetime.timedelta(seconds=900)
        }
        token = jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')
        return jsonify({'access_token': token}), 200

    @app.get('/me')
    def me():
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token = auth[7:].strip()
        try:
            payload = jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Unauthorized'}), 401
        email = payload.get('sub')
        if not isinstance(email, str):
            return jsonify({'error': 'Unauthorized'}), 401
        db = get_db()
        cur = db.execute("SELECT email FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        if not row:
            return jsonify({'error': 'Unauthorized'}), 401
        return jsonify({'email': row['email']}), 200

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=8000, debug=False)
