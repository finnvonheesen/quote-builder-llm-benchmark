import os
import re
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from email_validator import validate_email, EmailNotValidError
import sqlite3

app = Flask(__name__)
jwt_secret = os.getenv("JWT_SECRET", "dev-secret")
db_path = os.getenv("AUTH_DB_PATH", "auth.db")

@app.before_first_request
def init_db():
    from sqlite3 import connect
    conn = connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT)''')
    conn.commit()
    conn.close()

def validate_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(char.isalpha() for char in password)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Invalid request"}), 400

    try:
        validate_email(email)
    except EmailNotValidError:
        return jsonify({"error": "Invalid email format"}), 400

    if not validate_password(password):
        return jsonify({"error": "Password must be at least 8 characters long and include both letters and numbers"}), 400

    from sqlite3 import connect
    conn = connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, generate_password_hash(password)))
        conn.commit()
        return jsonify({"message": "User created successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Invalid request"}), 400

    from sqlite3 import connect
    conn = connect(db_path)
    cursor = conn.cursor()
    cursor.execute('SELECT id, password_hash FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user and check_password_hash(user[1], password):
        token = jwt.encode({'id': user[0]}, jwt_secret, algorithm='HS256', expires_in=900)
        return jsonify({"access_token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/me', methods=['GET'])
def me():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing token"}), 401

    token = auth_header.split()[1]

    try:
        data = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        user_id = data['id']

        from sqlite3 import connect
        conn = connect(db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

        if user:
            return jsonify({"email": user[0]}), 200
        else:
            return jsonify({"error": "User not found"}), 401

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8000, debug=False)