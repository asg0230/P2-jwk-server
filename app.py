from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from passlib.hash import argon2
import os
import uuid
import time
from functools import wraps

# Configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwks_server.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('NOT_MY_KEY', 'default_secret_key')

# Database setup
db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True)
    date_registered = db.Column(db.DateTime, default=db.func.now())
    last_login = db.Column(db.DateTime)

class AuthLog(db.Model):
    __tablename__ = 'auth_logs'
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String, nullable=False)
    request_timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# Utilities for AES encryption
def get_aes_key():
    key = os.environ.get('NOT_MY_KEY')
    if not key:
        raise RuntimeError("Encryption key is not set in the environment.")
    return key.encode('utf-8')

def aes_encrypt(data: str) -> bytes:
    key = get_aes_key()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'16bytesvector123'), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(encrypted_data: bytes) -> str:
    key = get_aes_key()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'16bytesvector123'), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode('utf-8')

# Rate limiter
def rate_limiter(max_requests, time_window):
    calls = {}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            client_ip = request.remote_addr

            if client_ip not in calls:
                calls[client_ip] = []
            calls[client_ip] = [t for t in calls[client_ip] if t > now - time_window]

            if len(calls[client_ip]) >= max_requests:
                return jsonify({"error": "Too Many Requests"}), 429

            calls[client_ip].append(now)
            return func(*args, **kwargs)

        return wrapper

    return decorator

# Endpoints
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error": "Username and email are required."}), 400

    generated_password = str(uuid.uuid4())
    password_hash = argon2.hash(generated_password)

    try:
        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Could not register user."}), 500

    return jsonify({"password": generated_password}), 201

@app.route('/auth', methods=['POST'])
@rate_limiter(max_requests=10, time_window=1)
def authenticate():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not argon2.verify(password, user.password_hash):
        return jsonify({"error": "Invalid credentials."}), 401

    auth_log = AuthLog(request_ip=request.remote_addr, user_id=user.id)
    db.session.add(auth_log)
    db.session.commit()

    return jsonify({"message": "Authentication successful."}), 200

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
