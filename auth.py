"""
auth.py
Owner: Abdallah Hanoosh (100749026)
"""

from flask import Blueprint, request, session, redirect, render_template, flash, abort
from functools import wraps
from datetime import datetime
import bcrypt
import hashlib
import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

import database as db
import crypto

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# RBAC decorator
# ---------------------------------------------------------------------------

def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect("/login")
            if session.get("role") not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@auth_bp.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    role     = request.form.get("role", "")

    import re
    # Username: alphanumeric and underscores only, 3-30 chars (whitelisting per Lec09)
    if not re.match(r'^[\w]{3,30}$', username):
        flash("Username must be 3-30 characters and contain only letters, numbers, and underscores.", "danger")
        return render_template("register.html")

    # Password: minimum 8 chars, must contain a letter and a number
    if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
        flash("Password must be at least 8 characters and contain at least one letter and one number.", "danger")
        return render_template("register.html")

    if not username or not password or not role:
        flash("All fields are required.", "danger")
        return render_template("register.html")

    if password != confirm:
        flash("Passwords do not match.", "danger")
        return render_template("register.html")

    if role not in ("purchaser", "supervisor", "orders_dept"):
        flash("Invalid role.", "danger")
        return render_template("register.html")

    if db.get_user_by_username(username):
        flash("Username already taken.", "danger")
        return render_template("register.html")

    # 1. Hash password with bcrypt
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # 2. Generate RSA-2048 key pair
    key = RSA.generate(2048)
    pub_pem  = key.publickey().export_key().decode()
    priv_pem = key.export_key().decode()

    # 3. Derive AES key from password using PBKDF2
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)

    # 4. Encrypt private key with AES-GCM
    cipher = AES.new(derived, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(priv_pem.encode())
    enc_priv = base64.b64encode(salt + cipher.nonce + tag + ct).decode()

    # 5. Store in DB
    try:
        db.insert_user(username, pw_hash, role, pub_pem, enc_priv)
    except Exception:
        flash("Registration failed due to a server error. Please try again.", "danger")
        return render_template("register.html")

    flash("Account created. Please log in.", "success")
    return redirect("/login")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = db.get_user_by_username(username)

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        flash("Invalid username or password.", "danger")
        return render_template("login.html")

    # Decrypt private key into session memory
    try:
        priv_pem = crypto.decrypt_private_key(user["encrypted_private_key"], password)
    except Exception:
        flash("Failed to decrypt private key. Try again.", "danger")
        return render_template("login.html")

    session.permanent = True
    session["user_id"]               = user["id"]
    session["username"]              = user["username"]
    session["role"]                  = user["role"]
    session["decrypted_private_key"] = priv_pem

    db.write_audit_log(user["id"], "login")
    return redirect("/dashboard")


@auth_bp.route("/logout")
def logout():
    db.write_audit_log(session.get("user_id"), "logout")
    session.clear()
    return redirect("/login")


@auth_bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    role = session.get("role")
    if role == "purchaser":
        return redirect("/dashboard/purchaser")
    elif role == "supervisor":
        return redirect("/dashboard/supervisor")
    elif role == "orders_dept":
        return redirect("/dashboard/orders")
    return redirect("/login")
