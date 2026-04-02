import os

# Secret key: generated once, saved to .secret_key file, never committed to GitHub.
# This means sessions survive server restarts without hardcoding anything.
_key_file = ".secret_key"
if os.path.exists(_key_file):
    with open(_key_file, "r") as f:
        SECRET_KEY = f.read().strip()
else:
    SECRET_KEY = os.urandom(32).hex()
    with open(_key_file, "w") as f:
        f.write(SECRET_KEY)

DATABASE = "pos.db"
PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
SESSION_FILE_DIR = ".flask_sessions"
SESSION_TYPE = "filesystem"
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = 3600
# Set PRODUCTION=true in environment to enforce HTTPS-only cookies
SESSION_COOKIE_SECURE = os.environ.get("PRODUCTION", "false").lower() == "true"
