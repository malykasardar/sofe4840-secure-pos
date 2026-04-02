import os
from flask import Flask
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import config
import database as db

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.permanent_session_lifetime = config.PERMANENT_SESSION_LIFETIME

# Server-side session config - private key stays on the server, never in the browser cookie
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = config.SESSION_FILE_DIR
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True  # signs the session ID cookie
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot read the cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" # CSRF mitigation
app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE  # HTTPS-only in production

os.makedirs(config.SESSION_FILE_DIR, exist_ok=True)
Session(app)

from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_SECRET_KEY"] = config.SECRET_KEY

# Rate limiting - prevents brute force on login and registration spam
limiter = Limiter(get_remote_address, app=app, default_limits=[])

from auth import auth_bp
from orders import orders_bp
app.register_blueprint(auth_bp)
app.register_blueprint(orders_bp)

# Apply rate limits to auth routes
limiter.limit("10 per minute")(app.view_functions["auth.login"])
limiter.limit("5 per minute")(app.view_functions["auth.register"])

# Generic error handlers - never expose stack traces to the user
@app.errorhandler(403)
def forbidden(e):
    from flask import render_template
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(e):
    from flask import render_template
    return render_template("error.html", code=404, message="Page not found."), 404

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Internal server error: %s", e)
    from flask import render_template
    return render_template("error.html", code=500, message="An internal error occurred."), 500

with app.app_context():
    db.init_db()

if __name__ == "__main__":
    # debug=False in all cases - debug mode exposes an interactive Python shell on errors
    app.run(debug=False)
