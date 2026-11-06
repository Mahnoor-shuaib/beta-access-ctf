import os
import json
import base64
import hmac
import hashlib
import secrets
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Flag: 24 characters in total. Override with the FLAG environment variable if needed.
FLAG = os.environ.get("FLAG", "CGS{n0n3_4lg_jwt_byp4ss}")

# Secret used to sign tokens for the HS256 path. Players never need this;
# the bug is that the server also accepts tokens that claim to need no secret at all.
SECRET = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.secret_key = SECRET  # needed for flash() messages
COOKIE_NAME = "session_token"

USERS = {
    "admin": {"hash": generate_password_hash(secrets.token_hex(16)), "role": "admin"},
}

CHANGELOG = [
    ("v0.9.4", "Added dark mode to the dashboard."),
    ("v0.9.3", "Fixed a crash when uploading large avatars."),
    ("v0.9.2", "Improved cold-start time by 30%."),
]

ADMIN_TOOLS = [
    "Feature flags: 12 active, 3 scheduled",
    "Crash reports: 0 open, all triaged",
    "Rollout: 100% of insiders on v0.9.4",
]


# ---------------------------------------------------------------------------
# Minimal JWT-style helper (header.payload.signature, base64url, no padding)
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(username, role):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": username, "role": role}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    s = b64url_encode(sig)
    return f"{h}.{p}.{s}"


class InvalidToken(Exception):
    pass


# VULNERABILITY: when the token's header claims alg "none", the server skips
# signature verification entirely and trusts the payload as-is.
def verify_token(token):
    try:
        h_part, p_part, s_part = token.split(".")
        header = json.loads(b64url_decode(h_part))
        payload = json.loads(b64url_decode(p_part))
    except Exception:
        raise InvalidToken("malformed token")

    alg = header.get("alg", "")

    if alg.lower() == "none":
        # Signature is not checked at all in this branch. The flaw is here.
        return payload

    if alg != "HS256":
        raise InvalidToken("unsupported algorithm")

    signing_input = f"{h_part}.{p_part}".encode()
    expected = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    actual = b64url_decode(s_part) if s_part else b""
    if not hmac.compare_digest(expected, actual):
        raise InvalidToken("bad signature")
    return payload


def current_payload():
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        return verify_token(token)
    except InvalidToken:
        return None


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if current_payload() is None:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


@app.context_processor
def inject_user():
    payload = current_payload()
    return {
        "current_user": payload.get("user") if payload else None,
        "current_role": payload.get("role") if payload else None,
    }


def message(title, text, status=200):
    return render_template("message.html", title=title, text=text), status


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/changelog")
def changelog():
    return render_template("changelog.html", entries=CHANGELOG)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 20) or not username.replace("_", "").isalnum():
            flash("Username must be 3-20 characters: letters, numbers, underscore.")
        elif len(password) < 4:
            flash("Password must be at least 4 characters.")
        elif username in USERS:
            flash("That username is taken.")
        else:
            USERS[username] = {"hash": generate_password_hash(password), "role": "tester"}
            flash("Account created. You can log in now.")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and check_password_hash(user["hash"], password):
            token = issue_token(username, user["role"])
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(COOKIE_NAME, token, samesite="Lax")
            return resp
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/insider")
@login_required
def insider():
    payload = current_payload()
    # The role check itself is correct. The weakness is how the role in the
    # token can be forged (see verify_token above).
    if payload.get("role") != "admin":
        return message("Access denied", "The insider tools are for admins only.", 403)
    return render_template("insider.html", tools=ADMIN_TOOLS, flag=FLAG)


@app.errorhandler(404)
def not_found(_):
    return message("Not found", "That page does not exist. Head back to the home page.", 404)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
