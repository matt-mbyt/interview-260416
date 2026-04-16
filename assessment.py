"""
SecureAsset – Internal Asset Management API
============================================
This service allows security team members to search the asset inventory,
run basic network diagnostics, and validate internal service API keys.

Candidate task: Review this code for security issues. For each issue found,
describe the vulnerability, explain how it could be exploited, and suggest
a fix.
"""

from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import subprocess
import pickle
import base64
import jwt
import requests as http
import os

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "1234567890")

GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# ---------------------------------------------------------------------------
# Authorized users — update this list when people join or leave the team.
# ---------------------------------------------------------------------------
AUTHORIZED_EMAILS = [
    "jsmith@company.com",
    "alee@company.com",
    "bwong@company.com",
    "mgarcia@company.com",
    "contractor.dan@gmail.com",
]

INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "1234567890")

VALID_CRITICALITY = {"low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect("/var/db/assets.db")
    conn.row_factory = sqlite3.Row
    return conn


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        token = header.removeprefix("Bearer ").strip()
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user = payload
        except jwt.PyJWTError:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@app.route("/auth/login", methods=["POST"])
def login():
    """Exchange a Google OAuth access token for a service session token."""
    body = request.get_json(silent=True) or {}
    google_token = body.get("google_token", "")

    # Verify the token with Google and retrieve the user's profile.
    resp = http.get(GOOGLE_USERINFO_URL, headers={"Authorization": f"Bearer {google_token}"})
    if resp.status_code != 200:
        return jsonify({"error": "Invalid Google token"}), 401

    email = resp.json().get("email", "").lower()

    if email not in AUTHORIZED_EMAILS:
        return jsonify({"error": "Access denied"}), 403

    token = jwt.encode(
        {"sub": email, "exp": datetime.utcnow() + timedelta(hours=8)},
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token})


@app.route("/users/me", methods=["GET"])
@require_auth
def get_current_user():
    return jsonify({
        "email": request.user.get("sub"),
        "session_expires": datetime.utcfromtimestamp(request.user.get("exp")).isoformat(),
    })


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@app.route("/assets", methods=["POST"])
@require_auth
def create_asset():
    body = request.get_json(silent=True) or {}
    name = body.get("name", "").strip()
    owner = body.get("owner", "").strip()
    criticality = body.get("criticality", "").strip().lower()

    if not name or not owner:
        return jsonify({"error": "name and owner are required"}), 400
    if criticality not in VALID_CRITICALITY:
        return jsonify({"error": f"criticality must be one of {sorted(VALID_CRITICALITY)}"}), 400

    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO assets (name, owner, criticality) VALUES (?, ?, ?)",
        (name, owner, criticality),
    )
    conn.commit()
    asset_id = cursor.lastrowid
    conn.close()
    return jsonify({"id": asset_id, "name": name, "owner": owner, "criticality": criticality}), 201


@app.route("/assets/<int:asset_id>", methods=["GET"])
@require_auth
def get_asset(asset_id):
    conn = get_db()
    row = conn.execute(
        "SELECT id, name, owner, criticality FROM assets WHERE id = ?",
        (asset_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "Asset not found"}), 404
    return jsonify(dict(row))


@app.route("/assets/search", methods=["GET"])
@require_auth
def search_assets():
    term = request.args.get("q", "")
    conn = get_db()
    rows = conn.execute(
        f"SELECT id, name, owner, criticality FROM assets WHERE name LIKE '%{term}%'"
    ).fetchall()
    conn.close()
    return jsonify({"results": [dict(r) for r in rows]})


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route("/reports/generate", methods=["POST"])
@require_auth
def generate_report():
    body = request.get_json(silent=True) or {}

    # filter_config is a base64-encoded serialized ReportFilter object,
    # allowing callers to pass complex filter criteria in a single field.
    raw = base64.b64decode(body.get("filter_config", "e30="))
    config = pickle.loads(raw)

    criticality = config.get("criticality", "low")
    owner = config.get("owner", "")

    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, owner, criticality FROM assets WHERE criticality = ? AND owner = ?",
        (criticality, owner),
    ).fetchall()
    conn.close()
    return jsonify({"results": [dict(r) for r in rows]})


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

@app.route("/diagnostics/ping", methods=["POST"])
@require_auth
def ping_host():
    body = request.get_json(silent=True) or {}
    host = body.get("host", "")
    output = subprocess.check_output(f"ping -c 3 {host}", shell=True, timeout=10)
    return jsonify({"output": output.decode()})


# ---------------------------------------------------------------------------
# Internal key validation
# ---------------------------------------------------------------------------

@app.route("/internal/validate-key", methods=["POST"])
@require_auth
def validate_api_key():
    body = request.get_json(silent=True) or {}
    provided = body.get("key", "")
    if provided == INTERNAL_API_KEY:
        return jsonify({"valid": True})
    return jsonify({"valid": False})


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
