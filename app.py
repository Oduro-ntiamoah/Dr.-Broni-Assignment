import hashlib
import os
import time
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy

import config

API_KEY = config.API_KEY

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "ESCA_DATABASE_URI", "sqlite:///esca.db")
app.config["SECRET_KEY"] = os.environ.get("ESCA_SECRET_KEY", "dev-secret-change-me")
db = SQLAlchemy(app)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128), unique=True, nullable=False)
    last_seen = db.Column(db.Float, default=0)
    first_seen = db.Column(db.Float, default=time.time)

    def last_seen_str(self):
        return datetime.fromtimestamp(self.last_seen).strftime("%Y-%m-%d %H:%M:%S") if self.last_seen else "never"

    def is_online(self):
        return (time.time() - self.last_seen) < 90 if self.last_seen else False


class AllowlistEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_hash = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(256))
    publisher = db.Column(db.String(256))
    added_at = db.Column(db.Float, default=time.time)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(128))
    timestamp = db.Column(db.Float)
    event_type = db.Column(db.String(32))     # allowed | violation | heartbeat
    process_name = db.Column(db.String(256))
    pid = db.Column(db.Integer, nullable=True)
    file_path = db.Column(db.String(512), nullable=True)
    file_hash = db.Column(db.String(64), nullable=True)
    action_taken = db.Column(db.String(64))
    detail = db.Column(db.Text, nullable=True)

    def timestamp_str(self):
        return datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.headers.get("X-API-Key") != API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def _check_web_auth(username, password):
    """Optional simple auth for the web UI (configure via ESCA_WEB_USER/PASS)."""
    if not config.WEB_USER:
        return True  # auth disabled
    return username == config.WEB_USER and password == config.WEB_PASS


def require_web_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not config.WEB_USER:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_web_auth(auth.username, auth.password):
            return (
                jsonify({"error": "authentication required"}),
                401,
                {"WWW-Authenticate": 'Basic realm="ESCA Dashboard"'},
            )
        return f(*args, **kwargs)
    return wrapper


def touch_device(device_id):
    device = Device.query.filter_by(device_id=device_id).first()
    if not device:
        device = Device(device_id=device_id, first_seen=time.time())
        db.session.add(device)
    device.last_seen = time.time()
    db.session.commit()


# ---------------------------------------------------------------------------
# Agent-facing API
# ---------------------------------------------------------------------------

@app.route("/api/allowlist", methods=["GET"])
@require_api_key
def api_get_allowlist():
    entries = {e.file_hash: {"name": e.name, "publisher": e.publisher} for e in AllowlistEntry.query.all()}
    return jsonify({"entries": entries})


@app.route("/api/report", methods=["POST"])
@require_api_key
def api_report_event():
    data = request.get_json(force=True)
    touch_device(data.get("device_id", "unknown"))

    event = Event(
        device_id=data.get("device_id"),
        timestamp=data.get("timestamp", time.time()),
        event_type=data.get("event_type"),
        process_name=data.get("process_name"),
        pid=data.get("pid"),
        file_path=data.get("file_path"),
        file_hash=data.get("file_hash"),
        action_taken=data.get("action_taken"),
        detail=data.get("detail", ""),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def api_heartbeat():
    data = request.get_json(force=True)
    touch_device(data.get("device_id", "unknown"))
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Dashboard UI
# ---------------------------------------------------------------------------

@app.route("/")
@require_web_auth
def index():
    return redirect(url_for("devices_view"))


@app.route("/devices")
@require_web_auth
def devices_view():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template("devices.html", devices=devices)


@app.route("/events")
@require_web_auth
def events_view():
    device_filter = request.args.get("device")
    query = Event.query
    if device_filter:
        query = query.filter_by(device_id=device_filter)
    events = query.order_by(Event.timestamp.desc()).limit(200).all()
    devices = Device.query.all()
    return render_template("events.html", events=events, devices=devices, selected_device=device_filter)


@app.route("/allowlist", methods=["GET", "POST"])
@require_web_auth
def allowlist_view():
    if request.method == "POST":
        file_hash = request.form.get("file_hash", "").strip().lower()
        name = request.form.get("name", "").strip()
        publisher = request.form.get("publisher", "").strip()

        if len(file_hash) != 64:
            flash("Hash must be a 64-character SHA-256 hex string.", "error")
        elif AllowlistEntry.query.filter_by(file_hash=file_hash).first():
            flash("This hash is already on the allowlist.", "error")
        else:
            entry = AllowlistEntry(file_hash=file_hash, name=name, publisher=publisher)
            db.session.add(entry)
            db.session.commit()
            flash(f"Added '{name}' to the allowlist.", "success")
        return redirect(url_for("allowlist_view"))

    entries = AllowlistEntry.query.order_by(AllowlistEntry.added_at.desc()).all()
    return render_template("allowlist.html", entries=entries)


@app.route("/allowlist/delete/<int:entry_id>", methods=["POST"])
@require_web_auth
def allowlist_delete(entry_id):
    entry = AllowlistEntry.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    flash(f"Removed '{entry.name}' from the allowlist.", "success")
    return redirect(url_for("allowlist_view"))


# ---------------------------------------------------------------------------
# Utility: compute hash of an uploaded file, to help populate the allowlist
# ---------------------------------------------------------------------------

@app.route("/allowlist/hash-tool", methods=["GET", "POST"])
@require_web_auth
def hash_tool():
    computed_hash = None
    filename = None
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded:
            filename = uploaded.filename
            sha256 = hashlib.sha256()
            for chunk in iter(lambda: uploaded.read(65536), b""):
                sha256.update(chunk)
            computed_hash = sha256.hexdigest()
    return render_template("hash_tool.html", computed_hash=computed_hash, filename=filename)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("=" * 60)
    print("ESCA Dashboard")
    print(f"  Listening on    : {config.SERVER_HOST}:{config.SERVER_PORT}")
    print(f"  LAN URL for VMs : http://{config.LAN_IP}:{config.SERVER_PORT}")
    print(f"  Agent dashboard : {config.DASHBOARD_URL}")
    print(f"  API key         : {config.API_KEY}")
    if config.WEB_USER:
        print(f"  Web UI auth     : enabled (user: {config.WEB_USER})")
    else:
        print("  Web UI auth     : DISABLED (set ESCA_WEB_USER/ESCA_WEB_PASS to enable)")
    print("  Debug mode      : %s" % ("ON" if config.SERVER_DEBUG else "OFF"))
    print("=" * 60)
    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=config.SERVER_DEBUG)
