import os
import re
import time
import uuid
import datetime as dt
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, join_room
from sqlalchemy import or_, and_
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IS_PROD = os.environ.get("RENDER") == "true"  # Render sets this automatically

# static_folder=None: the React build is served by the catch-all route at the bottom
app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # trust Render's proxy headers

# --- secrets: no insecure fallback in production
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    if IS_PROD:
        raise RuntimeError("SECRET_KEY environment variable is required in production.")
    SECRET_KEY = "dev-only-secret-not-for-production"
app.config["SECRET_KEY"] = SECRET_KEY

# --- database: Render gives postgres://, SQLAlchemy wants postgresql://
db_url = os.environ.get("DATABASE_URL", "sqlite:///chat.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- uploads
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 26 * 1024 * 1024  # 25 MB file + form overhead

MEDIA_TYPES = {
    ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image", ".webp": "image",
    ".mp4": "video", ".webm": "video", ".mov": "video",
}

FRONTEND_DIST = os.environ.get("FRONTEND_DIST", os.path.join(BASE_DIR, "frontend", "dist"))

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# In production only your own site may open a socket; in dev any origin is allowed.
allowed_origin = os.environ.get("APP_ORIGIN") or os.environ.get("RENDER_EXTERNAL_URL")
socketio = SocketIO(
    app,
    cors_allowed_origins=(allowed_origin if IS_PROD and allowed_origin else ("*" if not IS_PROD else None)),
    async_mode="threading",
)


# --------------------------------------------------------------------------- security headers
@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if IS_PROD:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' wss:; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    return resp


# --------------------------------------------------------------------------- models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(60), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {"id": self.id, "email": self.email, "username": self.username}


class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(10), default="pending")  # pending | accepted | rejected
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.Text, nullable=False, default="")
    media_url = db.Column(db.String(255))
    media_type = db.Column(db.String(10))  # 'image' | 'video'
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "text": self.text,
            "media_url": self.media_url,
            "media_type": self.media_type,
            "created_at": self.created_at.isoformat() + "Z",
        }


# --------------------------------------------------------------------------- helpers
online = {}  # user_id -> number of open connections (needs a single worker process)
sid_to_user = {}  # socket id -> user_id
_msg_hits = {}  # user_id -> recent send timestamps

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def too_fast(uid, limit=20, per=10):
    """Allow at most `limit` socket messages per `per` seconds for one user."""
    now = time.time()
    recent = [t for t in _msg_hits.get(uid, []) if now - t < per]
    if len(recent) >= limit:
        _msg_hits[uid] = recent
        return True
    recent.append(now)
    _msg_hits[uid] = recent
    return False


def sniff_kind(head):
    """Identify the real file type from its first bytes, not from its name."""
    if head.startswith(b"\xff\xd8\xff"):
        return "image"  # jpeg
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    if head[4:8] == b"ftyp":
        return "video"  # mp4 / mov
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return "video"  # webm
    return None


def make_token(user):
    payload = {"sub": str(user.id), "exp": dt.datetime.utcnow() + dt.timedelta(days=7)}
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token):
    try:
        data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        return db.session.get(User, int(data["sub"]))
    except Exception:
        return None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        user = decode_token(header.replace("Bearer ", "", 1)) if header else None
        if not user:
            return jsonify(error="Please log in again."), 401
        g.user = user
        return fn(*args, **kwargs)

    return wrapper


def pair_request(a_id, b_id):
    """The request between two users, in either direction."""
    return FriendRequest.query.filter(
        or_(
            and_(FriendRequest.sender_id == a_id, FriendRequest.receiver_id == b_id),
            and_(FriendRequest.sender_id == b_id, FriendRequest.receiver_id == a_id),
        )
    ).first()


def are_friends(a_id, b_id):
    fr = pair_request(a_id, b_id)
    return bool(fr and fr.status == "accepted")


def request_dict(fr):
    return {
        "id": fr.id,
        "sender": fr.sender.to_dict(),
        "receiver": fr.receiver.to_dict(),
        "created_at": fr.created_at.isoformat() + "Z",
    }


def notify(user_id, event, payload=None):
    socketio.emit(event, payload or {}, room=f"user_{user_id}")


def remove_media(messages):
    """Delete uploaded files belonging to these messages."""
    for m in messages:
        if m.media_url:
            try:
                os.remove(os.path.join(UPLOAD_DIR, os.path.basename(m.media_url)))
            except OSError:
                pass


@app.errorhandler(413)
def too_large(_e):
    return jsonify(error="File is too large (max 25 MB)."), 413


@app.errorhandler(429)
def rate_limited(_e):
    return jsonify(error="Too many attempts. Please wait a minute and try again."), 429


@app.get("/healthz")
def healthz():
    return "ok"


# --------------------------------------------------------------------------- auth routes
@app.post("/api/register")
@limiter.limit("5 per minute; 30 per hour")
def register():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    if not EMAIL_RE.match(email) or len(email) > 255:
        return jsonify(error="Enter a valid email address."), 400
    if not (1 <= len(username) <= 30):
        return jsonify(error="Username must be 1 to 30 characters."), 400
    if not (8 <= len(password) <= 128):
        return jsonify(error="Password must be 8 to 128 characters."), 400
    if User.query.filter_by(email=email).first():
        return jsonify(error="An account with this email already exists."), 409
    user = User(email=email, username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return jsonify(token=make_token(user), user=user.to_dict()), 201


@app.post("/api/login")
@limiter.limit("10 per minute; 50 per hour")
def login():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if not user or len(password) > 128 or not check_password_hash(user.password_hash, password):
        return jsonify(error="Incorrect email or password."), 401
    return jsonify(token=make_token(user), user=user.to_dict())


@app.get("/api/me")
@auth_required
def me():
    return jsonify(user=g.user.to_dict())


# --------------------------------------------------------------------------- friend routes
@app.post("/api/friends/request")
@limiter.limit("20 per hour")
@auth_required
def send_request():
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    target = User.query.filter_by(email=email).first()
    me_ = g.user
    if not target:
        return jsonify(error="No user found with that email."), 404
    if target.id == me_.id:
        return jsonify(error="You can't add yourself."), 400

    existing = pair_request(me_.id, target.id)
    if existing:
        if existing.status == "accepted":
            return jsonify(error="You are already friends."), 409
        if existing.status == "pending":
            if existing.sender_id == me_.id:
                return jsonify(error="Request already sent."), 409
            # They already asked us: sending a request back accepts theirs.
            existing.status = "accepted"
            db.session.commit()
            notify(target.id, "request_accepted", {"friend": me_.to_dict()})
            notify(me_.id, "friends_updated")
            return jsonify(message=f"You and {target.username} are now friends.", accepted=True)
        # previously rejected: allow a fresh request
        existing.sender_id, existing.receiver_id, existing.status = me_.id, target.id, "pending"
        existing.created_at = dt.datetime.utcnow()
        fr = existing
    else:
        fr = FriendRequest(sender_id=me_.id, receiver_id=target.id)
        db.session.add(fr)
    db.session.commit()

    notify(target.id, "friend_request", {"from": me_.to_dict()})
    return jsonify(message=f"Request sent to {target.username}.", request=request_dict(fr)), 201


@app.get("/api/friends/requests")
@auth_required
def incoming_requests():
    rows = FriendRequest.query.filter_by(receiver_id=g.user.id, status="pending").order_by(FriendRequest.created_at.desc())
    return jsonify(requests=[request_dict(r) for r in rows])


@app.get("/api/friends/requests/sent")
@auth_required
def sent_requests():
    rows = FriendRequest.query.filter_by(sender_id=g.user.id, status="pending").order_by(FriendRequest.created_at.desc())
    return jsonify(requests=[request_dict(r) for r in rows])


@app.post("/api/friends/requests/<int:req_id>/accept")
@auth_required
def accept_request(req_id):
    fr = db.session.get(FriendRequest, req_id)
    if not fr or fr.receiver_id != g.user.id or fr.status != "pending":
        return jsonify(error="Request not found."), 404
    fr.status = "accepted"
    db.session.commit()
    notify(fr.sender_id, "request_accepted", {"friend": g.user.to_dict()})
    notify(g.user.id, "friends_updated")
    return jsonify(friend=fr.sender.to_dict())


@app.post("/api/friends/requests/<int:req_id>/reject")
@auth_required
def reject_request(req_id):
    fr = db.session.get(FriendRequest, req_id)
    if not fr or fr.receiver_id != g.user.id or fr.status != "pending":
        return jsonify(error="Request not found."), 404
    fr.status = "rejected"
    db.session.commit()
    return jsonify(ok=True)


@app.get("/api/friends")
@auth_required
def list_friends():
    rows = FriendRequest.query.filter(
        FriendRequest.status == "accepted",
        or_(FriendRequest.sender_id == g.user.id, FriendRequest.receiver_id == g.user.id),
    ).all()
    friends = []
    for r in rows:
        other = r.receiver if r.sender_id == g.user.id else r.sender
        d = other.to_dict()
        d["online"] = online.get(other.id, 0) > 0
        last = Message.query.filter(
            or_(
                and_(Message.sender_id == g.user.id, Message.receiver_id == other.id),
                and_(Message.sender_id == other.id, Message.receiver_id == g.user.id),
            )
        ).order_by(Message.id.desc()).first()
        d["last_message"] = last.to_dict() if last else None
        friends.append(d)
    friends.sort(key=lambda f: f["last_message"]["created_at"] if f["last_message"] else "", reverse=True)
    return jsonify(friends=friends)


# --------------------------------------------------------------------------- chat history
@app.get("/api/messages/<int:friend_id>")
@auth_required
def history(friend_id):
    if not are_friends(g.user.id, friend_id):
        return jsonify(error="You can only chat with friends."), 403
    rows = Message.query.filter(
        or_(
            and_(Message.sender_id == g.user.id, Message.receiver_id == friend_id),
            and_(Message.sender_id == friend_id, Message.receiver_id == g.user.id),
        )
    ).order_by(Message.id.asc()).limit(500)
    return jsonify(messages=[m.to_dict() for m in rows])


@app.delete("/api/messages/<int:friend_id>")
@auth_required
def delete_chat(friend_id):
    """Delete the whole conversation with a friend (for both people)."""
    if not are_friends(g.user.id, friend_id):
        return jsonify(error="You can only manage chats with friends."), 403
    convo = Message.query.filter(
        or_(
            and_(Message.sender_id == g.user.id, Message.receiver_id == friend_id),
            and_(Message.sender_id == friend_id, Message.receiver_id == g.user.id),
        )
    )
    remove_media(convo.all())
    convo.delete(synchronize_session=False)
    db.session.commit()
    notify(friend_id, "chat_deleted", {"friend_id": g.user.id})
    return jsonify(ok=True)


@app.delete("/api/messages/item/<int:msg_id>")
@auth_required
def delete_message(msg_id):
    """Delete one of your own messages (for both people)."""
    m = db.session.get(Message, msg_id)
    if not m or m.sender_id != g.user.id:
        return jsonify(error="Message not found."), 404
    other = m.receiver_id
    remove_media([m])
    db.session.delete(m)
    db.session.commit()
    notify(other, "message_deleted", {"id": msg_id, "friend_id": g.user.id})
    return jsonify(ok=True)


# --------------------------------------------------------------------------- media upload
@app.post("/api/upload")
@limiter.limit("30 per hour")
@auth_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="No file selected."), 400
    ext = os.path.splitext(f.filename)[1].lower()
    kind = MEDIA_TYPES.get(ext)
    if not kind:
        return jsonify(error="Only images (jpg, png, gif, webp) and videos (mp4, webm, mov) are allowed."), 400
    # the file's real contents must match its extension
    head = f.stream.read(32)
    f.stream.seek(0)
    if sniff_kind(head) != kind:
        return jsonify(error="That file doesn't look like a valid image or video."), 400
    name = f"{g.user.id}_{uuid.uuid4().hex}{ext}"
    f.save(os.path.join(UPLOAD_DIR, name))
    return jsonify(url=f"/api/uploads/{name}", type=kind)


@app.get("/api/uploads/<filename>")
def serve_upload(filename):
    # send_from_directory blocks path traversal and supports Range requests (video seeking)
    return send_from_directory(UPLOAD_DIR, filename, max_age=86400)


# --------------------------------------------------------------------------- socket.io
@socketio.on("connect")
def on_connect(auth):
    token = (auth or {}).get("token", "")
    user = decode_token(token)
    if not user:
        return False  # reject connection
    sid_to_user[request.sid] = user.id
    join_room(f"user_{user.id}")
    online[user.id] = online.get(user.id, 0) + 1
    if online[user.id] == 1:
        socketio.emit("presence", {"user_id": user.id, "online": True})


@socketio.on("disconnect")
def on_disconnect(*_):
    uid = sid_to_user.pop(request.sid, None)
    if uid is None:
        return
    online[uid] = max(0, online.get(uid, 1) - 1)
    if online[uid] == 0:
        socketio.emit("presence", {"user_id": uid, "online": False})


@socketio.on("send_message")
def on_send_message(data):
    if not isinstance(data, dict):
        return {"ok": False}
    uid = sid_to_user.get(request.sid)
    to = data.get("to")
    text = str(data.get("text") or "").strip()
    media_url = data.get("media_url")
    media_type = None

    if not uid or not isinstance(to, int) or not are_friends(uid, to):
        return {"ok": False}
    if too_fast(uid):
        return {"ok": False, "error": "You're sending messages too fast."}

    if media_url:
        name = os.path.basename(str(media_url))
        ext = os.path.splitext(name)[1].lower()
        valid = (
            media_url == f"/api/uploads/{name}"
            and name.startswith(f"{uid}_")
            and ext in MEDIA_TYPES
            and os.path.isfile(os.path.join(UPLOAD_DIR, name))
        )
        if not valid:
            return {"ok": False}
        media_type = MEDIA_TYPES[ext]

    if not text and not media_url:
        return {"ok": False}

    msg = Message(sender_id=uid, receiver_id=to, text=text[:2000],
                  media_url=media_url, media_type=media_type)
    db.session.add(msg)
    db.session.commit()
    payload = msg.to_dict()
    socketio.emit("new_message", payload, room=f"user_{to}")
    socketio.emit("new_message", payload, room=f"user_{uid}")  # echo to all of sender's tabs
    return {"ok": True}


@socketio.on("typing")
def on_typing(data):
    if not isinstance(data, dict):
        return
    uid = sid_to_user.get(request.sid)
    to = data.get("to")
    if uid and isinstance(to, int) and are_friends(uid, to):
        notify(to, "typing", {"from": uid})


# --------------------------------------------------------------------------- serve the React build
@app.get("/", defaults={"path": ""})
@app.get("/<path:path>")
def spa(path):
    if path.startswith("api/") or path.startswith("socket.io"):
        return jsonify(error="Not found."), 404
    if path and os.path.isfile(os.path.join(FRONTEND_DIST, path)):
        return send_from_directory(FRONTEND_DIST, path)
    return send_from_directory(FRONTEND_DIST, "index.html")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    # local development only; on Render gunicorn starts the app (see start command)
    socketio.run(app, host="127.0.0.1", port=5000, debug=True, allow_unsafe_werkzeug=True)