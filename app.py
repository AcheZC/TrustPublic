# app.py
import os
import datetime as dt

from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from pymysql.cursors import DictCursor
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Config desde entorno
# =========================
def env(name, default=None, cast=str):
    v = os.environ.get(name, default)
    if v is None:
        return None
    return cast(v) if cast and v != "" else v

DB_HOST = env("MYSQL_HOST", "localhost")
DB_PORT = env("MYSQL_PORT", 3306, int)
DB_NAME = env("MYSQL_DB", "trustdb")
DB_USER = env("MYSQL_USER", "root")
DB_PASS = env("MYSQL_PASSWORD", "")
SECRET_KEY = env("SECRET_KEY", "change-me-dev")
JWT_EXPIRES_HOURS = env("JWT_EXPIRES_HOURS", 72, int)
INITIAL_WALLET = env("INITIAL_WALLET", 100, int)

# =========================
# App & CORS
# =========================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://www.quantumsolutions.space", "https://quantumsolutions.space"]}})

# =========================
# DB helpers (con SSL/timeout)
# =========================
def get_conn():
    """Conecta a MySQL con soporte opcional de SSL (MYSQL_SSL=1) y timeout."""
    ssl_flag = os.environ.get("MYSQL_SSL") in ("1", "true", "TRUE")
    kwargs = dict(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4", cursorclass=DictCursor,
        autocommit=True, connect_timeout=10
    )
    if ssl_flag:
        # Render/PlanetScale/Railway suelen aceptar dict vacío para activar TLS
        kwargs["ssl"] = {"ssl": {}}
    return pymysql.connect(**kwargs)

def query(sql, params=None, one=False):
    with get_conn() as cn, cn.cursor() as cur:
        cur.execute(sql, params or ())
        rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows

def execute(sql, params=None):
    with get_conn() as cn, cn.cursor() as cur:
        cur.execute(sql, params or ())
        cn.commit()
        return cur.lastrowid

# =========================
# Bootstrap (crea tablas si no existen)
# =========================
def bootstrap():
    execute("""
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(120) NOT NULL,
      handle VARCHAR(80) UNIQUE,
      email VARCHAR(190) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    execute("""
    CREATE TABLE IF NOT EXISTS trust_events (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      from_user BIGINT NULL,
      to_user   BIGINT NULL,
      amount INT NOT NULL,
      note VARCHAR(255) NULL,
      INDEX(from_user), INDEX(to_user),
      CONSTRAINT fk_from FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE SET NULL,
      CONSTRAINT fk_to   FOREIGN KEY (to_user)   REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

bootstrap()

# =========================
# JWT helpers
# =========================
def make_token(user_id, email, handle=None):
    exp = dt.datetime.utcnow() + dt.timedelta(hours=JWT_EXPIRES_HOURS)
    payload = {"sub": str(user_id), "email": email, "handle": handle, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def auth_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        request.user = payload
        return fn(*args, **kwargs)
    return wrapper

# =========================
# Utils
# =========================
def clean_handle(s: str):
    if not s: return None
    s = s.strip()
    if s.startswith("@"): s = s[1:]
    return s or None

def find_user_by_any(identifier: str):
    """Busca por handle o email."""
    if not identifier: return None
    handle = clean_handle(identifier)
    if "@" in identifier and "." in identifier:
        u = query("SELECT * FROM users WHERE email=%s", (identifier,), one=True)
        if u: return u
    if handle:
        u = query("SELECT * FROM users WHERE handle=%s", (handle,), one=True)
        if u: return u
    return None

# =========================
# Health
# =========================
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "trust-public", "time": dt.datetime.utcnow().isoformat()})

# =========================
# Auth: Register / Login
# =========================
@app.post("/auth/register")
def auth_register():
    data = request.get_json(force=True, silent=True) or {}
    name   = (data.get("name") or "").strip()
    handle = clean_handle(data.get("handle") or "")
    email  = (data.get("email") or "").strip().lower()
    pw     = data.get("password") or ""

    if not name or not email or not pw or not handle:
        return jsonify({"error": "Datos incompletos"}), 400

    if query("SELECT id FROM users WHERE email=%s", (email,), one=True):
        return jsonify({"error": "Email ya registrado"}), 409
    if handle and query("SELECT id FROM users WHERE handle=%s", (handle,), one=True):
        return jsonify({"error": "Usuario ya existe"}), 409

    uid = execute(
        "INSERT INTO users(name,handle,email,password_hash) VALUES(%s,%s,%s,%s)",
        (name, handle, email, generate_password_hash(pw))
    )
    token = make_token(uid, email, handle)
    return jsonify({"ok": True, "user": {"id": uid, "name": name, "email": email, "handle": handle}, "token": token})

def _login_impl():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    pw    = data.get("password") or ""
    if not email or not pw:
        return jsonify({"error": "Email y contraseña requeridos"}), 400
    u = query("SELECT * FROM users WHERE email=%s", (email,), one=True)
    if not u or not check_password_hash(u["password_hash"], pw):
        return jsonify({"error": "Credenciales inválidas"}), 401
    token = make_token(u["id"], u["email"], u.get("handle"))
    user_payload = {"id": u["id"], "email": u["email"], "handle": u.get("handle"), "name": u.get("name")}
    return jsonify({"token": token, "user": user_payload})

@app.post("/auth/login")
def auth_login():
    return _login_impl()

@app.post("/api/login")
def api_login():
    return _login_impl()

# =========================
# Summary
# =========================
@app.get("/api/summary")
@auth_required
def api_summary():
    sub = int(request.user["sub"])

    row_in  = query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE to_user=%s", (sub,), one=True)
    row_out = query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE from_user=%s", (sub,), one=True)

    total_in  = int(row_in["s"] if row_in and row_in["s"] is not None else 0)
    total_out = int(row_out["s"] if row_out and row_out["s"] is not None else 0)

    wallet = max(0, INITIAL_WALLET - total_out)

    events = query(
        """
        SELECT te.id, te.created_at,
               fu.handle AS from_handle, fu.email AS from_email,
               tu.handle AS to_handle,   tu.email AS to_email,
               te.amount, te.note
        FROM trust_events te
        LEFT JOIN users fu ON fu.id = te.from_user
        LEFT JOIN users tu ON tu.id = te.to_user
        WHERE te.from_user=%s OR te.to_user=%s
        ORDER BY te.created_at DESC
        LIMIT 10
        """,
        (sub, sub)
    )

    summary = [
        f"Asignaste {total_out} tokens.",
        f"Recibiste {total_in} tokens.",
        f"Wallet disponible: {wallet}."
    ]

    feed = []
    for ev in events:
        who = ev["from_handle"] or ev["from_email"] or "—"
        to  = ev["to_handle"]   or ev["to_email"]   or "—"
        ev_type = "recibido" if ev["to_email"] or ev["to_handle"] else "mov"
        feed.append({
            "who": f"{who} → {to}",
            "what": f"{('+' if (ev['to_email'] or ev['to_handle']) else '-')}{ev['amount']}",
            "when": ev["created_at"].strftime("%Y-%m-%d %H:%M"),
            "type": ev_type
        })

    return jsonify({
        "out": total_out,
        "in": total_in,
        "wallet": wallet,
        "feed": feed,
        "trust_available": wallet,
        "reliability_total": total_in,
        "summary": summary,
        "events": [
            {
                "created_at": ev["created_at"].isoformat(),
                "type": "assign" if ev["from_email"] else "receive",
                "from": ev["from_email"] or ev["from_handle"],
                "to": ev["to_email"] or ev["to_handle"],
                "amount": ev["amount"],
                "note": ev["note"] or ""
            } for ev in events
        ]
    })

# =========================
# Assign
# =========================
@app.post("/api/assign")
@auth_required
def api_assign():
    sub = int(request.user["sub"])
    data = request.get_json(force=True, silent=True) or {}

    to = (data.get("to") or "").strip()
    amount = int(data.get("amount") or 0)
    note = (data.get("note") or "").strip()[:255] or None

    if not to or amount <= 0:
        return jsonify({"error": "Parámetros inválidos"}), 400

    u_to = find_user_by_any(to)
    if not u_to:
        return jsonify({"error": "Destinatario no encontrado"}), 404

    row_out = query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE from_user=%s", (sub,), one=True)
    total_out = int(row_out["s"] if row_out and row_out["s"] is not None else 0)
    wallet = max(0, INITIAL_WALLET - total_out)
    if amount > wallet:
        return jsonify({"error": "Fondos de confianza insuficientes"}), 400

    execute(
        "INSERT INTO trust_events(from_user,to_user,amount,note) VALUES(%s,%s,%s,%s)",
        (sub, u_to["id"], amount, note)
    )

    new_wallet = wallet - amount
    return jsonify({"success": True, "new_balance": new_wallet})

# =========================
# Error handlers
# =========================
@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error", "detail": str(e)}), 500

# =========================
# Local run
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
