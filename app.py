# app.py
import os
import datetime as dt
from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from pymysql.cursors import DictCursor
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ========= Config =========
def env(name, default=None, cast=str):
    v = os.environ.get(name, default)
    if v is None:
        return None
    return cast(v) if cast and v != "" else v

DB_HOST = env("MYSQL_HOST")
DB_PORT = env("MYSQL_PORT", 3306, int)
DB_NAME = env("MYSQL_DB")
DB_USER = env("MYSQL_USER")
DB_PASS = env("MYSQL_PASSWORD")
SECRET_KEY = env("SECRET_KEY", "change-me-dev")
JWT_EXPIRES_HOURS = env("JWT_EXPIRES_HOURS", 72, int)
INITIAL_WALLET = env("INITIAL_WALLET", 100, int)

# ========= App & CORS =========
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["https://www.quantumsolutions.space", "https://quantumsolutions.space"]}})

# ========= DB helpers =========
def get_conn():
    """Conecta a MySQL con SSL opcional (MYSQL_SSL=1) y CA (MYSQL_SSL_CA)."""
    ssl_flag = os.environ.get("MYSQL_SSL") in ("1", "true", "TRUE")
    ssl_ca = os.environ.get("MYSQL_SSL_CA")  # opcional, p.ej. /etc/ssl/certs/ca-certificates.crt

    kwargs = dict(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS,
        database=DB_NAME, charset="utf8mb4", cursorclass=DictCursor,
        autocommit=True, connect_timeout=10
    )
    if ssl_flag:
        kwargs["ssl"] = {"ssl": {}}
        if ssl_ca:
            # Si tu proveedor requiere validar CA explícita
            kwargs["ssl"] = {"ca": ssl_ca}

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

# ========= Bootstrap (perezoso) =========
_BOOTSTRAPPED = False

def bootstrap():
    # users
    execute("""
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(120) NOT NULL,
      handle VARCHAR(80) UNIQUE,
      email VARCHAR(190) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)
    # trust_events
    execute("""
    CREATE TABLE IF NOT EXISTS trust_events (
      id BIGINT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      from_user BIGINT UNSIGNED NULL,
      to_user   BIGINT UNSIGNED NULL,
      amount INT NOT NULL,
      note VARCHAR(255) NULL,
      INDEX(from_user), INDEX(to_user)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # Normaliza tipos (por si existían distintos)
    try: execute("ALTER TABLE users MODIFY id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT;")
    except Exception: pass
    for col in ("id", "from_user", "to_user"):
        try: execute(f"ALTER TABLE trust_events MODIFY {col} BIGINT UNSIGNED{' NOT NULL' if col=='id' else ' NULL'};")
        except Exception: pass

    # Dropea FKs viejas incompatibles
    try:
        fks = query("""
            SELECT CONSTRAINT_NAME
            FROM information_schema.TABLE_CONSTRAINTS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME='trust_events' AND CONSTRAINT_TYPE='FOREIGN KEY'
        """, (DB_NAME,))
        for fk in fks:
            if fk["CONSTRAINT_NAME"] in ("fk_from", "fk_to"):
                try: execute(f"ALTER TABLE trust_events DROP FOREIGN KEY {fk['CONSTRAINT_NAME']};")
                except Exception: pass
    except Exception:
        pass

    # Crea FKs correctas si faltan
    def fk_exists(name):
        row = query("""
            SELECT 1 FROM information_schema.TABLE_CONSTRAINTS
            WHERE TABLE_SCHEMA=%s AND TABLE_NAME='trust_events'
              AND CONSTRAINT_TYPE='FOREIGN KEY' AND CONSTRAINT_NAME=%s
            LIMIT 1
        """, (DB_NAME, name), one=True)
        return bool(row)

    if not fk_exists("fk_from"):
        execute("""
            ALTER TABLE trust_events
            ADD CONSTRAINT fk_from FOREIGN KEY (from_user)
            REFERENCES users(id) ON DELETE SET NULL
        """)
    if not fk_exists("fk_to"):
        execute("""
            ALTER TABLE trust_events
            ADD CONSTRAINT fk_to FOREIGN KEY (to_user)
            REFERENCES users(id) ON DELETE SET NULL
        """)

def ensure_bootstrap():
    global _BOOTSTRAPPED
    if not _BOOTSTRAPPED:
        bootstrap()
        _BOOTSTRAPPED = True

# ========= JWT =========
def make_token(user_id, email, handle=None):
    exp = dt.datetime.utcnow() + dt.timedelta(hours=JWT_EXPIRES_HOURS)
    payload = {"sub": str(user_id), "email": email, "handle": handle, "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def auth_required(fn):
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

# ========= Utils =========
def clean_handle(s): return s.strip()[1:] if s and s.startswith("@") else (s.strip() if s else s)
def find_user_by_any(identifier):
    if not identifier: return None
    handle = clean_handle(identifier)
    if "@" in identifier and "." in identifier:
        u = query("SELECT * FROM users WHERE email=%s", (identifier,), one=True)
        if u: return u
    if handle:
        u = query("SELECT * FROM users WHERE handle=%s", (handle,), one=True)
        if u: return u
    return None

# ========= Health checks =========
@app.get("/health")
def health():
    # No toca la DB → Render lo usa para marcar "UP"
    return jsonify({"status": "ok"}), 200

@app.get("/ready")
def ready():
    # Toca DB sin mutar; útil para verificar conexión
    try:
        ensure_bootstrap()
        query("SELECT 1", one=True)
        return jsonify({"status": "ready"}), 200
    except Exception as e:
        return jsonify({"status": "degraded", "detail": str(e)}), 503

# ========= Rutas =========
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "trust-public", "time": dt.datetime.utcnow().isoformat()})

@app.post("/auth/register")
def register():
    ensure_bootstrap()
    d = request.get_json(force=True) or {}
    name, handle, email, pw = d.get("name","").strip(), clean_handle(d.get("handle","")), (d.get("email","") or "").lower().strip(), d.get("password","")
    if not all([name, handle, email, pw]): return jsonify({"error":"Datos incompletos"}),400
    if query("SELECT id FROM users WHERE email=%s",(email,),one=True): return jsonify({"error":"Email ya registrado"}),409
    uid=execute("INSERT INTO users(name,handle,email,password_hash) VALUES(%s,%s,%s,%s)", (name,handle,email,generate_password_hash(pw)))
    token=make_token(uid,email,handle)
    return jsonify({"ok":True,"user":{"id":uid,"name":name,"email":email,"handle":handle},"token":token})

@app.post("/auth/login")
def login():
    ensure_bootstrap()
    d=request.get_json(force=True) or {}
    email,pw=(d.get("email","") or "").lower().strip(), d.get("password","") or ""
    u=query("SELECT * FROM users WHERE email=%s",(email,),one=True)
    if not u or not check_password_hash(u["password_hash"],pw):
        return jsonify({"error":"Credenciales inválidas"}),401
    token=make_token(u["id"],u["email"],u.get("handle"))
    return jsonify({"token":token,"user":{"id":u["id"],"email":u["email"],"handle":u.get("handle"),"name":u.get("name")}})

@app.get("/api/summary")
@auth_required
def summary():
    ensure_bootstrap()
    sub=int(request.user["sub"])
    row_in = query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE to_user=%s",(sub,),one=True)
    row_out= query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE from_user=%s",(sub,),one=True)
    total_in  = int(row_in["s"] if row_in and row_in["s"] is not None else 0)
    total_out = int(row_out["s"] if row_out and row_out["s"] is not None else 0)
    wallet = max(0, INITIAL_WALLET - total_out)
    events=query("""
        SELECT te.created_at,fu.handle AS from_handle,fu.email AS from_email,
               tu.handle AS to_handle,tu.email AS to_email,te.amount, te.to_user
        FROM trust_events te
        LEFT JOIN users fu ON fu.id=te.from_user
        LEFT JOIN users tu ON tu.id=te.to_user
        WHERE te.from_user=%s OR te.to_user=%s
        ORDER BY te.created_at DESC LIMIT 10
    """,(sub,sub))
    feed=[{
        "who": f"{ev['from_handle'] or ev['from_email']} → {ev['to_handle'] or ev['to_email']}",
        "what": f"+{ev['amount']}" if ev["to_user"]==sub else f"-{ev['amount']}",
        "when": ev["created_at"].strftime("%Y-%m-%d %H:%M"),
        "type": "mov"
    } for ev in events]
    return jsonify({"out": total_out, "in": total_in, "wallet": wallet, "feed": feed})

@app.post("/api/assign")
@auth_required
def assign():
    ensure_bootstrap()
    sub=int(request.user["sub"])
    d=request.get_json(force=True) or {}
    to,amount=(d.get("to","") or "").strip(), int(d.get("amount") or 0)
    note=(d.get("note") or "").strip()[:255] or None
    if not to or amount<=0: return jsonify({"error":"Parámetros inválidos"}),400
    u_to=find_user_by_any(to)
    if not u_to: return jsonify({"error":"Destinatario no encontrado"}),404
    row_out=query("SELECT COALESCE(SUM(amount),0) AS s FROM trust_events WHERE from_user=%s",(sub,),one=True)
    wallet=max(0, INITIAL_WALLET - int(row_out["s"] or 0))
    if amount>wallet: return jsonify({"error":"Fondos de confianza insuficientes"}),400
    execute("INSERT INTO trust_events(from_user,to_user,amount,note) VALUES(%s,%s,%s,%s)",(sub,u_to["id"],amount,note))
    return jsonify({"success":True,"new_balance":wallet-amount})

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error":"Server error","detail": str(e)}),500

if __name__=="__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
