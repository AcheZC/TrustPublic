import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import event, text
import bcrypt

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# --- DATABASE_URL normalizado para PyMySQL ---
raw_url = os.getenv("DATABASE_URL", "")
if raw_url.startswith("mysql://"):
    raw_url = raw_url.replace("mysql://", "mysql+pymysql://", 1)

u = urlparse(raw_url)
q = dict(parse_qsl(u.query, keep_blank_values=True))
for k in ("sslmode", "ssl_mode", "ssl"):
    q.pop(k, None)
raw_url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

app.config["SQLALCHEMY_DATABASE_URI"] = raw_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Evita agotar conexiones (límite 5) y activa SSL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 1,
    "max_overflow": 0,
    "pool_recycle": 240,
    "pool_pre_ping": True,
    "connect_args": {"ssl": {}},
}

db = SQLAlchemy(app)

# --------- Modelo ---------
class User(db.Model):
    __tablename__ = "users"
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(80),  nullable=False)
    handle   = db.Column(db.String(50),  nullable=False, unique=True, index=True)
    email    = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password = db.Column(db.String(120), nullable=False)  # guardaremos hash bcrypt
    code     = db.Column(db.String(120))

# --------- Healths ---------
@app.get("/health")
def health():
    return jsonify(ok=True)

@app.get("/db/health")
def db_health():
    with db.engine.connect() as c:
        ok = c.execute(text("SELECT 1")).scalar() == 1
    return {"ok": ok}

# --------- Init ---------
@app.get("/init-db")
def init_db():
    try:
        db.create_all()
        return jsonify(ok=True, msg="Tablas listas")
    except Exception as e:
        return (f"DB init error: {e}", 500)

# --------- Registro ---------
@app.post("/auth/register")
def register():
    data = request.get_json(force=True) or {}
    required = ["name", "handle", "email", "password"]
    if any(not data.get(k) for k in required):
        return ("Faltan campos", 400)
    if len(data["password"]) < 6:
        return ("Contraseña mínima 6 caracteres", 400)

    pw_hash = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    try:
        u = User(
            name=data["name"].strip(),
            handle=data["handle"].strip(),
            email=data["email"].strip().lower(),
            password=pw_hash,
            code=(data.get("code") or "").strip()
        )
        db.session.add(u)
        db.session.commit()
        return jsonify(ok=True, msg="Cuenta creada"), 201
    except IntegrityError:
        db.session.rollback()
        return ("Email o usuario ya registrados.", 409)
    except Exception as e:
        db.session.rollback()
        return (f"Error del servidor: {e}", 500)

# --------- Login ---------
@app.post("/auth/login")
def login():
    data = request.get_json(force=True) or {}
    if not data.get("login") or not data.get("password"):
        return ("Faltan campos", 400)

    login_id = data["login"].strip().lower()
    user = User.query.filter(
        (User.email == login_id) | (User.handle == login_id)
    ).first()

    if not user:
        return ("Credenciales inválidas", 401)

    if not bcrypt.checkpw(data["password"].encode("utf-8"), user.password.encode("utf-8")):
        return ("Credenciales inválidas", 401)

    # Aquí luego generaremos token/sesión; por ahora OK simple
    return jsonify(ok=True, user={"id": user.id, "name": user.name, "handle": user.handle, "email": user.email})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
