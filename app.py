import os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
# Si vas a llamar desde Systeme.io y NO usas cookies, * está bien.
CORS(app, resources={r"/*": {"origins": "*"}})

# --- Normaliza DATABASE_URL para MySQL + PyMySQL ---
raw_url = os.getenv("DATABASE_URL", "")

# Asegura el driver correcto
if raw_url.startswith("mysql://"):
    raw_url = raw_url.replace("mysql://", "mysql+pymysql://", 1)

# Limpia parámetros que no entiende PyMySQL
u = urlparse(raw_url)
q = dict(parse_qsl(u.query, keep_blank_values=True))
for k in ("sslmode", "ssl_mode", "ssl"):  # quitamos todos
    q.pop(k, None)
raw_url = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

app.config["SQLALCHEMY_DATABASE_URI"] = raw_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Conexión robusta con pool mínimo y timeouts (evita cuelgues en planes gratis)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_size": 1,
    "max_overflow": 0,
    "pool_recycle": 240,
    "pool_pre_ping": True,
    "connect_args": {
        "ssl": {},              # muchos proveedores requieren TLS
        "connect_timeout": 5,
        "read_timeout": 5,
        "write_timeout": 5,
    },
}

db = SQLAlchemy(app)

# --------- Modelo ---------
class User(db.Model):
    __tablename__ = "users"
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(80),  nullable=False)
    handle   = db.Column(db.String(50),  nullable=False, unique=True, index=True)
    email    = db.Column(db.String(120), nullable=False, unique=True, index=True)
    password = db.Column(db.String(120), nullable=False)  # TODO: hash (cuando quieras)
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
    try:
        u = User(
            name=data["name"].strip(),
            handle=data["handle"].strip(),
            email=data["email"].strip().lower(),
            password=data["password"],  # TODO: reemplazar por hash cuando toque
            code=(data.get("code") or "").strip()
        )
        db.session.add(u)
        db.session.commit()
        return jsonify(ok=True, msg="Cuenta guardada en DB"), 201
    except IntegrityError:
        db.session.rollback()
        return ("Email o usuario ya registrados.", 409)
    except Exception as e:
        db.session.rollback()
        return (f"Error del servidor: {e}", 500)

# --------- SUMMARY (público, sin auth por ahora) ---------
@app.get("/api/summary")
def api_summary():
    # Placeholder del servidor (luego se hará real con la DB)
    data = {
        "out": 12,
        "in": 27,
        "wallet": 88,
        "feed": [
            {"who": "@Lingualux", "what": "+3",  "when": "hoy 10:15",  "type": "recibido"},
            {"who": "@Dany",      "what": "-2",  "when": "ayer 21:02", "type": "asignado"},
            {"who": "@ColegioX",  "what": "+10", "when": "ayer 18:40", "type": "recibido"},
        ]
    }
    # Anonimiza el emisor cuando es "recibido"
    for x in data["feed"]:
        if x.get("type") == "recibido":
            x["who"] = "Fuente anónima"
    return jsonify(ok=True, **data)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
