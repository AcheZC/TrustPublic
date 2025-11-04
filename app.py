import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Conexión a Clever Cloud (Render la lee de env)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# --------- Modelo ---------
class User(db.Model):
    __tablename__ = "users"
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(80),  nullable=False)
    handle   = db.Column(db.String(50),  nullable=False, unique=True)
    email    = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)  # TODO: hash
    code     = db.Column(db.String(120))

@app.get("/health")
def health():
    return jsonify(ok=True)

# Inicialización segura (manual)
@app.get("/init-db")
def init_db():
    try:
        db.create_all()
        return jsonify(ok=True, msg="Tablas listas")
    except Exception as e:
        # Devuelve el error para depurar si algo falla
        return (f"DB init error: {e}", 500)

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
            password=data["password"],  # TODO: hash
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
