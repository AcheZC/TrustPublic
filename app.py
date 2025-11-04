import os
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

# 🔓 En modo desarrollo: permitir todas las conexiones (evita error "Failed to fetch")
# Luego, cuando todo funcione, cambiamos "*" por los dominios específicos
CORS(app, resources={r"/*": {"origins": "*"}})

@app.get("/health")
def health():
    return jsonify(ok=True)

@app.post("/auth/register")
def register():
    data = request.get_json(force=True) or {}
    required = ["name", "handle", "email", "password"]
    if any(not data.get(k) for k in required):
        return ("Faltan campos", 400)
    # MOCK: aún sin base de datos, solo confirma que llegó bien
    return jsonify(ok=True, msg="Cuenta creada (mock)."), 201

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
