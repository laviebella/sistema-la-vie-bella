from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# ======================
# CONFIGURAÇÕES
# ======================
app.config["SECRET_KEY"] = "chave-super-secreta"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ======================
# MODELO
# ======================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# ======================
# FUNÇÃO DE PROTEÇÃO
# ======================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"erro": "Não autorizado"}), 401
        return f(*args, **kwargs)
    return decorated

# ======================
# ROTAS
# ======================

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return jsonify({"erro": "JSON inválido"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"erro": "Email e senha são obrigatórios"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"erro": "Usuário já existe"}), 400

    hashed_password = generate_password_hash(password)
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"mensagem": "Usuário criado com sucesso"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify({"erro": "JSON inválido"}), 400

    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"erro": "Credenciais inválidas"}), 401

    session["user_id"] = user.id

    return jsonify({"mensagem": "Login realizado com sucesso"})


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return jsonify({
        "mensagem": "Bem-vindo ao sistema La Vie Bella",
        "user_id": session["user_id"]
    })


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return jsonify({"mensagem": "Logout realizado com sucesso"})


# ======================
# START APP (SEMPRE POR ÚLTIMO)
# ======================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=10000)

