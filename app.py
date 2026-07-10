import sqlite3, os
import secrets
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, abort, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "users.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


USERS = {
    "admin": {
        "password_hash": "scrypt:32768:8:1$1fJJeHZLARvCfYig$27820c0d0a2026f0dfcf226dc6287394868bd3ad32375874b26440b317ca00990e115e04232dd4ee393ba1e6aa3a9c4ccd1b4b6d4a49e15faf04e3424da59ce1",##将密码改成hash值，防止密码直接泄露
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "password_hash": "scrypt:32768:8:1$NgMEqNIPbiNsGfRy$7234bffe9c05d150c8d7a64b340a262c43514a52adb282a282f103dbf8b3d84997c6f5cde09ce8a69c8c236222cacfed2c6f71710930d64da5dfc300605cc47c",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)

    columns = [column[1] for column in cursor.execute("PRAGMA table_info(users)").fetchall()]
    if "balance" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
        cursor.execute("UPDATE users SET balance = 99999 WHERE username = 'admin'")
        cursor.execute("UPDATE users SET balance = 100 WHERE username = 'alice'")

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone, balance)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 99999)
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone, balance)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 100)
    """)
    conn.commit()
    conn.close()


init_db()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_csrf():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected_token = session.get("_csrf_token", "")
        submitted_token = request.form.get("csrf_token", "")

        if not expected_token or not submitted_token:
            abort(400, description="CSRF token missing")

        if not secrets.compare_digest(expected_token, submitted_token):
            abort(400, description="CSRF token invalid")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        username = session.get("username")
        if not username or username not in USERS:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def get_user(username):##新增一个函数，只部分返回用户信息
    user=USERS.get(username)
    if not user:
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    db_user = conn.execute(
        "SELECT id, balance FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    return {
        "id":db_user["id"] if db_user else None,
        "username":username,
        "phone":user["phone"],
        "email":user["email"],
        "balance":db_user["balance"] if db_user else user["balance"],
        "role":user["role"]
    }

@app.route("/")
def index():
    username = session.get("username")
    user = get_user(username) if username else None
    return render_template("index.html", user=user, keyword="", search_results=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    message = request.args.get("message", "")

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)

        if user and check_password_hash(user["password_hash"],password):##改为检验哈希值
            session.clear()
            session["username"] = username
            return redirect("/")

        error = "用户名或密码错误"

    return render_template("login.html", error=error, message=message)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        try:
            cursor.execute(sql)
            conn.commit()
            return redirect("/login?message=注册成功，请登录")
        except sqlite3.Error as e:
            error = str(e)
        finally:
            conn.close()

    return render_template("register.html", error=error)


@app.route("/search")
def search():
    username = session.get("username")
    user = get_user(username) if username else None
    keyword = request.args.get("keyword", "")
    search_results = []

    if keyword:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(sql)
        cursor.execute(sql)
        search_results = cursor.fetchall()
        conn.close()

    return render_template("index.html", user=user, keyword=keyword, search_results=search_results)


def get_profile_user(username):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    profile_user = conn.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    return profile_user


@app.route("/profile")
@login_required
def profile():
    profile_user = get_profile_user(session["username"])
    message = request.args.get("message", "")

    if not profile_user:
        return render_template("profile.html", profile_user=None), 404

    return render_template("profile.html", profile_user=profile_user, message=message)


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    username = session["username"]
    raw_amount = request.form.get("amount", "").strip()

    try:
        amount = Decimal(raw_amount)
        if not amount.is_finite():
            raise InvalidOperation
        amount = amount.quantize(Decimal("0.01"))
    except InvalidOperation:
        profile_user = get_profile_user(username)
        return render_template(
            "profile.html",
            profile_user=profile_user,
            error="充值金额格式错误",
        ), 400

    if amount <= 0:
        profile_user = get_profile_user(username)
        return render_template(
            "profile.html",
            profile_user=profile_user,
            error="充值金额必须大于 0",
        ), 400

    if amount > Decimal("100000"):
        profile_user = get_profile_user(username)
        return render_template(
            "profile.html",
            profile_user=profile_user,
            error="单次充值金额不能超过 100000",
        ), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(
        "UPDATE users SET balance = ROUND(balance + ?, 2) WHERE username = ?",
        (float(amount), username),
    )
    conn.commit()
    conn.close()

    if cursor.rowcount != 1:
        return "用户不存在", 404

    return redirect(url_for("profile", message="充值成功"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    error = None
    file_url = None
    filename = None

    if request.method == "POST":
        uploaded_file = request.files.get("avatar")

        if not uploaded_file or uploaded_file.filename == "":
            error = "请选择要上传的文件"
        else:
            filename = uploaded_file.filename
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            uploaded_file.save(save_path)
            file_url = url_for("static", filename=f"uploads/{filename}")

    return render_template("upload.html", error=error, file_url=file_url, filename=filename)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":##启动时不要默认 debug=True 和 0.0.0.0
    debug = os.environ.get("FLASK_DEBUG") == "1"##这个更改暂时没看懂
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(debug=debug, host=host, port=5000)
