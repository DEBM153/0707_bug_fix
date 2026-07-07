import os
import secrets

from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


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

def get_user(username):##新增一个函数，只部分返回用户信息
    user=USERS.get(username)
    if not user:
        return None

    return {
        "username":username,
        "phone":user["phone"],
        "email":user["email"],
        "balance":user["balance"],
        "role":user["role"]
    }

@app.route("/")
def index():
    username = session.get("username")
    user = get_user(username) if username else None
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)

        if user and check_password_hash(user["password_hash"],password):##改为检验哈希值
            session.clear()
            session["username"] = username
            return redirect("/")

        error = "用户名或密码错误"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":##启动时不要默认 debug=True 和 0.0.0.0
    debug = os.environ.get("FLASK_DEBUG") == "1"##这个更改暂时没看懂
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(debug=debug, host=host, port=5000)
