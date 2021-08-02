
import base64
from typing import Optional
import hmac
import hashlib
from fastapi import FastAPI, Form, Cookie
import json
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "70e8a08fd89d113765859b1f25aeb819e63325e6a625023350b37456a4499b22"
PASSWORD_SALT = "a7eb6439db5bebf9bd9abf496c8a8635b74d36ab1d4123334ef1911f12a914c2"


def sign_data(data: str) -> str:
    """возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()
    

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return password_hash == stored_password_hash


users = {
    "alexey@user.com": {
        "name": "Алексей",
        "password": "666df7e7a77515f07c550fef57486d06190251a2c8d6647dc2ba2abba719891d",
        "balance": 100_000
    },
    "petr@user.com": {
        "name": "Петр",
        "password": "364f073179bf6bf1f0823d73d05845c68452dac69a70827c3fdddc66aede9370",
        "balance": 555_555
    }
}


@app.get('/')
def index():
    with open('templates/index.html', 'r') as f:
        login_page = f.read()
    return Response(login_page, media_type="text/html")

@app.get("/index2")
def index_page2(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except Exception:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']} "
        , media_type="text/html")
    

@app.post("/login")
def process_login_page(username: str = Form(...), password : str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я Вас не знаю!"
            }),
            media_type="application/json")
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br /> Балансе: {user['balance']}"
        }),
        media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response


@app.post("/logout")
def process_logout():

    with open('templates/loginpage.html', 'r') as f:
        login_page = f.read()
    response = Response(login_page, media_type="text/html")
    response.delete_cookie(key="username")


