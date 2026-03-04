import time
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from pwdlib import PasswordHash
from jose import jwt
from datetime import timedelta, datetime


SECRET_KEY = "very_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

app = FastAPI()
users_db = {} # фейк база данных с пользователя {username: {"hashed_password", "displayname"}}
login_attempts = {} # {username: {"attempts", "last_attempt_time"}}
hashing = PasswordHash.recommended()
login_attempts = {}  # {username: {attempts, last_attempt_time}}


class UserLogin(BaseModel):
    username: str
    password: str

class UserRequestRegistation(BaseModel):
    displayname: str
    username: str
    password_plaintext: str

def hash_password(password_plaintext: str) -> str:
    return hashing.hash(password_plaintext)

def verify_password(password_plaintext: str, hashed_password: str) -> bool:
    return hashing.verify(password_plaintext, hashed_password)

def create_access_token(username: str) -> str:
    data = {"sub": username}
    expire = datetime.utcnow() + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire,
                 "type": "access_token"})
    return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)



def check_rate_limit(username: str) -> bool:
    current_time = time.time()

    if username not in login_attempts:
        login_attempts[username] = {"attempts": 0, "last_attempt_time": current_time}
        return True

    user_attempts = login_attempts[username]

    if current_time - user_attempts["last_attempt_time"] > 60:
        user_attempts["attempts"] = 0
        user_attempts["last_attempt_time"] = current_time
        return True


    if user_attempts["attempts"] <= 5:
        return True
    return False

def increment_login_attempt(username: str):
    if username not in login_attempts:
        login_attempts[username] = {"attempts": 1, "last_attempt_time": time.time()}
    else:
        login_attempts[username]["attempts"] += 1
        login_attempts[username]["last_attempts_time"] = time.time()


@app.get("/")
async def root():
    return {"message": "server work"}


@app.post("/auth/login")
async def login(user: UserLogin):
    if user.username not in users_db:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Incorrect login or password"
        )
    if not check_rate_limit(user.username):
        raise HTTPException(
            status_code = status.HTTP_429_TOO_MANY_REQUESTS,
            detail = "Too many login attempts. Please try again later"
        )

    increment_login_attempt(user.username)

    access_token = create_access_token(user.username)

    return {"access_token": access_token, "type": "bearer"}



@app.post("/auth/register")
async def register(user_data: UserRequestRegistation):
    if user_data.username in users_db:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "username is already registered"
        )
    if len(user_data.password_plaintext) < 5:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "your password is too easy, password must be at least 5 characters long"
        )
    if len(user_data.username) < 3:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "username must be at least 3 characters long"
        )

    hashed_password = hash_password(user_data.password_plaintext)

    users_db[user_data.username] = {
        "hashed_password": hashed_password,
        "displayname": user_data.displayname
    }

    return {"message": "пользователь создан"}



