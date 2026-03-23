from datetime import datetime, timedelta
from fastapi import HTTPException, status
from os import getenv
from dotenv import load_dotenv
from jose import jwt

load_dotenv()

SECRET_KEY = getenv("SECRET_KEY")
ALGORITHM = getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(getenv("REFRESH_TOKEN_EXPIRE_DAYS"))


def create_refresh_token(username: str) -> str:
    data = {"sub": username}
    expire = datetime.utcnow() + timedelta(days = REFRESH_TOKEN_EXPIRE_DAYS)
    data.update({"exp": expire,
                 "type": "refresh_token"})
    return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)


def create_access_token(username: str) -> str:
    data = {"sub": username}
    expire = datetime.utcnow() + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire,
                 "type": "access_token"})
    return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = ALGORITHM)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=403, detail="invalid token")

def verify_access_token(token: str) -> bool:
    try:
        payload = jwt.decode(token, SECRET_KEY,algorithms=ALGORITHM)
        #ну а это проверка на нужный тип токена
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=401,
                detail="Invalid token type")
        #проверить существует ли username
        if "username" not in payload:
            raise HTTPException(
                status_code=403,
                detail="Invalid token payload")
        return True
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expired")
    #токен не действителен, подделан или еще пишут что истек, но тогда верхняя проверка не нужна? не понял в общем
    except jwt.JWTError:
        raise HTTPException(
            status_code=403,
            detail="Invalid Token")
