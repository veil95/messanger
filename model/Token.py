from datetime import datetime, timedelta
from os import getenv
from dotenv import load_dotenv
from jose import jwt

load_dotenv()

SECRET_KEY = getenv("SECRET_KEY")
ALGORITHM = getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(getenv("REFRESH_TOKEN_EXPIRE_DAYS"))

def create_access_token(username: str) -> str:
    data = {"sub": username}
    expire = datetime.utcnow() + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire,
                 "type": "access_token"})
    return jwt.encode(data, SECRET_KEY, algorithm = ALGORITHM)