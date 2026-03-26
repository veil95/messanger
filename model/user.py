import re
from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class User:
    def __init__(self):
        self.users_db = {}

    def create_user(self, username: str, hashed_password: str, display_name: str) -> dict:
        self.users_db[username] = {"hashed_password": hashed_password,
                                   "displayname": display_name}
        return self.users_db[username]

    def user_exists(self, username: str) -> bool:
        return username in self.users_db

    def get_user(self, username: str) -> dict | None:
        return self.users_db.get(username)

    def get_hashed_password(self, username: str) -> Optional[str]:
        password = self.users_db[username]["hashed_password"]
        if password:
            return password
        return None


class UserLogin(BaseModel):
    username: str
    password: str


class UserRequestRegistation(BaseModel):
    username: str = Field(..., min_length=3, max_length=25, description="username должен быть от 3 до 25 символов")
    displayname: str = Field(..., min_length=1, max_length=30, description="Отображаемое имя должно быть от 1 до 30 символов")
    password_plaintext: str = Field(..., min_length=5, description="минимальная длина паролы должна быть 5 символов")

    @field_validator('username', mode='before')
    def valide_username(cls, value):
        if not re.match("^[a-zA-Z0-9_]+$", value):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="The username can only contain letters and numbers")
        if len(value) < 3 or len(value) > 25:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Username must be at least 3 characters and not exceed 25")
        return value

    @field_validator('password_plaintext', mode='before')
    def check_password(cls, value):
        if len(value) < 5:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="your password is too easy, password must be at least 5 characters long")
        return value


user_instance = User()