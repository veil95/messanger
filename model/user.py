import re

from pydantic import BaseModel, Field, field_validator


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
    username: str
    displayname: str
    password_plaintext: str

user_instance = User()