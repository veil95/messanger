import re
from typing import Optional

from pwdlib import PasswordHash


class AuthController:
    def __init__(self):
        self.hashing = PasswordHash.recommended()
    def hash_password(self, password_plaintext: str) -> str:
        return self.hashing.hash(password_plaintext)

    def verify_password(self, password_plaintext: str, hashed_password: Optional[str]) -> bool:
        if hashed_password is None:
            return False
        return self.hashing.verify(password_plaintext, hashed_password)

    def valide_username(self, username: str) -> bool:
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return False
        return True
    def check_username_len(self, username: str) -> bool:
        if len(username) < 3:
            return False
        return True

    def check_password_len(self, password_plainttext: str) -> bool:
        if len(password_plainttext) < 5:
            return False
        return True



