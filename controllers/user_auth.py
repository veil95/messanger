import re
from typing import Optional
from pwdlib import PasswordHash


class AuthController:
    def __init__(self):
        self.hashing = PasswordHash.recommended()

    def hash_password(self, password_plaintext: str) -> str:
        return self.hashing.hash(password_plaintext)

    def verify_password(self, password_plaintext: str, hashed_password: Optional[str]) -> bool:
        if not hashed_password:
            return False
        return self.hashing.verify(password_plaintext, hashed_password)



