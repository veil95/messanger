from enum import Enum
from pydantic import BaseModel


class TokenTypeJWT(Enum):
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"


class TokenTransport(Enum):
    BEARER = "bearer"


class TokenJWT(BaseModel):
    type: TokenTypeJWT
    token: str
    transport: TokenTransport