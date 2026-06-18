from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import bcrypt
from typing import Optional
from app.config import settings
import secrets, hashlib

# decode is to convert back to string/original data from Base64 encoded string. encode is to convert to Base64 encoded string from original data/string.
def hash_password(password:str)-> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# bcrypt.checkpw expects both inputs as bytes.
def verify_password(plain_password:str, hashed_password:str)-> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

# Input:
# data={"sub":"12"}
# ACCESS_TOKEN_EXPIRE_MINUTES=30
# Output payload becomes roughly:
# {"sub":"12","exp":<utc_now_plus_30m>}
# Then it is signed and serialized to JWT string.
#expires_delta is optional custom lifetime. If omitted, default minutes from env is used.
def create_access_token(data:dict, expires_delta:Optional[timedelta]=None)-> str:
    # Makes a copy so original input isn’t mutated.
    to_encode=data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    # Adds JWT standard expiration claim. This means token is invalid after this timestamp. this exp is added in the payload of the JWT.
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt
# secrets.token_urlsafe(32) — generates a cryptographically secure random string (URL-safe base64, 256 bits of entropy). This is your raw refresh token that gets sent to the client.

# hashlib.sha256(token.encode()).hexdigest() — produces the hash you store in the DB.
def create_refresh_token()-> tuple[str, str]:
    raw_token= secrets.token_urlsafe(32)
    hashed_token= hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, hashed_token

def hash_refresh_token(raw_token:str)-> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()

def generate_jti()-> str:
    return secrets.token_hex(16)  # Generates a 32-character hex string (128 bits of entropy)

