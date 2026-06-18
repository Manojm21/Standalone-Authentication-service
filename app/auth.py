from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import bcrypt
from typing import Optional
from app.config import settings

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
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt