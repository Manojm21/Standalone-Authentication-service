from fastapi import Depends,HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from jose import ExpiredSignatureError
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.config import settings
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()
    
# Call /login and get access token.
# Call /me with Authorization: Bearer <token>.
# dependencies.py oauth2_scheme reads that header and extracts the token.
# get_current_user decodes token and loads the user.
# Also, in future it is not limited to /me. Any endpoint that uses Depends(get_current_user) becomes a later protected request using the same token pattern.


def get_current_user (token: str = Depends(oauth2_scheme),
db: Session = Depends(get_db),
) -> User:

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid_token",
        headers={"WWW-Authenticate": "Bearer"},)
    try:
        payload =jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        #  sub has the user id because when we created the token in auth.py, we put user id in sub claim. sub stands for subject and is a standard JWT claim for the principal that is the subject of the token. In our case, it's the user id.
        user_id= payload.get("sub")
        token_type = payload.get("type")


        if user_id is None or token_type!="access":
            raise credentials_exception

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="expired_token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except JWTError:
        raise credentials_exception


    user = (db.query(User)
        .filter(User.id == user_id)
        .first())
    if user is None:
        raise credentials_exception

    return user
    
