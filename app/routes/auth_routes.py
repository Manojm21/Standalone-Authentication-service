from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timezone, timedelta
from app.config import settings
from app.auth import hash_password, verify_password, create_access_token, create_refresh_token, hash_refresh_token, generate_jti
from app.models import User, RefreshToken
from app.schema import UserCreate, UserLogin, UserResponse, Token, RefreshTokenRequest
from app.dependencies import get_db, get_current_user

router = APIRouter(tags=["Authentication"])

# response_model is a fastAPI route parameter definition for outgoing (to client) contract enforcement 
@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email_already_registered",
        )

    new_user = User(
        email=user.email,
        hashed_password=hash_password(user.password),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)

def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    db_user = (
        db.query(User)
        .filter(User.email == username)
        .first()
    )
    if not db_user or not verify_password(password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid_email_or_password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": str(db_user.id)})

    raw_refresh_token, hashed_refresh_token = create_refresh_token()

    db_refresh_token = RefreshToken(
        jti=generate_jti(),  # Unique identifier for this token
        user_id=db_user.id,
        token_hash=hashed_refresh_token,
        device_name=None,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)  # Set expiration as needed
    )

    db.add(db_refresh_token)
    db.commit()

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": raw_refresh_token}

# DI of get_current_user means this route requires authentication. If token is missing/invalid, user will get 401 before reaching route code.
@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/refresh", response_model=Token)
def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    hashed_token = hash_refresh_token(request.refresh_token)
    db_refresh_token = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_token, RefreshToken.revoked == False).first()
    # SQLite stores datetimes without timezone info (naive). We attach UTC back for comparison.
    if not db_refresh_token or db_refresh_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Revoke the old refresh token ROTATION
    db_refresh_token.revoked = True
    db.commit()

    # Create a new access token and refresh token
    access_token = create_access_token(data={"sub": str(db_refresh_token.user_id)})
    new_raw_refresh_token, new_hashed_refresh_token = create_refresh_token()

    #insert new refresh token into DB
    new_db_refresh_token = RefreshToken(
        jti=generate_jti(),
        user_id=db_refresh_token.user_id,
        token_hash=new_hashed_refresh_token,
        device_name=db_refresh_token.device_name,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(new_db_refresh_token)
    db.commit()

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": new_raw_refresh_token}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    hashed_token = hash_refresh_token(request.refresh_token)
    row = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_token, RefreshToken.revoked == False).first()
    if row:
        row.revoked = True
        db.commit()
    return