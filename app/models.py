from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from app.database import Base
from datetime import datetime, timezone

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    # This is a uuid4() string you'll generate when creating the token
    # But in your rotation design (Step 7), when you rotate, you create a new row with a new jti. The old row gets revoked=True. So the jti does change on rotation 
    # — it's per-token, not per-session. If you wanted a stable session ID across rotations, you'd need a separate session_id column.
    jti = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String,index=True, unique=True, nullable=False)
    device_name = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked= Column(Boolean, default=False)
    # Without the lambda, datetime.now() is evaluated once at import time and every row gets the same timestamp. The lambda makes it evaluate per insert.
    created_at = Column(DateTime(timezone=True), default= lambda:datetime.now(timezone.utc), nullable=False)