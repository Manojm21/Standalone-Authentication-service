from pydantic import BaseModel, EmailStr, Field
from typing import Annotated

PasswordType = Annotated[str, Field(min_length=8, max_length=72)]


class UserCreate(BaseModel):
    email: EmailStr
    password:PasswordType

class UserLogin(BaseModel):
    email: EmailStr
    password: PasswordType

class UserResponse(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes= True

class Token(BaseModel):
    access_token: str
    token_type: str
    
