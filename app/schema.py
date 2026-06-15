# BaseModel defines the structure and validation rules for data.
# Typing = data type language
from pydantic import BaseModel, EmailStr, Field
from typing import Annotated

# It lets you attach extra metadata/constraints to a type.
PasswordType = Annotated[str, Field(min_length=8, max_length=72)]

# JSON request body (dict)

class UserCreate(BaseModel):
    email: EmailStr
    password:PasswordType

# JSON request body (dict)
class UserLogin(BaseModel):
    email: EmailStr
    password: PasswordType

#from_attributes = True is only needed on UserResponse because 
# it's the only schema that reads data from a SQLAlchemy model object.
class UserResponse(BaseModel):
    id: int
    email: EmailStr

# from_attributes = True tells Pydantic: "read values using obj.field_name instead of obj["field_name"]."
    class Config:
        from_attributes= True

# You return a plain dict
class Token(BaseModel):
    access_token: str
    token_type: str
    
