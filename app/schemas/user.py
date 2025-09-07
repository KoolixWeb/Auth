from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserLogin(UserBase):
    email: EmailStr = Field(..., alias="username")
    password: str

    class Config:
        validate_by_name = True  # Updated for Pydantic V2

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str | None = None