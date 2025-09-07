from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from app.config import settings
from app.schemas.user import Token

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: str) -> str:
    to_encode = {"sub": user_id, "exp": datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def create_refresh_token(user_id: str) -> str:
    to_encode = {"sub": user_id, "exp": datetime.utcnow() + timedelta(minutes=settings.refresh_token_expire_minutes)}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

def get_token_response(access_token: str, refresh_token: str) -> Token:
    return Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )