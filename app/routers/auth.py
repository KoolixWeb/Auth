from fastapi import APIRouter, HTTPException, status, Depends, Form
from app.database import users_collection
from app.schemas.user import UserCreate, UserLogin, Token
from app.utils.security import hash_password, verify_password, create_access_token, create_refresh_token, get_token_response
from bson import ObjectId
from jose import jwt, JWTError
from app.config import settings
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import logging

router = APIRouter(prefix="/auth", tags=["auth"])
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

@router.post("/register", response_model=Token)
async def register(user: UserCreate):
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    hashed_password = hash_password(user.password)
    user_dict = {
        "email": user.email,
        "hashed_password": hashed_password,
        "oauth_provider": None,
        "oauth_id": None
    }
    result = await users_collection.insert_one(user_dict)
    user_id = str(result.inserted_id)
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    return get_token_response(access_token, refresh_token)

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    logger.info(f"Login request payload: {form_data.__dict__}")
    user = UserLogin(email=form_data.username, password=form_data.password)
    logger.info(f"Parsed UserLogin: {user.dict(by_alias=True)}")
    db_user = await users_collection.find_one({"email": user.email})
    if not db_user or db_user.get("oauth_provider"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or use OAuth login",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = str(db_user["_id"])
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    return get_token_response(access_token, refresh_token)

@router.post("/login-json", response_model=Token)
async def login_json(user: UserLogin):
    logger.info(f"Login JSON request payload: {user.dict(by_alias=True)}")
    db_user = await users_collection.find_one({"email": user.email})
    if not db_user or db_user.get("oauth_provider"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or use OAuth login",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = str(db_user["_id"])
    access_token = create_access_token(user_id)
    refresh_token = create_refresh_token(user_id)
    return get_token_response(access_token, refresh_token)

@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    try:
        payload = jwt.decode(refresh_token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        new_access_token = create_access_token(user_id)
        new_refresh_token = create_refresh_token(user_id)
        return get_token_response(new_access_token, new_refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        try:
            user = await users_collection.find_one({"_id": ObjectId(user_id)})
        except ValueError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user ID format")
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

@router.get("/me", response_model=dict)
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "email": current_user["email"],
        "oauth_provider": current_user.get("oauth_provider"),
        "oauth_id": current_user.get("oauth_id")
    }