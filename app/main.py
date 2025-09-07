from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.routers import auth, oauth
from app.config import settings

app = FastAPI(title=settings.app_name, debug=settings.debug)

# Add SessionMiddleware for OAuth
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(oauth.router, prefix="/auth/oauth", tags=["oauth"])

@app.get("/")
async def root():
    return {"message": "Auth System is running!"}