from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from httpx import AsyncClient
import logging
import secrets
from app.config import settings
from app.database import users_collection
from app.utils.security import create_access_token, get_token_response
from app.schemas.user import Token

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

router = APIRouter()

# OAuth setup
oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.google_client_id,
    client_secret=settings.google_client_secret,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    client_kwargs={
        'scope': settings.google_scopes,
    },
    authorize_params={
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'consent',
    }
)

@router.get("/login/google")
async def login_google(request: Request):
    redirect_uri = settings.google_redirect_uri
    try:
        # Generate and store state
        state = secrets.token_urlsafe(16)
        request.session['oauth_state'] = state
        logger.debug(f"Initiating Google OAuth with redirect_uri: {redirect_uri}, State: {state}")
        redirect_response = await oauth.google.authorize_redirect(request, redirect_uri, state=state)
        logger.debug(f"Authorization redirect URL: {redirect_response.headers.get('location')}")
        return redirect_response
    except Exception as e:
        logger.error(f"Error in login_google: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate Google OAuth: {str(e)}"
        )

@router.get("/google/callback")
async def callback_google(request: Request):
    try:
        # Log full callback URL and states
        logger.debug(f"Callback URL: {str(request.url)}")
        query_state = request.query_params.get('state')
        session_state = request.session.get('oauth_state')
        logger.debug(f"Query state: {query_state}, Session state: {session_state}")

        # Validate state
        if not query_state or query_state != session_state:
            logger.error(f"State mismatch: Query state={query_state}, Session state={session_state}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OAuth state: CSRF warning"
            )

        # Extract code
        code = request.query_params.get('code')
        if not code:
            logger.error("No code in callback URL")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing authorization code"
            )

        # Exchange code for token
        async with AsyncClient() as client:
            token_response = await client.post(
                'https://accounts.google.com/o/oauth2/token',
                data={
                    'code': code,
                    'client_id': settings.google_client_id,
                    'client_secret': settings.google_client_secret,
                    'redirect_uri': settings.google_redirect_uri,
                    'grant_type': 'authorization_code'
                }
            )
            token_response.raise_for_status()
            token = token_response.json()
        logger.debug(f"Token received: {token}")

        # Fetch user info
        async with AsyncClient() as client:
            user_info_response = await client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f"Bearer {token['access_token']}"}
            )
            user_info = user_info_response.json()
        logger.debug(f"User info: {user_info}")

        if not user_info or not user_info.get('email'):
            logger.error("No email in user_info")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to fetch user email from Google"
            )

        email = user_info.get('email')
        oauth_id = user_info.get('sub')

        # Find or create user in MongoDB
        user = await users_collection.find_one({"email": email})
        if not user:
            new_user = {
                "email": email,
                "oauth_provider": "google",
                "oauth_id": oauth_id,
                "hashed_password": None
            }
            result = await users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            if user.get("oauth_provider") != "google" or user.get("oauth_id") != oauth_id:
                logger.error(f"Email conflict: {email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email associated with a different login method"
                )
            user_id = str(user["_id"])

        # Issue JWT
        access_token = create_access_token(user_id)
        # Handle refresh_token if present
        refresh_token = token.get('refresh_token')
        if refresh_token:
            await users_collection.update_one(
                {"_id": user_id},
                {"$set": {"refresh_token": refresh_token}}
            )

        response = get_token_response(access_token)
        if refresh_token:
            response.refresh_token = refresh_token
        # Clear session state
        if 'oauth_state' in request.session:
            del request.session['oauth_state']
        return response
    except Exception as e:
        logger.error(f"Error in callback_google: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to process Google callback: {str(e)}"
        )