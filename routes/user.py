"""
User authentication and management routes.

This module handles user registration, login, OAuth, password reset,
email verification, and user management operations.
"""
import logging
import secrets
import string
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional, Dict, Any

from fastapi import Depends, HTTPException, status, APIRouter, Request, Cookie, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import jwt, JWTError
from jose.exceptions import ExpiredSignatureError
import httpx
import requests

from models import User, EmailVerificationOTP, PasswordResetToken, Reflection
from database import localSession
from .config import settings
from .email_service import email_service

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Router configuration
router = APIRouter(
    tags=["User"],
    prefix="/user"
)

# Security configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/token")

# JWT configuration
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = 30 * 24 * 60  # 30 days

# Google OAuth settings
GOOGLE_CLIENT_ID = settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET = settings.GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI = settings.GOOGLE_REDIRECT_URI


# ========== Database Dependency ==========

def get_db():
    """Provide database session for dependency injection."""
    db = localSession()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


# ========== Pydantic Schemas ==========

class UserIdSchema(BaseModel):
    """Schema for user ID operations."""
    id: int = Field(gt=0, description="User ID")
    
    model_config = {
        "json_schema_extra": {
            "example": {"id": 1}
        }
    }


class Token(BaseModel):
    """JWT token response schema."""
    access_token: str
    token_type: str


class CreateUserSchema(BaseModel):
    """Schema for creating a new user (admin use)."""
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user", pattern="^(user|admin)$")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "johndoe",
                "password": "SecurePass123!",
                "role": "user"
            }
        }
    }

class SignupSchema(BaseModel):
    """Schema for user signup (deprecated - use SignupRequestSchema)."""
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    recaptcha_response: str
    
    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        validation_result = validate_password_complexity(v)
        if not validation_result["is_valid"]:
            error_message = "Password requirements not met: " + "; ".join(validation_result["errors"])
            raise ValueError(error_message)
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "newuser",
                "email": "user@example.com", 
                "password": "SecurePass123!",
                "recaptcha_response": "test_recaptcha_token"
            }
        }
    }

class SignupRequestSchema(BaseModel):
    """Schema for initial signup request - sends OTP email."""
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=5, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    recaptcha_response: str
    
    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        validation_result = validate_password_complexity(v)
        if not validation_result["is_valid"]:
            error_message = "Password requirements not met: " + "; ".join(validation_result["errors"])
            raise ValueError(error_message)
        return v

    model_config = {
        "json_schema_extra": {
            "example": {
                "username": "newuser",
                "email": "user@example.com",
                "password": "SecurePass123!",
                "recaptcha_response": "test_recaptcha_token"
            }
        }
    }


class OTPVerificationSchema(BaseModel):
    """Schema for OTP verification to complete signup."""
    email: str = Field(min_length=5, max_length=100)
    otp_code: str = Field(min_length=6, max_length=6, pattern="^[0-9]{6}$")
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "otp_code": "123456"
            }
        }
    }

# ========== Utility Functions ==========

def generate_otp() -> str:
    """Generate a 6-digit OTP code."""
    return email_service.generate_otp()


def cleanup_expired_otps(db: Session) -> int:
    """
    Remove expired OTP records from database.
    
    Args:
        db: Database session.
        
    Returns:
        Number of expired records removed.
    """
    try:
        expired_otps = db.query(EmailVerificationOTP).filter(
            EmailVerificationOTP.expires_at < datetime.now()
        ).all()
        
        for otp in expired_otps:
            db.delete(otp)
        
        db.commit()
        return len(expired_otps)
    except Exception as e:
        logger.error(f"Failed to cleanup expired OTPs: {e}")
        db.rollback()
        return 0

class ForgotPasswordSchema(BaseModel):
    """Schema for password reset request."""
    email: str = Field(min_length=5, max_length=100)
    recaptcha_response: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "recaptcha_response": "test_recaptcha_token"
            }
        }
    }


class ResetPasswordSchema(BaseModel):
    """Schema for resetting password with token."""
    token: str = Field(min_length=1, description="Password reset token")
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)
    
    @field_validator('new_password')
    @classmethod
    def validate_password_complexity(cls, v):
        validation_result = validate_password_complexity(v)
        if not validation_result["is_valid"]:
            error_message = "Password requirements not met: " + "; ".join(validation_result["errors"])
            raise ValueError(error_message)
        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v, info):
        if 'new_password' in info.data and v != info.data['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "token": "reset_token_here",
                "new_password": "NewSecurePass123!",
                "confirm_password": "NewSecurePass123!"
            }
        }
    }

def cleanup_expired_reset_tokens(db: Session) -> int:
    """
    Remove expired password reset tokens from database.
    
    Args:
        db: Database session.
        
    Returns:
        Number of expired tokens removed.
    """
    try:
        expired_tokens = db.query(PasswordResetToken).filter(
            PasswordResetToken.expires_at < datetime.now()
        ).all()
        
        for token in expired_tokens:
            db.delete(token)
        
        db.commit()
        return len(expired_tokens)
    except Exception as e:
        logger.error(f"Failed to cleanup expired reset tokens: {e}")
        db.rollback()
        return 0


def generate_reset_token() -> str:
    """Generate a secure password reset token."""
    return email_service.generate_reset_token()

# ========== Avatar Routes ==========

@router.get("/avatar/{user_id}")
async def get_user_avatar(user_id: int, db: DbSession):
    """
    Serve user avatar image with caching support.
    
    Args:
        user_id: ID of the user whose avatar to fetch.
        db: Database session.
        
    Returns:
        Avatar image response with caching headers.
        
    Raises:
        HTTPException: If avatar not found or cannot be fetched.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.avatar_url:
        raise HTTPException(status_code=404, detail="Avatar not found")
    
    try:
        # Fetch the image from Google and serve it
        async with httpx.AsyncClient() as client:
            response = await client.get(user.avatar_url, timeout=10.0)
            if response.status_code == 200:
                from fastapi.responses import Response as FastAPIResponse
                return FastAPIResponse(
                    content=response.content,
                    media_type="image/jpeg",
                    headers={
                        "Cache-Control": "public, max-age=86400",  # Cache for 1 day
                        "Access-Control-Allow-Origin": "*"
                    }
                )
    except Exception as e:
        logger.error(f"Error fetching avatar: {e}")
    
    # If we can't get the avatar, return 404
    raise HTTPException(status_code=404, detail="Avatar not available")

# ========== Google OAuth Routes ==========

@router.get("/google/login")
async def google_login(response: Response):
    """
    Initiate Google OAuth login flow.
    
    Redirects user to Google's OAuth consent screen and sets
    a state cookie for CSRF protection.
    
    Returns:
        RedirectResponse to Google OAuth URL.
    """
    # Generate random state for CSRF protection
    state = secrets.token_urlsafe(32)
    
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={GOOGLE_REDIRECT_URI}&"
        f"scope=openid email profile&"
        f"response_type=code&"
        f"state={state}"
    )
    
    # Store state in cookie for verification
    response = RedirectResponse(url=google_auth_url)
    response.set_cookie(
        key="oauth_state", 
        value=state, 
        httponly=True, 
        secure=False,  # TODO: Set to True in production with HTTPS
        samesite="lax",
        max_age=600  # 10 minutes
    )
    return response

@router.get("/google/callback")
async def google_callback(
    request: Request,
    db: DbSession,
    response: Response,
    code: str = None,
    state: str = None,
    oauth_state: str = Cookie(None)
):
    """Handle Google OAuth callback"""
    
    # Check if we have the required parameters
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not provided")
    
    if not state:
        raise HTTPException(status_code=400, detail="State parameter not provided")
    
    # Verify state parameter for security
    if not oauth_state or oauth_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Clear the state cookie
    response.delete_cookie("oauth_state")
    
    try:
        # Exchange code for tokens
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                }
            )
            
            if token_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to exchange code for tokens")
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            
            # Get user info from Google
            user_response = await client.get(
                f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={access_token}"
            )
            
            if user_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            user_info = user_response.json()
            
        # Extract user information
        google_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name")
        picture = user_info.get("picture")
        
        # Modify the picture URL to get a smaller size
        if picture:
            picture = picture.replace("s96-c", "s48-c")
        
        if not google_id or not email:
            raise HTTPException(status_code=400, detail="Required user information not available")
        
        # Check if user exists by Google ID or email
        existing_user = db.query(User).filter(
            (User.google_id == google_id) | (User.email == email)
        ).first()
        
        if existing_user:
            # Update existing user's info if needed
            if not existing_user.google_id:
                existing_user.google_id = google_id
            if not existing_user.email:
                existing_user.email = email
            if not existing_user.full_name:
                existing_user.full_name = name
            if not existing_user.avatar_url:
                existing_user.avatar_url = picture
            
            db.commit()
            user = existing_user
        else:
            # Create new user
            user = create_oauth_user(db, email, google_id, name, picture)
        
        # Create JWT token
        token = create_access_token(
            user.username, 
            user.id, 
            user.role, 
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        # Set cookie and redirect
        redirect_response = RedirectResponse(url="/")
        redirect_response.set_cookie(
            key="access_token",
            value=token,
            httponly=True,  
            secure=False,  # Set to True in production
            samesite="lax", 
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
        return redirect_response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth error: {str(e)}")

def create_oauth_user(db: Session, email: str, google_id: str, name: str, picture: str) -> User:
    """Create a new user from Google OAuth data"""
    new_user = User(
        username=email,
        email=email,
        google_id=google_id,
        full_name=name,
        avatar_url=picture,
        role="user",
        hashed_password=None
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def create_regular_user(db: Session, username: str, password: str, role: str) -> User:
    """Create a new user with username/password"""
    new_user = User(
        username=username,
        hashed_password=pwd_context.hash(password),
        role=role,
        email=None,
        google_id=None,
        full_name=None,
        avatar_url=None
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Add this after your existing user creation functions
def verify_recaptcha(recaptcha_response: str) -> bool:
    """Verify reCAPTCHA response with Google"""
    secret_key = settings.RECAPTCHA_SECRET_KEY
    
    data = {
        'secret': secret_key,
        'response': recaptcha_response
    }
    
    try:
        response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA verification error: {e}")
        return False

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_complexity(password: str) -> Dict[str, any]:
    """
    Validate password complexity and return detailed feedback
    
    Requirements:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    
    Returns:
        Dict with 'is_valid' bool and 'errors' list
    """
    errors = []
    
    # Check minimum length
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Check for special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")
    
    return {
        "is_valid": len(errors) == 0,
        "errors": errors
    }

def get_password_strength(password: str) -> Dict[str, any]:
    """
    Calculate password strength score and provide feedback
    Returns score out of 5 and descriptive strength level
    """
    score = 0
    feedback = []
    
    # Length score
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
        
    # Character variety score
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        score += 1
    
    # Determine strength level
    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 3:
        strength = "Fair"
        color = "orange"
    elif score <= 4:
        strength = "Good"
        color = "yellow"
    else:
        strength = "Strong"
        color = "green"
    
    return {
        "score": score,
        "max_score": 5,
        "strength": strength,
        "color": color,
        "percentage": (score / 5) * 100
    }

# ========== Authentication Routes ==========

@router.post("/token")
async def login_for_access(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
    response: Response
):
    """
    OAuth2 compatible token login endpoint.
    
    Used for Swagger UI authentication and API token generation.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user or not user.hashed_password or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user"
        )

    token = create_access_token(
        user.username,
        user.id,
        user.role,
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,  
        secure=False,  # TODO: Set to True in production
        samesite="lax", 
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    return {"message": "Login successful", "token_type": "bearer"}


class LoginSchema(BaseModel):
    """Schema for user login with reCAPTCHA."""
    login_identifier: str = Field(min_length=3, max_length=100, description="Username or email")
    password: str = Field(min_length=1)
    recaptcha_response: str
    
    model_config = {
        "json_schema_extra": {
            "example": {
                "login_identifier": "user@example.com",
                "password": "SecurePass123!",
                "recaptcha_response": "test_recaptcha_token"
            }
        }
    }

# Add utility function to identify if input is email or username
def is_email(identifier: str) -> bool:
    """Check if the identifier is an email address"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, identifier) is not None

@router.post("/login")
async def login_with_captcha(login_data: LoginSchema, db: DbSession, response: Response):
    """Login with username or email and reCAPTCHA verification"""
    
    # Verify reCAPTCHA
    if not verify_recaptcha(login_data.recaptcha_response):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed"
        )
    
    # Determine if login identifier is email or username
    if is_email(login_data.login_identifier):
        # Login with email
        user = db.query(User).filter(User.email == login_data.login_identifier).first()
        identifier_type = "email"
    else:
        # Login with username
        user = db.query(User).filter(User.username == login_data.login_identifier).first()
        identifier_type = "username"
    
    # Verify user exists and has a password
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )
    
    # Check if user has a password (not OAuth-only account)
    if not user.hashed_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"This account was created with Google Sign-In. Please use Google to log in or reset your password to create one."
        )
    
    # Verify password
    if not pwd_context.verify(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials"
        )
    
    # Optional: Check if email is verified (uncomment if you want to enforce this)
    # if not user.is_email_verified:
    #     raise HTTPException(
    #         status_code=status.HTTP_401_UNAUTHORIZED,
    #         detail="Please verify your email address before logging in"
    #     )

    # Create token
    token = create_access_token(user.username, user.id, user.role, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # Set cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,  
        secure=False,  
        samesite="lax", 
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    
    return {
        "message": "Login successful", 
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email,
            "login_method": identifier_type
        }
    }

def create_access_token(username: str, id: int, role: str, expire_time: timedelta):
    encode = {"sub": username, "id": id, "role": role}
    expires = int((datetime.now(timezone.utc) + expire_time).timestamp())
    encode.update({"exp": expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(response: Response, access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="could not validate user")
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        role: str = payload.get("role")

        if not user_id or not username or not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="could not validate user ")
        return {"username": username, "id": user_id, "role": role}
    except ExpiredSignatureError:
        response.delete_cookie("access_token")  
        raise HTTPException(status_code=401, detail="token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid token")

@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully"}

# ========== User Management Routes ==========

@router.get("/get-users", status_code=status.HTTP_200_OK)
async def get_all_users(db: DbSession):
    """
    Get all users in the system.
    
    Returns:
        List of all users.
    """
    return db.query(User).all()

@router.post("/add-user", status_code=status.HTTP_201_CREATED)
async def add_user(user_data: CreateUserSchema, db: DbSession):
    """
    Create a new user with username/password (admin use).
    
    Args:
        user_data: User creation data.
        db: Database session.
        
    Returns:
        Success message with new user ID.
        
    Raises:
        HTTPException: If username already exists or creation fails.
    """
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Username already exists"
        )
    
    try:
        new_user = create_regular_user(db, user_data.username, user_data.password, user_data.role)
        return {
            "message": f"User {new_user.username} created successfully",
            "user_id": new_user.id
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


# ========== Email Verification Routes ==========

@router.post("/signup/request-verification", status_code=status.HTTP_200_OK)
async def request_email_verification(signup_data: SignupRequestSchema, db: DbSession):
    """
    Step 1: Request email verification - sends OTP to email.
    
    Initiates the signup process by sending a verification OTP to the provided email.
    User data is temporarily stored until verification is complete.
    """
    
    # Cleanup expired OTPs first
    cleanup_expired_otps(db)
    
    # Validate email format
    if not validate_email(signup_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )
    
    # Verify reCAPTCHA
    if not verify_recaptcha(signup_data.recaptcha_response):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed"
        )
    
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == signup_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == signup_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    try:
        # Check if there's already a pending verification for this email
        existing_otp = db.query(EmailVerificationOTP).filter(
            EmailVerificationOTP.email == signup_data.email,
            EmailVerificationOTP.is_used == False,
            EmailVerificationOTP.expires_at > datetime.now()
        ).first()
        
        if existing_otp:
            # Delete existing OTP to create a new one
            db.delete(existing_otp)
            db.commit()
        
        # Generate OTP
        otp_code = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)  # OTP valid for 10 minutes
        
        # Create OTP record
        otp_record = EmailVerificationOTP(
            email=signup_data.email,
            username=signup_data.username,
            hashed_password=pwd_context.hash(signup_data.password),
            otp_code=otp_code,
            expires_at=expires_at,
            is_used=False,
            attempts=0
        )
        
        db.add(otp_record)
        db.commit()
        
        # Send verification email
        email_sent = email_service.send_verification_email(
            to_email=signup_data.email,
            username=signup_data.username,
            otp_code=otp_code
        )
        
        if not email_sent:
            # If email failed, clean up the OTP record
            db.delete(otp_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email. Please try again."
            )
        
        return {
            "message": "Verification email sent successfully",
            "email": signup_data.email,
            "expires_in_minutes": 10
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process signup request"
        )

@router.post("/signup/verify-email", status_code=status.HTTP_201_CREATED)
async def verify_email_and_create_account(verification_data: OTPVerificationSchema, db: DbSession):
    """Step 2: Verify OTP and create user account"""
    
    try:
        # Find the OTP record
        otp_record = db.query(EmailVerificationOTP).filter(
            EmailVerificationOTP.email == verification_data.email,
            EmailVerificationOTP.is_used == False
        ).first()
        
        if not otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending verification found for this email"
            )
        
        # Check if OTP is expired
        if otp_record.expires_at < datetime.now():
            db.delete(otp_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP has expired. Please request a new verification code."
            )
        
        # Check attempts limit (prevent brute force)
        if otp_record.attempts >= 5:
            db.delete(otp_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Too many failed attempts. Please request a new verification code."
            )
        
        # Verify OTP code
        if otp_record.otp_code != verification_data.otp_code:
            otp_record.attempts += 1
            db.commit()
            
            remaining_attempts = 5 - otp_record.attempts
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid OTP code. {remaining_attempts} attempts remaining."
            )
        
        # OTP is valid - create the user account
        new_user = User(
            username=otp_record.username,
            email=otp_record.email,
            hashed_password=otp_record.hashed_password,  # Already hashed
            role="user",
            google_id=None,
            full_name=None,
            avatar_url=None,
            is_email_verified=True  # Mark as verified
        )
        
        db.add(new_user)
        
        # Mark OTP as used
        otp_record.is_used = True
        
        db.commit()
        db.refresh(new_user)
        
        # Clean up the OTP record (optional - you might want to keep for audit)
        db.delete(otp_record)
        db.commit()
        
        return {
            "message": "Account created and verified successfully!",
            "username": new_user.username,
            "user_id": new_user.id,
            "email_verified": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify email and create account"
        )

@router.post("/signup/resend-otp", status_code=status.HTTP_200_OK)
async def resend_verification_otp(email_data: dict, db: DbSession):
    """Resend OTP for email verification"""
    email = email_data.get("email")
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    try:
        # Find existing OTP record
        otp_record = db.query(EmailVerificationOTP).filter(
            EmailVerificationOTP.email == email,
            EmailVerificationOTP.is_used == False
        ).first()
        
        if not otp_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending verification found for this email"
            )
        
        # Generate new OTP
        new_otp = generate_otp()
        new_expires_at = datetime.now() + timedelta(minutes=10)
        
        # Update OTP record
        otp_record.otp_code = new_otp
        otp_record.expires_at = new_expires_at
        otp_record.attempts = 0  # Reset attempts
        
        db.commit()
        
        # Send new verification email
        email_sent = email_service.send_verification_email(
            to_email=email,
            username=otp_record.username,
            otp_code=new_otp
        )
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email"
            )
        
        return {
            "message": "New verification code sent successfully",
            "email": email,
            "expires_in_minutes": 10
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resend verification code"
        )



@router.delete("/delete-user-by-id", status_code=status.HTTP_200_OK)
async def delete_user_by_id(user_id_data: UserIdSchema, db: DbSession):
    """
    Delete a user and all associated data.
    
    Args:
        user_id_data: Schema containing user ID to delete.
        db: Database session.
        
    Returns:
        Success message.
        
    Raises:
        HTTPException: If user not found or deletion fails.
    """
    # Find the user
    user_to_delete = db.query(User).filter(User.id == user_id_data.id).first()
    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    try:
        # Delete all reflections belonging to this user
        # (cascade delete should handle this automatically with proper relationship config)
        user_reflections = db.query(Reflection).filter(
            Reflection.user_id == user_id_data.id
        ).all()
        
        for reflection in user_reflections:
            db.delete(reflection)
        
        # Delete the user
        db.delete(user_to_delete)
        db.commit()
        
        return {
            "success": f"User {user_to_delete.username} deleted successfully",
            "reflections_deleted": len(user_reflections)
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error deleting user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to delete user"
        )

# Add this new endpoint for real-time password validation
@router.post("/validate-password")
async def validate_password_endpoint(password_data: dict):
    """Endpoint to validate password complexity in real-time"""
    password = password_data.get("password", "")
    
    validation_result = validate_password_complexity(password)
    strength_result = get_password_strength(password)
    
    return {
        "is_valid": validation_result["is_valid"],
        "errors": validation_result["errors"],
        "strength": strength_result
    }


# ========== Password Reset Routes ==========

@router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def forgot_password(forgot_data: ForgotPasswordSchema, db: DbSession):
    """
    Request password reset - sends reset link to email.
    
    Sends a password reset link to the user's email if the account exists.
    For security, always returns success even if email doesn't exist.
    """
    
    # Cleanup expired tokens first
    cleanup_expired_reset_tokens(db)
    
    # Validate email format
    if not validate_email(forgot_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )
    
    # Verify reCAPTCHA
    if not verify_recaptcha(forgot_data.recaptcha_response):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reCAPTCHA verification failed"
        )
    
    try:
        # Check if user exists with this email
        user = db.query(User).filter(User.email == forgot_data.email).first()
        
        # Always return success message (security best practice - don't reveal if email exists)
        success_message = {
            "message": "If an account with this email exists, you will receive a password reset link shortly.",
            "email": forgot_data.email
        }
        
        if not user:
            # Don't reveal that email doesn't exist, but don't send email either
            return success_message
        
        # Check if user has a password (not OAuth-only account)
        if not user.hashed_password:
            # User signed up with Google only, no password to reset
            return success_message
        
        # Check for existing valid reset token
        existing_token = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.is_used == False,
            PasswordResetToken.expires_at > datetime.now()
        ).first()
        
        if existing_token:
            # Delete existing token to create a new one
            db.delete(existing_token)
            db.commit()
        
        # Generate new reset token
        reset_token = generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=1)  # Token valid for 1 hour
        
        # Create reset token record
        token_record = PasswordResetToken(
            user_id=user.id,
            email=user.email,
            reset_token=reset_token,
            expires_at=expires_at,
            is_used=False
        )
        
        db.add(token_record)
        db.commit()
        
        # Send password reset email
        email_sent = email_service.send_password_reset_email(
            to_email=user.email,
            username=user.username,
            reset_token=reset_token
        )
        
        if not email_sent:
            # If email failed, clean up the token record
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send reset email. Please try again."
            )
        
        return success_message
        
    except Exception as e:
        db.rollback()
        # Always return the same message for security
        return {
            "message": "If an account with this email exists, you will receive a password reset link shortly.",
            "email": forgot_data.email
        }

@router.get("/reset-password/validate-token")
async def validate_reset_token(token: str, db: DbSession):
    """Validate if a reset token is valid and not expired"""
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token is required"
        )
    
    try:
        # Find the token record
        token_record = db.query(PasswordResetToken).filter(
            PasswordResetToken.reset_token == token,
            PasswordResetToken.is_used == False
        ).first()
        
        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Check if token is expired
        if token_record.expires_at < datetime.now():
            # Clean up expired token
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired. Please request a new password reset."
            )
        
        # Get user info
        user = db.query(User).filter(User.id == token_record.user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
        
        return {
            "valid": True,
            "email": user.email,
            "username": user.username,
            "expires_at": token_record.expires_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate reset token"
        )

@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(reset_data: ResetPasswordSchema, db: DbSession):
    """Step 2: Reset password using valid token"""
    
    try:
        # Find and validate the token
        token_record = db.query(PasswordResetToken).filter(
            PasswordResetToken.reset_token == reset_data.token,
            PasswordResetToken.is_used == False
        ).first()
        
        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )
        
        # Check if token is expired
        if token_record.expires_at < datetime.now():
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired. Please request a new password reset."
            )
        
        # Get the user
        user = db.query(User).filter(User.id == token_record.user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset token"
            )
        
        # Validate new password (Pydantic already does this, but double-check)
        password_validation = validate_password_complexity(reset_data.new_password)
        if not password_validation["is_valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password requirements not met: " + "; ".join(password_validation["errors"])
            )
        
        # Check if new password is different from current (optional security measure)
        if user.hashed_password and pwd_context.verify(reset_data.new_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from your current password"
            )
        
        # Update user's password
        user.hashed_password = pwd_context.hash(reset_data.new_password)
        
        # Mark token as used
        token_record.is_used = True
        token_record.used_at = datetime.now()
        
        # Commit changes
        db.commit()
        
        # Clean up any other unused tokens for this user (security measure)
        other_tokens = db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.is_used == False,
            PasswordResetToken.id != token_record.id
        ).all()
        
        for old_token in other_tokens:
            db.delete(old_token)
        
        db.commit()
        
        return {
            "message": "Password reset successfully! You can now log in with your new password.",
            "username": user.username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password"
        )

@router.get("/reset-password/check-token/{token}")
async def check_reset_token(token: str, db: DbSession):
    """
    Quick validation check for reset token.
    
    Args:
        token: Reset token to validate.
        db: Database session.
        
    Returns:
        Simple validity status without exposing user information.
    """
    token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.reset_token == token,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.now()
    ).first()
    
    return {"valid": bool(token_record)}


@router.post("/forgot-password/resend", status_code=status.HTTP_200_OK)
async def resend_password_reset(email_data: dict, db: DbSession):
    """
    Resend password reset email for existing token.
    
    Args:
        email_data: Dictionary containing email address.
        db: Database session.
        
    Returns:
        Success message if email resent.
        
    Raises:
        HTTPException: If no valid reset request found.
    """
    email = email_data.get("email")
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    try:
        # Find existing valid reset token
        token_record = db.query(PasswordResetToken).filter(
            PasswordResetToken.email == email,
            PasswordResetToken.is_used == False,
            PasswordResetToken.expires_at > datetime.now()
        ).first()
        
        if not token_record:
            # No valid token found - could be expired or doesn't exist
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid reset request found for this email. Please start a new password reset."
            )
        
        # Get user info
        user = db.query(User).filter(User.id == token_record.user_id).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid reset request"
            )
        
        # Resend the email with existing token
        email_sent = email_service.send_password_reset_email(
            to_email=user.email,
            username=user.username,
            reset_token=token_record.reset_token
        )
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to resend reset email"
            )
        
        return {
            "message": "Password reset email resent successfully",
            "email": email
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Failed to resend password reset email: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resend reset email"
        )
