"""
View routes for rendering HTML templates.

This module handles all template rendering and view-related functionality.
"""
import random
import calendar
from datetime import datetime, timedelta
from typing import Annotated, Optional

from fastapi import APIRouter, Request, Cookie, Depends, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError
from sqlalchemy.orm import Session
import requests

from models import Reflection, Question, User
from database import localSession
from .config import settings
from .user import SECRET_KEY, ALGORITHM, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(
    tags=["View"],
)

# Template configuration
templates = Jinja2Templates(directory="View/template")


# ========== Database Dependency ==========

def get_db():
    """Provide database session for dependency injection."""
    db = localSession()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


# ========== Authentication Helpers ==========

async def get_current_user_optional(
    access_token: str = Cookie(None), 
    db: Session = Depends(get_db)
) -> Optional[dict]:
    """
    Get current user data if authenticated, None otherwise.
    
    Args:
        access_token: JWT token from cookie.
        db: Database session.
        
    Returns:
        User data dictionary if authenticated, None otherwise.
    """
    if not access_token:
        return None
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        role: str = payload.get("role", "user")

        if not user_id or not username:
            return None
        
        # Get full user data from database
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
            
        return {
            "username": user.username,
            "id": user.id,
            "role": user.role,
            "email": user.email,
            "full_name": user.full_name,
            "avatar_url": user.avatar_url
        }
    except (JWTError, Exception):
        return None


OptionalUser = Annotated[Optional[dict], Depends(get_current_user_optional)]


# ========== Utility Functions ==========

def verify_recaptcha(recaptcha_response: str) -> bool:
    """
    Verify reCAPTCHA response with Google.
    
    Args:
        recaptcha_response: The reCAPTCHA response token.
        
    Returns:
        True if verification successful, False otherwise.
    """
    data = {
        'secret': settings.RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify', 
            data=data
        )
        result = response.json()
        return result.get('success', False)
    except Exception as e:
        print(f"reCAPTCHA verification error: {e}")
        return False


def group_reflections_by_date(reflections: list) -> list:
    """
    Group reflections by month and year for organized display.
    
    Args:
        reflections: List of reflection objects.
        
    Returns:
        List of grouped reflections sorted by date (newest first).
    """
    current_year = datetime.now().year
    groups = {}
    
    for reflection in reflections:
        try:
            # Parse the date string (format: "December 25, 2023 at 3:45 PM")
            date_str = reflection.date
            if date_str and date_str != "No date":
                # Extract date part and parse
                date_parts = date_str.split(" at ")[0]
                date_obj = datetime.strptime(date_parts, "%B %d, %Y")
                
                year = date_obj.year
                month = date_obj.month
                month_name = calendar.month_name[month]
                
                # Create group key based on year
                if year == current_year:
                    group_key = month_name  # Just month for current year
                else:
                    group_key = f"{month_name} {year}"  # Month and year for other years
                
                sort_key = (year, month)
            else:
                # Handle reflections without proper dates
                group_key = "No Date"
                sort_key = (1900, 1)  # Sort at bottom
            
            # Add reflection to group
            if group_key not in groups:
                groups[group_key] = {
                    'name': group_key,
                    'reflections': [],
                    'sort_key': sort_key
                }
            
            groups[group_key]['reflections'].append(reflection)
                
        except (ValueError, AttributeError):
            # If date parsing fails, put in "No Date" group
            group_key = "No Date"
            if group_key not in groups:
                groups[group_key] = {
                    'name': group_key,
                    'reflections': [],
                    'sort_key': (1900, 1)
                }
            groups[group_key]['reflections'].append(reflection)
    
    # Sort groups by date (newest first)
    sorted_groups = sorted(
        groups.values(), 
        key=lambda x: x['sort_key'], 
        reverse=True
    )
    
    return sorted_groups


# ========== View Routes ==========

@router.get("/")
async def index(
    request: Request, 
    db: DbSession, 
    user: OptionalUser
):
    """
    Render the main page with user's reflections and a random question.
    
    Args:
        request: FastAPI request object.
        db: Database session.
        user: Current user data if authenticated.
        
    Returns:
        Rendered HTML template.
    """
    # Get random question for display
    questions = db.query(Question).all()
    if questions:
        question_text = random.choice(questions).question
    elif not user:
        question_text = "Free Your Mind"
    else:
        question_text = "Click to refresh question"
    
    # Only get reflections if user is logged in
    reflection_groups = None
    if user:
        reflections = db.query(Reflection).filter(
            Reflection.user_id == user.get("id")
        ).order_by(Reflection.date.desc()).all()
        
        # Group reflections by month/year
        reflection_groups = group_reflections_by_date(reflections)
    
    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request,
            "ref": reflection_groups,
            "question": question_text,
            "user": user
        }
    )


@router.get("/login")
async def login_page(request: Request):
    """
    Render the login page.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Rendered login template.
    """
    return templates.TemplateResponse(
        "login.html", 
        {
            "request": request,
            "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
        }
    )


@router.get("/signup")
async def signup_page(request: Request):
    """
    Render the signup page.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Rendered signup template.
    """
    return templates.TemplateResponse(
        "signup.html", 
        {
            "request": request,
            "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
        }
    )


@router.get("/verify-email")
async def verify_email_page(request: Request):
    """
    Render the email verification page.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Rendered email verification template.
    """
    return templates.TemplateResponse(
        "verify-email.html", 
        {
            "request": request
        }
    )


@router.get("/forgot-password")
async def forgot_password_page(request: Request):
    """
    Render the forgot password page.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Rendered forgot password template.
    """
    return templates.TemplateResponse(
        "forgot-password.html", 
        {
            "request": request,
            "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
        }
    )


@router.get("/reset-password")
async def reset_password_page(request: Request):
    """
    Render the password reset page.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Rendered password reset template.
    """
    return templates.TemplateResponse(
        "reset-password.html", 
        {
            "request": request
        }
    )