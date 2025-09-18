from models import Reflection, base, Question, User  # Add User import
from database import engine, localSession
from fastapi import  Depends, HTTPException, status, APIRouter, Request, Cookie
from typing import Annotated, Optional
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import random
from .user import get_current_user
from jose import jwt, JWTError
from .user import SECRET_KEY, ALGORITHM
from datetime import datetime
import calendar
from .config import settings
import requests
from fastapi.security import OAuth2PasswordRequestForm
from .user import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta
from fastapi import Response


router = APIRouter(
    tags=["view"],
)

template = Jinja2Templates(directory="View/template")

def get_db():
    db = localSession()
    try:
        yield db
    finally:
        db.close()

dbDepends = Annotated[Session, Depends(get_db)]

# Create optional user dependency that includes full user data
async def get_current_user_optional(access_token: str = Cookie(None), db: Session = Depends(get_db)):
    """Returns full user data if logged in, None if not logged in"""
    if not access_token:
        return None
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        role: str = payload.get("role") or "user"

        if not user_id or not username:
            return None
        
        # Get full user data from database
        full_user = db.query(User).filter(User.id == user_id).first()
        if not full_user:
            return None
            
        return {
            "username": full_user.username,
            "id": full_user.id,
            "role": full_user.role,
            "email": full_user.email,
            "full_name": full_user.full_name,
            "avatar_url": full_user.avatar_url
        }
    except (JWTError, Exception):
        return None

optionalUserDepends = Annotated[Optional[dict], Depends(get_current_user_optional)]

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

@router.get("/")
async def index(req: Request, db: dbDepends, user: optionalUserDepends):
    questions = db.query(Question).all()
    if questions:
        question_text = random.choice(questions).question
    elif not user:
        question_text = "Free Your Mind"
    else:
        question_text = "press to change the title"
    
    # Only get reflections if user is logged in
    reflection_groups = None
    if user:
        reflections = db.query(Reflection).filter(Reflection.user_id == user.get("id")).order_by(Reflection.date.desc()).all()
        
        # Group reflections by month and year
        reflection_groups = group_reflections_by_date(reflections)
    
    return template.TemplateResponse("index.html", {
        "request": req, 
        "ref": reflection_groups,
        "question": question_text,
        "user": user  # Now includes full user data with avatar
    })

def group_reflections_by_date(reflections):
    """Group reflections by month and year, format appropriately"""
    current_year = datetime.now().year
    groups = {}
    
    for reflection in reflections:
        try:
            # Parse the date string to extract month and year
            # Assuming date format like "December 25, 2023 at 3:45 PM"
            date_str = reflection.date
            if date_str and date_str != "No date":
                # Try to parse different date formats
                date_parts = date_str.split(" at ")[0]  # Remove time part
                date_obj = datetime.strptime(date_parts, "%B %d, %Y")
                
                year = date_obj.year
                month = date_obj.month
                month_name = calendar.month_name[month]
                
                # Create group key based on year
                if year == current_year:
                    group_key = month_name  # Just month for current year
                    sort_key = (year, month)
                else:
                    group_key = f"{month_name} {year}"  # Month and year for other years
                    sort_key = (year, month)
                
                if group_key not in groups:
                    groups[group_key] = {
                        'name': group_key,
                        'reflections': [],
                        'sort_key': sort_key
                    }
                
                groups[group_key]['reflections'].append(reflection)
            else:
                # Handle reflections without proper dates
                group_key = "No Date"
                if group_key not in groups:
                    groups[group_key] = {
                        'name': group_key,
                        'reflections': [],
                        'sort_key': (1900, 1)  # Sort at bottom
                    }
                groups[group_key]['reflections'].append(reflection)
                
        except ValueError:
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
    sorted_groups = sorted(groups.values(), key=lambda x: x['sort_key'], reverse=True)
    
    return sorted_groups

@router.get("/login")
async def login_page(req: Request):
    return template.TemplateResponse("login.html", {
        "request": req,
        "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
    })

@router.get("/signup")
async def signup_page(req: Request):
    return template.TemplateResponse("signup.html", {
        "request": req,
        "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
    })

@router.get("/verify-email")
async def verify_email_page(req: Request):
    return template.TemplateResponse("verify-email.html", {
        "request": req
    })

# ADD THESE MISSING ROUTES
@router.get("/forgot-password")
async def forgot_password_page(req: Request):
    return template.TemplateResponse("forgot-password.html", {
        "request": req,
        "recaptcha_site_key": settings.RECAPTCHA_SITE_KEY
    })

@router.get("/reset-password")
async def reset_password_page(req: Request):
    return template.TemplateResponse("reset-password.html", {
        "request": req
    })

# Add this at the end of your view.py file for testing
@router.get("/test-forgot")
async def test_forgot_password():
    return {"message": "Forgot password route is working!"}