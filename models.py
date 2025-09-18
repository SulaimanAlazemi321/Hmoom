from database import base
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

class Reflection(base):
    __tablename__ = "Reflection"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    date = Column(String)  
    reflection = Column(String)
    user_id = Column(Integer, ForeignKey("User.id"))
    user = relationship("User", back_populates="reflections")
    
class Question(base):
    __tablename__ = "Question"
    id = Column(Integer, primary_key=True, index=True)
    question = Column(String)

class User(base):
    __tablename__ = "User"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_password = Column(String) 
    role = Column(String) 
    google_id = Column(String, unique=True, nullable=True)
    email = Column(String, unique=True, nullable=True)
    full_name = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    is_email_verified = Column(Boolean, default=False)
    reflections = relationship("Reflection", back_populates="user")

# OTP model for email verification during signup
class EmailVerificationOTP(base):
    __tablename__ = "EmailVerificationOTP"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    username = Column(String, index=True)
    hashed_password = Column(String)  # Store temporarily until verification
    otp_code = Column(String, index=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)  # Track failed attempts

# Password Reset Token model for forgot password functionality
class PasswordResetToken(base):
    __tablename__ = "PasswordResetToken"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("User.id"), index=True)
    email = Column(String, index=True)
    reset_token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    
    # Relationship to user
    user = relationship("User")



  

