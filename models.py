"""
Database models for the Hmoom application.

This module contains all SQLAlchemy ORM models used in the application.
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import base


class User(base):
    """
    User model for authentication and user management.
    
    Supports both regular (username/password) and OAuth (Google) authentication.
    """
    __tablename__ = "User"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    
    # Authentication fields
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=True)  # Nullable for OAuth users
    role = Column(String, default="user")
    
    # OAuth fields (Google)
    google_id = Column(String, unique=True, nullable=True)
    
    # Profile fields
    email = Column(String, unique=True, nullable=True)
    full_name = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    
    # Email verification
    is_email_verified = Column(Boolean, default=False)
    
    # Relationships
    reflections = relationship("Reflection", back_populates="user", cascade="all, delete-orphan")


class Reflection(base):
    """
    Reflection model for storing user's journal entries.
    
    Each reflection belongs to a user and contains their thoughts/journal entry.
    """
    __tablename__ = "Reflection"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    date = Column(String, nullable=False)  # Consider using DateTime in future
    reflection = Column(String, nullable=False)
    
    # Foreign key to User
    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="reflections")


class Question(base):
    """
    Question model for storing daily reflection prompts.
    
    These questions are displayed randomly to inspire users' reflections.
    """
    __tablename__ = "Question"
    
    id = Column(Integer, primary_key=True, index=True)
    question = Column(String, nullable=False)


class EmailVerificationOTP(base):
    """
    OTP model for email verification during signup.
    
    Stores temporary OTP codes sent to users for email verification.
    """
    __tablename__ = "EmailVerificationOTP"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    username = Column(String, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)  # Stored temporarily until verification
    otp_code = Column(String, index=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    
    # Usage tracking
    is_used = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)  # Track failed verification attempts


class PasswordResetToken(base):
    """
    Password reset token model for forgot password functionality.
    
    Stores secure tokens for password reset requests with expiration.
    """
    __tablename__ = "PasswordResetToken"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("User.id"), index=True, nullable=False)
    email = Column(String, index=True, nullable=False)
    reset_token = Column(String, unique=True, index=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    
    # Usage tracking
    is_used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User")



  

