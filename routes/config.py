"""
Application configuration settings.

This module manages all application settings, loading sensitive values
from environment variables and providing defaults for others.
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    
    Sensitive values are loaded from .env file while public
    configuration can be hardcoded with defaults.
    """
    
    # Security and Authentication
    SECRET_KEY: str  # JWT secret key (from .env)
    ALGORITHM: str = "HS256"  # JWT algorithm
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID: str  # Google OAuth client ID (from .env)
    GOOGLE_CLIENT_SECRET: str  # Google OAuth client secret (from .env)
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/user/google/callback"
    
    # reCAPTCHA Configuration
    RECAPTCHA_SITE_KEY: str
    RECAPTCHA_SECRET_KEY: str  # reCAPTCHA secret key (from .env)
    
    # Email Configuration
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USERNAME: str  #  email username (from .env)
    EMAIL_APP_PASSWORD: str  # Gmail app password (from .env)
    EMAIL_FROM: str  # Email (from .env)
    EMAIL_FROM_NAME: str = "Hmoom"
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()