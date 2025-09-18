from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Sensitive keys - loaded from .env
    SECRET_KEY: str  # From .env
    GOOGLE_CLIENT_SECRET: str  # From .env
    RECAPTCHA_SECRET_KEY: str  # From .env
    
    # Public configuration - can stay in code
    ALGORITHM: str = "HS256"
    GOOGLE_CLIENT_ID: str  # From .env - moved for GitHub security
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/user/google/callback"
    RECAPTCHA_SITE_KEY: str = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
    
    # Email configuration
    EMAIL_HOST: str = "smtp.gmail.com"
    EMAIL_PORT: int = 587
    EMAIL_USERNAME: str = "hamadq118@gmail.com"
    EMAIL_APP_PASSWORD: str  # From .env
    EMAIL_FROM: str = "hamadq118@gmail.com"
    EMAIL_FROM_NAME: str = "Hmoom"
    
    class Config:
        env_file = ".env"

settings = Settings()