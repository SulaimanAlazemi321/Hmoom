"""
Database configuration and session management for the application.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database configuration
DATABASE_URL = "sqlite:///./todos.db"

# Create database engine
# check_same_thread=False is needed for SQLite to work with FastAPI
engine = create_engine(
    url=DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Create SessionLocal class for database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Create Base class for declarative models
Base = declarative_base()

# Export commonly used names for backward compatibility
localSession = SessionLocal  # Deprecated: Use SessionLocal instead
base = Base  # Deprecated: Use Base instead
