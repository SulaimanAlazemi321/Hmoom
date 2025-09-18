from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


databaseURL = "sqlite:///./todos.db"
engine = create_engine(url=databaseURL, connect_args={"check_same_thread": False})
localSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
base = declarative_base()
