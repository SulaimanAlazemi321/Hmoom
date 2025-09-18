"""
Main application entry point for Hmoom - a reflection journaling platform.
"""
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import uvicorn

from routes import user, view, reflection

# Initialize FastAPI application
app = FastAPI(
    title="Hmoom",
    description="Release your thoughts - A personal reflection journaling platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount static files directory for serving CSS, JS, and images
app.mount("/static", StaticFiles(directory="View/static"), name="static")

# Include API routers
app.include_router(user.router)
app.include_router(view.router)
app.include_router(reflection.router)


