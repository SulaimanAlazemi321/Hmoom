from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routes import user, view, reflection  # Your existing route imports
import uvicorn

app = FastAPI(
    title="Hmoom",
    description="realse your thoughts",
    version="1.0.0"
)

# Mount static files directory
app.mount("/static", StaticFiles(directory="View/static"), name="static")

# Include your existing routers
app.include_router(user.router)
app.include_router(view.router)
app.include_router(reflection.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


