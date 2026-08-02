from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.admin import router as admin_router

app = FastAPI(
    title="ThreatLens",
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(admin_router)

@app.get("/")
def root():
    return {"message": "ThreatLens API is Running"}

@app.get("/health")
def health():
    return {"status": "healthy"}