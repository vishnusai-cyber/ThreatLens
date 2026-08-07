from fastapi import FastAPI

# Import database models
from app.database import base

from app.api.auth import router as auth_router
from app.api.threat import router as threat_router
from app.api.intelligence import router as intelligence_router
from app.api.dashboard import router as dashboard_router

app = FastAPI(
    title="ThreatLens",
    version="0.1.0",
)

# Authentication Routes
app.include_router(auth_router)

# Threat Routes
app.include_router(threat_router)

# Threat Intelligence Routes
app.include_router(intelligence_router)

# Dashboard Routes
app.include_router(dashboard_router)


@app.get("/")
def root():
    return {
        "message": "ThreatLens API is Running 🚀"
    }