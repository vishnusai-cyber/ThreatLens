from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ==========================================================
# Import database models
# ==========================================================

from app.database import base


# ==========================================================
# Import API Routers
# ==========================================================

from app.api.auth import router as auth_router
from app.api.threat import router as threat_router
from app.api.intelligence import router as intelligence_router
from app.api.dashboard import router as dashboard_router
from app.api.alert import router as alerts_router
from app.api.incident import router as incident_router
from app.api.threat_map import router as threat_map_router
from app.api.threat_score import router as threat_score_router


# ==========================================================
# FastAPI Application
# ==========================================================

app = FastAPI(
    title="ThreatLens",
    version="0.1.0",
)


# ==========================================================
# CORS Configuration
# ==========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        # Local development
        "http://localhost:5173",
        "http://127.0.0.1:5173",

        # Production frontend
        "https://threatlens-yf83.onrender.com",
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ==========================================================
# Authentication Routes
# ==========================================================

app.include_router(
    auth_router
)


# ==========================================================
# Threat Routes
# ==========================================================

app.include_router(
    threat_router
)


# ==========================================================
# Threat Intelligence Routes
# ==========================================================

app.include_router(
    intelligence_router
)


# ==========================================================
# Dashboard Routes
# ==========================================================

app.include_router(
    dashboard_router
)


# ==========================================================
# Alert Routes
# ==========================================================

app.include_router(
    alerts_router
)


# ==========================================================
# Incident Routes
# ==========================================================

app.include_router(
    incident_router
)


# ==========================================================
# Threat Map Routes
# ==========================================================

app.include_router(
    threat_map_router
)


# ==========================================================
# Threat Score Routes
# ==========================================================

app.include_router(
    threat_score_router
)


# ==========================================================
# Root Endpoint
# ==========================================================

@app.get("/")
def root():
    return {
        "message": "ThreatLens API is Running 🚀"
    }


# ==========================================================
# Health Check
# ==========================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ThreatLens API",
    }