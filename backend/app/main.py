from fastapi import FastAPI

from app.database.database import engine
from app.database.base import Base

app = FastAPI(title="ThreatLens")

Base.metadata.create_all(bind=engine)


@app.get("/")
def root():
    return {"message": "ThreatLens API is Running"}