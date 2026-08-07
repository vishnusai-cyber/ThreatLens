from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.otx import OTXService
from app.services.correlation import CorrelationService

from app.crud.intelligence import (
    create_lookup,
    get_lookup_history,
)

from app.schemas.intelligence import IntelligenceHistoryResponse
from app.schemas.correlation import CorrelationResponse


router = APIRouter(
    prefix="/intelligence",
    tags=["Threat Intelligence"]
)

# Services
vt_service = VirusTotalService()
abuse_service = AbuseIPDBService()
otx_service = OTXService()
correlation_service = CorrelationService()


# ==========================================================
# VirusTotal Lookup
# ==========================================================
@router.get("/ip/{ip}")
async def check_ip(
    ip: str,
    db: Session = Depends(get_db)
):
    try:
        result = await vt_service.get_ip_report(ip)

        attributes = result["data"]["attributes"]
        stats = attributes["last_analysis_stats"]

        risk_score = (
            stats.get("malicious", 0) * 10 +
            stats.get("suspicious", 0) * 5
        )

        create_lookup(
            db=db,
            ip=result["data"]["id"],
            source="VirusTotal",
            risk_score=risk_score,
            raw_response=result
        )

        return {
            "ip": result["data"]["id"],
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "owner": attributes.get("as_owner"),
            "reputation": attributes.get("reputation"),
            "risk_score": risk_score,
            "analysis": {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"),
                "undetected": stats.get("undetected")
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ==========================================================
# AbuseIPDB Lookup
# ==========================================================
@router.get("/abuseipdb/{ip}")
async def check_abuseipdb(
    ip: str,
    db: Session = Depends(get_db)
):
    try:
        result = await abuse_service.get_ip_report(ip, db)

        data = result["data"]

        return {
            "ip": data.get("ipAddress"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted")
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ==========================================================
# AlienVault OTX Lookup
# ==========================================================
@router.get("/otx/{ip}")
async def check_otx(ip: str):
    try:
        result = await otx_service.get_ip_report(ip)

        pulse_info = result.get("pulse_info", {})

        return {
            "ip": result.get("indicator"),
            "country": result.get("country_name"),
            "asn": result.get("asn"),
            "reputation": result.get("reputation"),
            "pulse_count": pulse_info.get("count"),
            "related_pulses": pulse_info.get("pulses", [])
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ==========================================================
# Threat Correlation
# ==========================================================
@router.get(
    "/correlate/{ip}",
    response_model=CorrelationResponse
)
async def correlate_ip(
    ip: str,
    db: Session = Depends(get_db)
):
    try:
        return await correlation_service.correlate_ip(ip, db)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ==========================================================
# Intelligence History
# ==========================================================
@router.get(
    "/history",
    response_model=list[IntelligenceHistoryResponse]
)
def get_history(
    limit: int = 10,
    offset: int = 0,
    ip: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db)
):
    """
    Retrieve intelligence lookup history.

    Supports:
    - Pagination
    - IP filtering
    - Source filtering
    """

    return get_lookup_history(
        db=db,
        limit=limit,
        offset=offset,
        ip=ip,
        source=source
    )