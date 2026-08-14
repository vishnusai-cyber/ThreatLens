# ==========================================================
# ThreatLens - Intelligence API
# ==========================================================

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
import traceback

from app.database.database import get_db

from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.otx import OTXService
from app.services.correlation import CorrelationService

from app.crud.intelligence import (
    create_lookup,
    get_lookup_history,
    attach_lookup_to_incident,
    detach_lookup_from_incident,
)

from app.models.incident import Incident
from app.models.intelligence import IntelligenceLookup

from app.schemas.intelligence import IntelligenceHistoryResponse
from app.schemas.correlation import CorrelationResponse


# ==========================================================
# Router
# ==========================================================

router = APIRouter(
    prefix="/intelligence",
    tags=["Threat Intelligence"],
)


# ==========================================================
# Services
# ==========================================================

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
    db: Session = Depends(get_db),
):
    try:
        result = await vt_service.get_ip_report(ip)

        attributes = result["data"]["attributes"]

        stats = attributes["last_analysis_stats"]

        risk_score = (
            stats.get("malicious", 0) * 10
            + stats.get("suspicious", 0) * 5
        )

        create_lookup(
            db=db,
            ip=result["data"]["id"],
            source="VirusTotal",
            risk_score=risk_score,
            raw_response=result,
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
                "undetected": stats.get("undetected"),
            },
        }

    except Exception as e:
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ==========================================================
# AbuseIPDB Lookup
# ==========================================================

@router.get("/abuseipdb/{ip}")
async def check_abuseipdb(
    ip: str,
    db: Session = Depends(get_db),
):
    try:
        result = await abuse_service.get_ip_report(
            ip,
            db,
        )

        data = result["data"]

        return {
            "ip": data.get("ipAddress"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get(
                "totalReports"
            ),
            "last_reported_at": data.get(
                "lastReportedAt"
            ),
            "is_public": data.get(
                "isPublic"
            ),
            "is_whitelisted": data.get(
                "isWhitelisted"
            ),
        }

    except Exception as e:
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ==========================================================
# AlienVault OTX Lookup
# ==========================================================

@router.get("/otx/{ip}")
async def check_otx(
    ip: str,
):
    try:
        result = await otx_service.get_ip_report(ip)

        pulse_info = result.get(
            "pulse_info",
            {},
        )

        return {
            "ip": result.get("indicator"),
            "country": result.get("country_name"),
            "asn": result.get("asn"),
            "reputation": result.get("reputation"),
            "pulse_count": pulse_info.get(
                "count"
            ),
            "related_pulses": pulse_info.get(
                "pulses",
                [],
            ),
        }

    except Exception as e:
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ==========================================================
# Threat Correlation
# ==========================================================

@router.get(
    "/correlate/{ip}",
    response_model=CorrelationResponse,
)
async def correlate_ip(
    ip: str,
    incident_id: int | None = None,
    db: Session = Depends(get_db),
):
    """
    Correlate an IP using:

    - VirusTotal
    - AbuseIPDB
    - AlienVault OTX

    Optionally associates the generated ThreatScore
    and Alert with an Incident.

    Example:

    /intelligence/correlate/217.60.195.160?incident_id=5
    """

    try:
        # ==================================================
        # Normalize IP
        # ==================================================

        ip = str(ip).strip()

        if not ip:
            raise HTTPException(
                status_code=400,
                detail="IP address cannot be empty.",
            )

        # ==================================================
        # Validate Incident
        # ==================================================

        if incident_id is not None:

            incident = (
                db.query(Incident)
                .filter(
                    Incident.id == incident_id
                )
                .first()
            )

            if not incident:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        f"Incident {incident_id} "
                        f"not found"
                    ),
                )

            # ------------------------------------------------
            # Optional IP consistency check
            # ------------------------------------------------
            #
            # If the incident already has an IP address,
            # make sure the scan matches it.
            #
            # We deliberately do not reject a mismatch here
            # because an incident may legitimately contain
            # multiple intelligence observations.
            # ------------------------------------------------

            print(
                "================================================"
            )

            print(
                "[ThreatLens] Incident-aware correlation"
            )

            print(
                "[ThreatLens] Incident ID:",
                incident_id,
            )

            print(
                "[ThreatLens] Incident IP:",
                incident.ip_address,
            )

            print(
                "[ThreatLens] Scan IP:",
                ip,
            )

            print(
                "================================================"
            )

        # ==================================================
        # Run Correlation
        # ==================================================

        result = await correlation_service.correlate_ip(
            ip=ip,
            db=db,
            incident_id=incident_id,
        )

        # ==================================================
        # Return Result
        # ==================================================

        return result

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


# ==========================================================
# Intelligence History
# ==========================================================

@router.get(
    "/history",
    response_model=list[IntelligenceHistoryResponse],
)
def get_history(
    limit: int = 10,
    offset: int = 0,
    ip: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
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
        source=source,
    )


# ==========================================================
# Attach Intelligence Lookup to Incident
# ==========================================================

@router.post(
    "/lookup/{lookup_id}/incident/{incident_id}"
)
def attach_intelligence_to_incident(
    lookup_id: int,
    incident_id: int,
    db: Session = Depends(get_db),
):
    # ======================================================
    # Check Incident
    # ======================================================

    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )

    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id} not found",
        )

    # ======================================================
    # Attach Lookup
    # ======================================================

    lookup = attach_lookup_to_incident(
        db=db,
        lookup_id=lookup_id,
        incident_id=incident_id,
    )

    if not lookup:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Intelligence lookup "
                f"{lookup_id} not found"
            ),
        )

    return {
        "message": (
            "Intelligence lookup attached "
            "to incident successfully"
        ),
        "lookup_id": lookup.id,
        "incident_id": lookup.incident_id,
        "ip": lookup.ip,
        "source": lookup.source,
        "risk_score": lookup.risk_score,
    }


# ==========================================================
# Detach Intelligence Lookup From Incident
# ==========================================================

@router.delete(
    "/lookup/{lookup_id}/incident"
)
def detach_intelligence_from_incident(
    lookup_id: int,
    db: Session = Depends(get_db),
):
    # ======================================================
    # Find Lookup
    # ======================================================

    lookup = (
        db.query(IntelligenceLookup)
        .filter(
            IntelligenceLookup.id == lookup_id
        )
        .first()
    )

    if not lookup:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Intelligence lookup "
                f"{lookup_id} not found"
            ),
        )

    # ======================================================
    # Check Attachment
    # ======================================================

    if lookup.incident_id is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Intelligence lookup is not "
                "attached to an incident"
            ),
        )

    previous_incident_id = lookup.incident_id

    # ======================================================
    # Detach
    # ======================================================

    lookup = detach_lookup_from_incident(
        db=db,
        lookup_id=lookup_id,
    )

    if not lookup:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Intelligence lookup "
                f"{lookup_id} not found"
            ),
        )

    return {
        "message": (
            "Intelligence lookup detached "
            "from incident successfully"
        ),
        "lookup_id": lookup.id,
        "previous_incident_id": previous_incident_id,
        "incident_id": lookup.incident_id,
        "ip": lookup.ip,
        "source": lookup.source,
        "risk_score": lookup.risk_score,
    }