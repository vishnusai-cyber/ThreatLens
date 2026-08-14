from sqlalchemy.orm import Session

from app.models.incident import Incident


# ==========================================================
# Create Incident
# ==========================================================

def create_incident(
    db: Session,
    incident_data,
):
    """
    Create a new security incident.
    """

    try:
        incident = Incident(
            title=incident_data.title,
            description=incident_data.description,
            severity=incident_data.severity,
            status=incident_data.status,
            ip_address=(
                str(incident_data.ip_address)
                if incident_data.ip_address is not None
                else None
            ),
        )

        db.add(incident)

        db.commit()

        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


# ==========================================================
# Get All Incidents
# ==========================================================

def get_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 100,
):
    return (
        db.query(Incident)
        .order_by(
            Incident.created_at.desc()
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


# ==========================================================
# Get Incident By ID
# ==========================================================

def get_incident_by_id(
    db: Session,
    incident_id: int,
):
    return (
        db.query(Incident)
        .filter(
            Incident.id == incident_id
        )
        .first()
    )


# ==========================================================
# Update Incident
# ==========================================================

def update_incident(
    db: Session,
    incident_id: int,
    incident_data,
):
    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:
        return None

    try:

        update_data = incident_data.model_dump(
            exclude_unset=True
        )

        if "ip_address" in update_data:

            if update_data["ip_address"] is not None:
                update_data["ip_address"] = str(
                    update_data["ip_address"]
                )

        for field, value in update_data.items():

            setattr(
                incident,
                field,
                value,
            )

        db.commit()

        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


# ==========================================================
# Delete Incident
# ==========================================================

def delete_incident(
    db: Session,
    incident_id: int,
):
    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:
        return None

    try:

        db.delete(incident)

        db.commit()

        return incident

    except Exception:
        db.rollback()
        raise


# ==========================================================
# Incident Statistics
# ==========================================================

def get_incident_stats(
    db: Session,
):
    incidents = (
        db.query(Incident)
        .all()
    )

    total = len(incidents)

    open_count = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "open"
    )

    investigating = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "investigating"
    )

    resolved = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "resolved"
    )

    critical = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "critical"
    )

    high = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "high"
    )

    medium = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "medium"
    )

    low = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "low"
    )

    return {
        "total": total,
        "open": open_count,
        "investigating": investigating,
        "resolved": resolved,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ==========================================================
# Incident Dashboard - Overview
# ==========================================================

def get_incident_dashboard_overview(
    db: Session,
):
    incidents = (
        db.query(Incident)
        .all()
    )

    total_incidents = len(incidents)

    critical = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "critical"
    )

    high = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "high"
    )

    medium = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "medium"
    )

    low = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "low"
    )

    open_count = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "open"
    )

    investigating = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "investigating"
    )

    resolved = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "resolved"
    )

    return {
        "total_incidents": total_incidents,

        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },

        "status": {
            "open": open_count,
            "investigating": investigating,
            "resolved": resolved,
        },
    }


# ==========================================================
# Incident Dashboard - Severity Distribution
# ==========================================================

def get_incident_severity_distribution(
    db: Session,
):
    incidents = (
        db.query(Incident)
        .all()
    )

    critical = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "critical"
    )

    high = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "high"
    )

    medium = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "medium"
    )

    low = sum(
        1
        for incident in incidents
        if incident.severity
        and incident.severity.lower() == "low"
    )

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ==========================================================
# Incident Dashboard - Status Distribution
# ==========================================================

def get_incident_status_distribution(
    db: Session,
):
    incidents = (
        db.query(Incident)
        .all()
    )

    open_count = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "open"
    )

    investigating = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "investigating"
    )

    resolved = sum(
        1
        for incident in incidents
        if incident.status
        and incident.status.lower() == "resolved"
    )

    return {
        "open": open_count,
        "investigating": investigating,
        "resolved": resolved,
    }


# ==========================================================
# Incident Dashboard - Recent Incidents
# ==========================================================

def get_recent_incidents(
    db: Session,
    limit: int = 10,
):
    return (
        db.query(Incident)
        .order_by(
            Incident.created_at.desc()
        )
        .limit(limit)
        .all()
    )


# ==========================================================
# Incident Dashboard - Activity
# ==========================================================

def get_incident_activity(
    db: Session,
    limit: int = 10,
):
    return (
        db.query(Incident)
        .order_by(
            Incident.created_at.desc()
        )
        .limit(limit)
        .all()
    )