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

    incident = Incident(
        title=incident_data.title,
        description=incident_data.description,
        severity=incident_data.severity,
        status=incident_data.status,
        ip_address=(
            str(incident_data.ip_address)
            if incident_data.ip_address
            else None
        ),
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    return incident


# ==========================================================
# Get All Incidents
# ==========================================================

def get_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 100,
):
    """
    Get incidents with pagination.
    """

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
    """
    Get a single incident by ID.
    """

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
    """
    Update an existing incident.
    """

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:
        return None

    update_data = incident_data.model_dump(
        exclude_unset=True
    )

    # ------------------------------------------------------
    # Convert IP address to string
    # ------------------------------------------------------

    if "ip_address" in update_data:

        if update_data["ip_address"] is not None:

            update_data["ip_address"] = str(
                update_data["ip_address"]
            )

    # ------------------------------------------------------
    # Apply updates
    # ------------------------------------------------------

    for field, value in update_data.items():

        setattr(
            incident,
            field,
            value,
        )

    db.commit()
    db.refresh(incident)

    return incident


# ==========================================================
# Delete Incident
# ==========================================================

def delete_incident(
    db: Session,
    incident_id: int,
):
    """
    Delete an incident.
    """

    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if not incident:
        return None

    db.delete(incident)
    db.commit()

    return incident


# ==========================================================
# Incident Statistics
# ==========================================================

def get_incident_stats(
    db: Session,
):
    """
    Get incident statistics.
    """

    incidents = (
        db.query(Incident)
        .all()
    )

    total = len(incidents)

    # ------------------------------------------------------
    # Status counts
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Severity counts
    # ------------------------------------------------------

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
    """
    Get overall incident dashboard statistics.
    """

    incidents = (
        db.query(Incident)
        .all()
    )

    total_incidents = len(incidents)

    # ------------------------------------------------------
    # Severity counts
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Status counts
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Return dashboard overview
    # ------------------------------------------------------

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
    """
    Get incident counts grouped by severity.
    """

    incidents = (
        db.query(Incident)
        .all()
    )

    # ------------------------------------------------------
    # Severity counts
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Return severity distribution
    # ------------------------------------------------------

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
    """
    Get incident counts grouped by status.
    """

    incidents = (
        db.query(Incident)
        .all()
    )

    # ------------------------------------------------------
    # Status counts
    # ------------------------------------------------------

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

    # ------------------------------------------------------
    # Return status distribution
    # ------------------------------------------------------

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
    """
    Get the most recently created incidents.
    """

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
    """
    Get recent incident activity.

    Currently returns the most recently created incidents.
    """

    return (
        db.query(Incident)
        .order_by(
            Incident.created_at.desc()
        )
        .limit(limit)
        .all()
    )