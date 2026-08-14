# ==========================================================
# ThreatLens - Alert CRUD
# ==========================================================

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate


# ==========================================================
# Normalize Status
# ==========================================================

def normalize_status(
    status: Optional[str],
) -> Optional[str]:

    if status is None:
        return None

    value = str(status).strip().lower()

    if value == "open":
        return "Open"

    if value == "resolved":
        return "Resolved"

    if value == "closed":
        return "Closed"

    return status


# ==========================================================
# Normalize Severity
# ==========================================================

def normalize_severity(
    severity: Optional[str],
) -> Optional[str]:

    if severity is None:
        return None

    value = str(severity).strip().lower()

    if value == "critical":
        return "Critical"

    if value == "high":
        return "High"

    if value == "medium":
        return "Medium"

    if value == "low":
        return "Low"

    return severity


# ==========================================================
# Create Alert
# ==========================================================

def create_alert(
    db: Session,
    alert_data: AlertCreate,
):

    alert = Alert(

        # --------------------------------------------------
        # Threat Score
        # --------------------------------------------------

        threat_score_id=(
            alert_data.threat_score_id
        ),

        # --------------------------------------------------
        # Incident
        # --------------------------------------------------

        incident_id=(
            alert_data.incident_id
        ),

        # --------------------------------------------------
        # Threat Information
        # --------------------------------------------------

        ip_address=(
            alert_data.ip_address
        ),

        threatlens_score=(
            alert_data.threatlens_score
        ),

        severity=normalize_severity(
            alert_data.severity
        ),

        title=(
            alert_data.title
        ),

        description=(
            alert_data.description
        ),

        recommendation=(
            alert_data.recommendation
        ),

        status=normalize_status(
            alert_data.status
        ),
    )

    # ------------------------------------------------------
    # Save
    # ------------------------------------------------------

    db.add(alert)

    db.commit()

    db.refresh(alert)

    return alert


# ==========================================================
# Get Alert By ID
# ==========================================================

def get_alert_by_id(
    db: Session,
    alert_id: int,
):

    return (
        db.query(Alert)
        .filter(
            Alert.id == alert_id
        )
        .first()
    )


# ==========================================================
# Get Existing Open Alert For IP + Severity
#
# Duplicate-prevention rule:
#
# Same IP + Same severity + Open
#     = existing alert
#
# Resolved / Closed alerts remain historical records.
# ==========================================================

def get_open_alert_for_ip_and_severity(
    db: Session,
    ip_address: str,
    severity: str,
):

    normalized_severity = normalize_severity(
        severity
    )

    return (
        db.query(Alert)
        .filter(
            Alert.ip_address == ip_address,
            Alert.severity == normalized_severity,
            Alert.status == "Open",
        )
        .order_by(
            Alert.created_at.desc(),
            Alert.id.desc(),
        )
        .first()
    )


# ==========================================================
# Get Existing Open Alert For IP
#
# Legacy / global helper.
#
# Searches for ANY open alert belonging
# to the specified IP.
# ==========================================================

def get_open_alert_for_ip(
    db: Session,
    ip_address: str,
):

    return (
        db.query(Alert)
        .filter(
            Alert.ip_address == ip_address,
            Alert.status == "Open",
        )
        .order_by(
            Alert.created_at.desc(),
            Alert.id.desc(),
        )
        .first()
    )


# ==========================================================
# Get Existing Open Alert For IP + Incident
#
# Legacy helper retained for compatibility.
#
# This function is NOT used by the new correlation
# duplicate-prevention logic.
# ==========================================================

def get_open_alert_for_ip_and_incident(
    db: Session,
    ip_address: str,
    incident_id: Optional[int] = None,
):

    query = (
        db.query(Alert)
        .filter(
            Alert.ip_address == ip_address,
            Alert.status == "Open",
        )
    )

    # ------------------------------------------------------
    # Incident-specific alert
    # ------------------------------------------------------

    if incident_id is not None:

        query = query.filter(
            Alert.incident_id == incident_id
        )

    # ------------------------------------------------------
    # Alert without incident
    # ------------------------------------------------------

    else:

        query = query.filter(
            Alert.incident_id.is_(None)
        )

    # ------------------------------------------------------
    # Newest first
    # ------------------------------------------------------

    return (
        query
        .order_by(
            Alert.created_at.desc(),
            Alert.id.desc(),
        )
        .first()
    )


# ==========================================================
# Get Alerts
# ==========================================================

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_id: Optional[int] = None,
):

    query = db.query(Alert)

    # ------------------------------------------------------
    # Status Filter
    # ------------------------------------------------------

    if status:

        normalized_status = normalize_status(
            status
        )

        query = query.filter(
            Alert.status == normalized_status
        )

    # ------------------------------------------------------
    # Severity Filter
    # ------------------------------------------------------

    if severity:

        normalized_severity = normalize_severity(
            severity
        )

        query = query.filter(
            Alert.severity == normalized_severity
        )

    # ------------------------------------------------------
    # Incident Filter
    # ------------------------------------------------------

    if incident_id is not None:

        query = query.filter(
            Alert.incident_id == incident_id
        )

    # ------------------------------------------------------
    # Newest First
    # ------------------------------------------------------

    return (
        query
        .order_by(
            Alert.created_at.desc(),
            Alert.id.desc(),
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


# ==========================================================
# Update Alert
# ==========================================================

def update_alert(
    db: Session,
    alert_id: int,
    alert_data: AlertUpdate,
):

    # ------------------------------------------------------
    # Find Alert
    # ------------------------------------------------------

    alert = get_alert_by_id(
        db,
        alert_id,
    )

    if not alert:
        return None

    # ------------------------------------------------------
    # Convert Pydantic model to dictionary
    # ------------------------------------------------------

    update_data = alert_data.model_dump(
        exclude_unset=True
    )

    # ------------------------------------------------------
    # Normalize Status
    # ------------------------------------------------------

    if "status" in update_data:

        update_data["status"] = normalize_status(
            update_data["status"]
        )

    # ------------------------------------------------------
    # Normalize Severity
    # ------------------------------------------------------

    if "severity" in update_data:

        update_data["severity"] = normalize_severity(
            update_data["severity"]
        )

    # ------------------------------------------------------
    # Apply Updates
    # ------------------------------------------------------

    for field, value in update_data.items():

        setattr(
            alert,
            field,
            value,
        )

    # ======================================================
    # Automatically Manage resolved_at
    # ======================================================

    if "status" in update_data:

        status = update_data["status"]

        # --------------------------------------------------
        # Resolve / Close
        # --------------------------------------------------

        if status in (
            "Resolved",
            "Closed",
        ):

            if alert.resolved_at is None:

                alert.resolved_at = datetime.now(
                    timezone.utc
                )

        # --------------------------------------------------
        # Re-open
        # --------------------------------------------------

        elif status == "Open":

            alert.resolved_at = None

    # ------------------------------------------------------
    # Save
    # ------------------------------------------------------

    db.commit()

    db.refresh(alert)

    return alert


# ==========================================================
# Delete Alert
# ==========================================================

def delete_alert(
    db: Session,
    alert_id: int,
):

    # ------------------------------------------------------
    # Find Alert
    # ------------------------------------------------------

    alert = get_alert_by_id(
        db,
        alert_id,
    )

    if not alert:
        return None

    # ------------------------------------------------------
    # Delete
    # ------------------------------------------------------

    db.delete(alert)

    db.commit()

    return alert


# ==========================================================
# Alert Statistics
# ==========================================================

def get_alert_stats(
    db: Session,
):

    # ======================================================
    # Total Alerts
    # ======================================================

    total_alerts = (
        db.query(Alert)
        .count()
    )

    # ======================================================
    # Open Alerts
    # ======================================================

    open_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "Open"
        )
        .count()
    )

    # ======================================================
    # Resolved Alerts
    # ======================================================

    resolved_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "Resolved"
        )
        .count()
    )

    # ======================================================
    # Closed Alerts
    # ======================================================

    closed_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "Closed"
        )
        .count()
    )

    # ======================================================
    # Critical Alerts
    # ======================================================

    critical_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Critical"
        )
        .count()
    )

    # ======================================================
    # High Alerts
    # ======================================================

    high_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "High"
        )
        .count()
    )

    # ======================================================
    # Medium Alerts
    # ======================================================

    medium_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Medium"
        )
        .count()
    )

    # ======================================================
    # Low Alerts
    # ======================================================

    low_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Low"
        )
        .count()
    )

    # ======================================================
    # Return Statistics
    # ======================================================

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "closed_alerts": closed_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
    }