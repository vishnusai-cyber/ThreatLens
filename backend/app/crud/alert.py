from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate


# ==========================================================
# Create Alert
# ==========================================================

def create_alert(
    db: Session,
    alert_data: AlertCreate,
):
    alert = Alert(
        threat_score_id=alert_data.threat_score_id,
        ip_address=alert_data.ip_address,
        threatlens_score=alert_data.threatlens_score,
        severity=alert_data.severity,
        title=alert_data.title,
        description=alert_data.description,
        status=alert_data.status,
        recommendation=alert_data.recommendation,
    )

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
        .filter(Alert.id == alert_id)
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
):
    query = db.query(Alert)

    # ------------------------------------------------------
    # Filter by status
    # ------------------------------------------------------

    if status:
        query = query.filter(
            Alert.status == status
        )

    # ------------------------------------------------------
    # Filter by severity
    # ------------------------------------------------------

    if severity:
        query = query.filter(
            Alert.severity == severity
        )

    # ------------------------------------------------------
    # Return newest alerts first
    # ------------------------------------------------------

    return (
        query
        .order_by(Alert.created_at.desc())
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
    alert = get_alert_by_id(
        db,
        alert_id,
    )

    if not alert:
        return None

    update_data = alert_data.model_dump(
        exclude_unset=True
    )

    # ------------------------------------------------------
    # Update fields
    # ------------------------------------------------------

    for field, value in update_data.items():
        setattr(alert, field, value)

    # ------------------------------------------------------
    # Automatically manage resolved_at
    # ------------------------------------------------------

    if "status" in update_data:

        # --------------------------------------------------
        # Resolve alert
        # --------------------------------------------------

        if update_data["status"] == "Resolved":

            if alert.resolved_at is None:
                alert.resolved_at = datetime.now(
                    timezone.utc
                )

        # --------------------------------------------------
        # Re-open alert
        # --------------------------------------------------

        elif update_data["status"] == "Open":

            alert.resolved_at = None

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
    alert = get_alert_by_id(
        db,
        alert_id,
    )

    if not alert:
        return None

    db.delete(alert)
    db.commit()

    return alert


# ==========================================================
# Alert Statistics
# ==========================================================

def get_alert_stats(
    db: Session,
):

    # ------------------------------------------------------
    # Total Alerts
    # ------------------------------------------------------

    total_alerts = (
        db.query(Alert)
        .count()
    )

    # ------------------------------------------------------
    # Open Alerts
    # ------------------------------------------------------

    open_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "Open"
        )
        .count()
    )

    # ------------------------------------------------------
    # Resolved Alerts
    # ------------------------------------------------------

    resolved_alerts = (
        db.query(Alert)
        .filter(
            Alert.status == "Resolved"
        )
        .count()
    )

    # ------------------------------------------------------
    # Critical Alerts
    # ------------------------------------------------------

    critical_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Critical"
        )
        .count()
    )

    # ------------------------------------------------------
    # High Alerts
    # ------------------------------------------------------

    high_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "High"
        )
        .count()
    )

    # ------------------------------------------------------
    # Medium Alerts
    # ------------------------------------------------------

    medium_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Medium"
        )
        .count()
    )

    # ------------------------------------------------------
    # Low Alerts
    # ------------------------------------------------------

    low_alerts = (
        db.query(Alert)
        .filter(
            Alert.severity == "Low"
        )
        .count()
    )

    # ------------------------------------------------------
    # Return Statistics
    # ------------------------------------------------------

    return {
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
    }