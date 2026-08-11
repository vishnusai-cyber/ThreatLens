from sqlalchemy.orm import Session

from app.models.alert import Alert


# ==========================================================
# Automatic Alert Generation
# ==========================================================
def generate_alert_if_needed(
    db: Session,
    ip_address: str,
    threatlens_score: int,
    severity: str,
    recommendation: str,
):
    """
    Automatically creates an alert for High or Critical threats.

    Low and Medium threats do not automatically generate alerts.
    """

    # ------------------------------------------------------
    # Only High and Critical threats generate alerts
    # ------------------------------------------------------
    if severity not in ["High", "Critical"]:
        return None

    # ------------------------------------------------------
    # Prevent duplicate open alerts for the same IP/severity
    # ------------------------------------------------------
    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.ip_address == ip_address,
            Alert.severity == severity,
            Alert.status == "Open",
        )
        .first()
    )

    if existing_alert:
        return existing_alert

    # ------------------------------------------------------
    # Generate alert title
    # ------------------------------------------------------
    if severity == "Critical":
        title = "Critical Threat Detected"
    else:
        title = "High Threat Detected"

    # ------------------------------------------------------
    # Generate description
    # ------------------------------------------------------
    description = (
        f"ThreatLens detected a {severity.lower()} threat "
        f"associated with IP address {ip_address}. "
        f"The calculated ThreatLens score is {threatlens_score}."
    )

    # ------------------------------------------------------
    # Create alert
    # ------------------------------------------------------
    alert = Alert(
        ip_address=ip_address,
        threatlens_score=threatlens_score,
        severity=severity,
        title=title,
        description=description,
        status="Open",
        recommendation=recommendation,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert