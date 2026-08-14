from typing import Optional

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
    incident_id: Optional[int] = None,
):
    """
    Automatically creates an alert for High or Critical threats.

    Low and Medium threats do not automatically generate alerts.

    If an incident_id is supplied, the generated alert will be
    associated with that incident.
    """

    # ======================================================
    # Normalize severity
    # ======================================================

    normalized_severity = (
        str(severity or "")
        .strip()
        .capitalize()
    )

    # ======================================================
    # Only High and Critical threats generate alerts
    # ======================================================

    if normalized_severity not in [
        "High",
        "Critical",
    ]:
        return None

    # ======================================================
    # Prevent duplicate open alerts
    #
    # Existing behaviour is preserved:
    #
    # Same IP + same severity + Open
    # = return existing alert
    # ======================================================

    existing_alert = (
        db.query(Alert)
        .filter(
            Alert.ip_address == ip_address,
            Alert.severity == normalized_severity,
            Alert.status == "Open",
        )
        .first()
    )

    if existing_alert:

        # --------------------------------------------------
        # If an incident is supplied and the existing alert
        # is not associated with one, attach it.
        # --------------------------------------------------

        if (
            incident_id is not None
            and existing_alert.incident_id is None
        ):
            existing_alert.incident_id = incident_id

            db.commit()
            db.refresh(existing_alert)

        return existing_alert

    # ======================================================
    # Generate alert title
    # ======================================================

    if normalized_severity == "Critical":
        title = "Critical Threat Detected"
    else:
        title = "High Threat Detected"

    # ======================================================
    # Generate description
    # ======================================================

    description = (
        f"ThreatLens detected a "
        f"{normalized_severity.lower()} threat "
        f"associated with IP address {ip_address}. "
        f"The calculated ThreatLens score is "
        f"{threatlens_score}."
    )

    # ======================================================
    # Create alert
    # ======================================================

    alert = Alert(
        ip_address=ip_address,
        threatlens_score=threatlens_score,
        severity=normalized_severity,
        title=title,
        description=description,
        status="Open",
        recommendation=recommendation,

        # --------------------------------------------------
        # NEW:
        # Associate alert with incident when available.
        # --------------------------------------------------

        incident_id=incident_id,
    )

    # ======================================================
    # Save
    # ======================================================

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert