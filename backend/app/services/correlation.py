from sqlalchemy.orm import Session

from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.otx import OTXService

from app.crud.alert import (
    create_alert,
    get_alerts,
)

from app.models.threat_score import ThreatScore

from app.schemas.alert import AlertCreate


class CorrelationService:

    def __init__(self):

        self.vt = VirusTotalService()
        self.abuse = AbuseIPDBService()
        self.otx = OTXService()

    # ==========================================================
    # Calculate Severity
    # ==========================================================

    def calculate_severity(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "Critical"

        if score >= 60:
            return "High"

        if score >= 30:
            return "Medium"

        return "Low"

    # ==========================================================
    # Get Recommendation
    # ==========================================================

    def get_recommendation(
        self,
        severity: str,
    ) -> str:

        if severity == "Critical":
            return "Block immediately and investigate."

        if severity == "High":
            return "Investigate immediately and consider blocking."

        if severity == "Medium":
            return "Investigate and monitor the IP."

        return "No immediate action required."

    # ==========================================================
    # Correlate IP
    # ==========================================================

    async def correlate_ip(
        self,
        ip: str,
        db: Session,
        incident_id: int | None = None,
    ):

        # ======================================================
        # VirusTotal
        # ======================================================

        vt_result = await self.vt.get_ip_report(ip)

        vt_attributes = vt_result["data"]["attributes"]

        vt_stats = vt_attributes.get(
            "last_analysis_stats",
            {}
        )

        vt_malicious = vt_stats.get(
            "malicious",
            0
        )

        vt_suspicious = vt_stats.get(
            "suspicious",
            0
        )

        vt_harmless = vt_stats.get(
            "harmless",
            0
        )

        vt_undetected = vt_stats.get(
            "undetected",
            0
        )

        vt_reputation = vt_attributes.get(
            "reputation",
            0
        )

        # ======================================================
        # AbuseIPDB
        # ======================================================

        abuse_result = await self.abuse.get_ip_report(
            ip,
            db
        )

        abuse_data = abuse_result.get(
            "data",
            {}
        )

        abuse_confidence = abuse_data.get(
            "abuseConfidenceScore",
            0
        )

        abuse_reports = abuse_data.get(
            "totalReports",
            0
        )

        abuse_country = abuse_data.get(
            "countryCode"
        )

        abuse_isp = abuse_data.get(
            "isp"
        )

        # ======================================================
        # AlienVault OTX
        # ======================================================

        otx_result = await self.otx.get_ip_report(
            ip
        )

        pulse_info = otx_result.get(
            "pulse_info",
            {}
        )

        pulse_count = pulse_info.get(
            "count",
            0
        )

        pulses = pulse_info.get(
            "pulses",
            []
        )

        # ======================================================
        # Calculate ThreatLens Score
        # ======================================================

        score = 0

        # ------------------------------------------------------
        # VirusTotal contribution
        # ------------------------------------------------------

        score += vt_malicious * 2

        score += vt_suspicious

        # ------------------------------------------------------
        # AbuseIPDB contribution
        # ------------------------------------------------------

        score += int(
            abuse_confidence * 0.5
        )

        # ------------------------------------------------------
        # OTX contribution
        # ------------------------------------------------------

        score += min(
            pulse_count * 2,
            30
        )

        # ------------------------------------------------------
        # VirusTotal reputation
        # ------------------------------------------------------

        if vt_reputation < 0:
            score += 10

        # ------------------------------------------------------
        # Maximum score = 100
        # ------------------------------------------------------

        score = min(
            score,
            100
        )

        # ======================================================
        # Severity
        # ======================================================

        severity = self.calculate_severity(
            score
        )

        # ======================================================
        # Recommendation
        # ======================================================

        recommendation = self.get_recommendation(
            severity
        )

        # ======================================================
        # Save Threat Score
        # ======================================================

        threat_score = ThreatScore(
            ip_address=ip,
            threatlens_score=score,
            severity=severity,
            recommendation=recommendation,
            incident_id=incident_id
        )

        db.add(threat_score)

        db.commit()

        db.refresh(threat_score)

        # ======================================================
        # Automatic Alert Generation
        # ======================================================

        alert_created = False

        alert_id = None

        # ------------------------------------------------------
        # Only High and Critical threats generate alerts
        # ------------------------------------------------------

        if severity in (
            "High",
            "Critical",
        ):

            # --------------------------------------------------
            # Find existing Open alert for this IP
            # --------------------------------------------------

            existing_alerts = get_alerts(
                db=db,
                skip=0,
                limit=100,
                status="Open"
            )

            existing_alert = next(
                (
                    alert
                    for alert in existing_alerts
                    if alert.ip_address == ip
                ),
                None
            )

            # --------------------------------------------------
            # Existing alert found
            # --------------------------------------------------

            if existing_alert:

                alert_created = False

                alert_id = existing_alert.id

            # --------------------------------------------------
            # Create new alert
            # --------------------------------------------------

            else:

                title = (
                    f"{severity} Threat Detected"
                )

                description = (
                    f"ThreatLens detected a "
                    f"{severity.lower()} threat associated "
                    f"with IP address {ip}. "
                    f"The calculated ThreatLens score is "
                    f"{score}."
                )

                alert_data = AlertCreate(
                    ip_address=ip,
                    threatlens_score=score,
                    severity=severity,
                    title=title,
                    description=description,
                    status="Open",
                    recommendation=recommendation,
                    threat_score_id=threat_score.id
                )

                alert = create_alert(
                    db=db,
                    alert_data=alert_data
                )

                alert_created = True

                alert_id = alert.id

        # ======================================================
        # OTX Tags
        # ======================================================

        otx_tags = []

        for pulse in pulses:

            tags = pulse.get(
                "tags",
                []
            )

            if tags:

                otx_tags.extend(
                    tags
                )

        # ------------------------------------------------------
        # Remove duplicate tags
        # ------------------------------------------------------

        otx_tags = list(
            dict.fromkeys(
                otx_tags
            )
        )

        # ======================================================
        # Final Response
        # ======================================================

        return {

            "id": threat_score.id,

            "ip": ip,

            "incident_id": incident_id,

            "threatlens_score": score,

            "severity": severity,

            "recommendation": recommendation,

            "alert_created": alert_created,

            "alert_id": alert_id,

            "sources": {

                # ==================================================
                # VirusTotal
                # ==================================================

                "virustotal": {

                    "malicious": vt_malicious,

                    "suspicious": vt_suspicious,

                    "harmless": vt_harmless,

                    "undetected": vt_undetected,

                    "reputation": vt_reputation,
                },

                # ==================================================
                # AbuseIPDB
                # ==================================================

                "abuseipdb": {

                    "confidence_score":
                        abuse_confidence,

                    "total_reports":
                        abuse_reports,

                    "country":
                        abuse_country,

                    "isp":
                        abuse_isp,
                },

                # ==================================================
                # OTX
                # ==================================================

                "otx": {

                    "pulse_count":
                        pulse_count,

                    "tags":
                        otx_tags,
                },
            },
        }