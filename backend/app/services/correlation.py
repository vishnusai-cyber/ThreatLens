# ==========================================================
# ThreatLens - Correlation Service
# ==========================================================

from sqlalchemy.orm import Session

from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.otx import OTXService

from app.crud.alert import (
    create_alert,
    get_open_alert_for_ip_and_severity,
)

from app.models.threat_score import ThreatScore

from app.schemas.alert import AlertCreate


# ==========================================================
# Correlation Service
# ==========================================================

class CorrelationService:

    # ======================================================
    # Initialize Services
    # ======================================================

    def __init__(self):

        self.vt = VirusTotalService()
        self.abuse = AbuseIPDBService()
        self.otx = OTXService()

    # ======================================================
    # Calculate Severity
    # ======================================================

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

    # ======================================================
    # Recommendation
    # ======================================================

    def get_recommendation(
        self,
        severity: str,
    ) -> str:

        if severity == "Critical":
            return (
                "Block immediately and investigate."
            )

        if severity == "High":
            return (
                "Investigate immediately and consider blocking."
            )

        if severity == "Medium":
            return (
                "Investigate and monitor the IP."
            )

        return (
            "No immediate action required."
        )

    # ======================================================
    # Correlate IP
    # ======================================================

    async def correlate_ip(
        self,
        ip: str,
        db: Session,
        incident_id: int | None = None,
    ):

        # ==================================================
        # Normalize IP
        # ==================================================

        ip = str(ip).strip()

        if not ip:
            raise ValueError(
                "IP address cannot be empty."
            )

        # ==================================================
        # VirusTotal
        # ==================================================

        vt_result = await self.vt.get_ip_report(
            ip
        )

        vt_attributes = (
            vt_result
            .get("data", {})
            .get("attributes", {})
        )

        vt_stats = vt_attributes.get(
            "last_analysis_stats",
            {},
        )

        vt_malicious = int(
            vt_stats.get(
                "malicious",
                0,
            )
            or 0
        )

        vt_suspicious = int(
            vt_stats.get(
                "suspicious",
                0,
            )
            or 0
        )

        vt_harmless = int(
            vt_stats.get(
                "harmless",
                0,
            )
            or 0
        )

        vt_undetected = int(
            vt_stats.get(
                "undetected",
                0,
            )
            or 0
        )

        vt_reputation = int(
            vt_attributes.get(
                "reputation",
                0,
            )
            or 0
        )

        # ==================================================
        # AbuseIPDB
        # ==================================================

        abuse_result = await self.abuse.get_ip_report(
            ip,
            db,
        )

        abuse_data = abuse_result.get(
            "data",
            {},
        )

        abuse_confidence = int(
            abuse_data.get(
                "abuseConfidenceScore",
                0,
            )
            or 0
        )

        abuse_reports = int(
            abuse_data.get(
                "totalReports",
                0,
            )
            or 0
        )

        abuse_country = abuse_data.get(
            "countryCode"
        )

        abuse_isp = abuse_data.get(
            "isp"
        )

        # ==================================================
        # AlienVault OTX
        # ==================================================

        otx_result = await self.otx.get_ip_report(
            ip
        )

        pulse_info = otx_result.get(
            "pulse_info",
            {},
        )

        pulse_count = int(
            pulse_info.get(
                "count",
                0,
            )
            or 0
        )

        pulses = pulse_info.get(
            "pulses",
            [],
        )

        # ==================================================
        # ThreatLens Score
        # ==================================================

        score = 0

        # --------------------------------------------------
        # VirusTotal
        # --------------------------------------------------

        score += (
            vt_malicious * 2
        )

        score += vt_suspicious

        # --------------------------------------------------
        # AbuseIPDB
        # --------------------------------------------------

        score += int(
            abuse_confidence * 0.5
        )

        # --------------------------------------------------
        # AlienVault OTX
        # --------------------------------------------------

        score += min(
            pulse_count * 2,
            30,
        )

        # --------------------------------------------------
        # VirusTotal Reputation
        # --------------------------------------------------

        if vt_reputation < 0:
            score += 10

        # --------------------------------------------------
        # AbuseIPDB Reports
        # --------------------------------------------------

        if abuse_reports >= 100:

            score += 10

        elif abuse_reports >= 50:

            score += 7

        elif abuse_reports >= 20:

            score += 5

        elif abuse_reports >= 5:

            score += 2

        # --------------------------------------------------
        # Clamp Score
        # --------------------------------------------------

        score = min(
            max(score, 0),
            100,
        )

        # ==================================================
        # Debug
        # ==================================================

        print(
            "========== THREATLENS DEBUG =========="
        )

        print(
            "IP:",
            ip,
        )

        print(
            "Incident ID:",
            incident_id,
        )

        print(
            "VT malicious:",
            vt_malicious,
        )

        print(
            "VT suspicious:",
            vt_suspicious,
        )

        print(
            "VT harmless:",
            vt_harmless,
        )

        print(
            "VT undetected:",
            vt_undetected,
        )

        print(
            "VT reputation:",
            vt_reputation,
        )

        print(
            "Abuse confidence:",
            abuse_confidence,
        )

        print(
            "Abuse reports:",
            abuse_reports,
        )

        print(
            "Abuse country:",
            abuse_country,
        )

        print(
            "Abuse ISP:",
            abuse_isp,
        )

        print(
            "OTX pulse count:",
            pulse_count,
        )

        print(
            "Calculated ThreatLens score:",
            score,
        )

        print(
            "======================================"
        )

        # ==================================================
        # Severity
        # ==================================================

        severity = self.calculate_severity(
            score
        )

        # ==================================================
        # Recommendation
        # ==================================================

        recommendation = self.get_recommendation(
            severity
        )

        # ==================================================
        # Save Threat Score
        # ==================================================

        threat_score = ThreatScore(
            ip_address=ip,
            threatlens_score=score,
            severity=severity,
            recommendation=recommendation,
            incident_id=incident_id,
        )

        db.add(
            threat_score
        )

        db.commit()

        db.refresh(
            threat_score
        )

        print(
            "[ThreatLens] ThreatScore created:",
            threat_score.id,
        )

        print(
            "[ThreatLens] ThreatScore incident_id:",
            threat_score.incident_id,
        )

        # ==================================================
        # Automatic Alert Generation
        # ==================================================

        alert_created = False
        alert_id = None

        # ==================================================
        # Only High / Critical create alerts
        # ==================================================

        if severity in (
            "High",
            "Critical",
        ):

            # ------------------------------------------------
            # Find existing OPEN alert for IP + Severity
            #
            # IMPORTANT:
            #
            # Incident ID is intentionally NOT part of the
            # duplicate-prevention rule.
            #
            # Same IP + Same Severity + Open
            # = Existing alert
            # ------------------------------------------------

            existing_alert = (
                get_open_alert_for_ip_and_severity(
                    db=db,
                    ip_address=ip,
                    severity=severity,
                )
            )

            # ------------------------------------------------
            # Existing Alert
            # ------------------------------------------------

            if existing_alert:

                alert_created = False
                alert_id = existing_alert.id

                print(
                    "================================================"
                )

                print(
                    "[ThreatLens] Existing OPEN alert found."
                )

                print(
                    "[ThreatLens] IP:",
                    ip,
                )

                print(
                    "[ThreatLens] Severity:",
                    severity,
                )

                print(
                    "[ThreatLens] New Incident ID:",
                    incident_id,
                )

                print(
                    "[ThreatLens] Existing Alert ID:",
                    alert_id,
                )

                print(
                    "[ThreatLens] Existing Alert Incident ID:",
                    existing_alert.incident_id,
                )

                print(
                    "[ThreatLens] No duplicate alert created."
                )

                print(
                    "================================================"
                )

            # ------------------------------------------------
            # Create New Alert
            # ------------------------------------------------

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

                # ============================================
                # Alert Data
                # ============================================

                alert_data = AlertCreate(
                    ip_address=ip,
                    threatlens_score=score,
                    severity=severity,
                    title=title,
                    description=description,
                    status="Open",
                    recommendation=recommendation,

                    # ----------------------------------------
                    # ThreatScore relationship
                    # ----------------------------------------

                    threat_score_id=threat_score.id,

                    # ----------------------------------------
                    # Incident relationship
                    # ----------------------------------------

                    incident_id=incident_id,
                )

                # ============================================
                # Create Alert
                # ============================================

                alert = create_alert(
                    db=db,
                    alert_data=alert_data,
                )

                alert_created = True
                alert_id = alert.id

                print(
                    "================================================"
                )

                print(
                    "[ThreatLens] NEW alert created."
                )

                print(
                    "[ThreatLens] Alert ID:",
                    alert_id,
                )

                print(
                    "[ThreatLens] IP:",
                    ip,
                )

                print(
                    "[ThreatLens] Incident ID:",
                    incident_id,
                )

                print(
                    "[ThreatLens] ThreatScore ID:",
                    threat_score.id,
                )

                print(
                    "[ThreatLens] Severity:",
                    severity,
                )

                print(
                    "[ThreatLens] Score:",
                    score,
                )

                print(
                    "================================================"
                )

        # ==================================================
        # OTX Tags
        # ==================================================

        otx_tags = []

        for pulse in pulses:

            tags = pulse.get(
                "tags",
                [],
            )

            if tags:

                otx_tags.extend(
                    tags
                )

        # --------------------------------------------------
        # Remove Duplicate Tags
        # --------------------------------------------------

        otx_tags = list(
            dict.fromkeys(
                otx_tags
            )
        )

        # ==================================================
        # Final Response
        # ==================================================

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

                # ==========================================
                # VirusTotal
                # ==========================================

                "virustotal": {

                    "malicious": vt_malicious,

                    "suspicious": vt_suspicious,

                    "harmless": vt_harmless,

                    "undetected": vt_undetected,

                    "reputation": vt_reputation,
                },

                # ==========================================
                # AbuseIPDB
                # ==========================================

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

                # ==========================================
                # AlienVault OTX
                # ==========================================

                "otx": {

                    "pulse_count":
                        pulse_count,

                    "tags":
                        otx_tags,
                },
            },
        }