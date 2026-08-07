from sqlalchemy.orm import Session

from app.services.virustotal import VirusTotalService
from app.services.abuseipdb import AbuseIPDBService
from app.services.otx import OTXService

from app.crud.threat_score import create_threat_score


class CorrelationService:

    def __init__(self):
        self.vt = VirusTotalService()
        self.abuse = AbuseIPDBService()
        self.otx = OTXService()

    async def correlate_ip(self, ip: str, db: Session):

        # --------------------------------
        # Fetch data from intelligence sources
        # --------------------------------

        vt_result = await self.vt.get_ip_report(ip)

        abuse_result = await self.abuse.get_ip_report(
            ip,
            db
        )

        otx_result = await self.otx.get_ip_report(
            ip
        )

        # --------------------------------
        # VirusTotal Data
        # --------------------------------

        vt_attributes = vt_result["data"]["attributes"]

        vt_stats = vt_attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = vt_stats.get(
            "malicious",
            0
        )

        suspicious = vt_stats.get(
            "suspicious",
            0
        )

        harmless = vt_stats.get(
            "harmless",
            0
        )

        undetected = vt_stats.get(
            "undetected",
            0
        )

        reputation = vt_attributes.get(
            "reputation",
            0
        )

        # --------------------------------
        # AbuseIPDB Data
        # --------------------------------

        abuse_data = abuse_result["data"]

        abuse_score = abuse_data.get(
            "abuseConfidenceScore",
            0
        )

        total_reports = abuse_data.get(
            "totalReports",
            0
        )

        country = abuse_data.get(
            "countryCode"
        )

        isp = abuse_data.get(
            "isp"
        )

        # --------------------------------
        # OTX Data
        # --------------------------------

        pulse_info = otx_result.get(
            "pulse_info",
            {}
        )

        otx_pulses = pulse_info.get(
            "count",
            0
        )

        otx_tags = []

        for pulse in pulse_info.get("pulses", []):
            otx_tags.extend(
                pulse.get("tags", [])
            )

        otx_tags = list(set(otx_tags))

        # --------------------------------
        # ThreatLens Risk Calculation
        # --------------------------------

        vt_score = (
            malicious * 10
        ) + (
            suspicious * 5
        )

        otx_score = 20 if otx_pulses > 0 else 0

        threatlens_score = min(
            vt_score + abuse_score + otx_score,
            100
        )

        severity = self.calculate_severity(
            threatlens_score
        )

        recommendation = self.get_recommendation(
            severity
        )

        # --------------------------------
        # Save Threat Score
        # --------------------------------

        create_threat_score(
            db=db,
            ip_address=ip,
            threatlens_score=threatlens_score,
            severity=severity,
            recommendation=recommendation,
        )

        # --------------------------------
        # Final Correlation Result
        # --------------------------------

        return {

            "ip": ip,

            "threatlens_score": threatlens_score,

            "severity": severity,

            "recommendation": recommendation,

            "sources": {

                "virustotal": {

                    "malicious": malicious,

                    "suspicious": suspicious,

                    "harmless": harmless,

                    "undetected": undetected,

                    "reputation": reputation

                },

                "abuseipdb": {

                    "confidence_score": abuse_score,

                    "total_reports": total_reports,

                    "country": country,

                    "isp": isp

                },

                "otx": {

                    "pulse_count": otx_pulses,

                    "tags": otx_tags

                }

            }

        }

    # --------------------------------
    # Severity Classification
    # --------------------------------

    def calculate_severity(
        self,
        score: int
    ) -> str:

        if score >= 81:
            return "Critical"

        elif score >= 51:
            return "High"

        elif score >= 21:
            return "Medium"

        else:
            return "Low"

    # --------------------------------
    # SOC Recommendation
    # --------------------------------

    def get_recommendation(
        self,
        severity: str
    ) -> str:

        recommendations = {

            "Critical":
            "Block immediately and investigate.",

            "High":
            "Investigate before allowing traffic.",

            "Medium":
            "Monitor closely and review activity.",

            "Low":
            "No immediate action required."

        }

        return recommendations[severity]