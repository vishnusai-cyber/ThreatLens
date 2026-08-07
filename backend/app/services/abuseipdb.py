import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.crud.intelligence import create_lookup


class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    async def get_ip_report(self, ip: str, db: Session):
        """
        Fetch IP reputation from AbuseIPDB,
        save the lookup to PostgreSQL,
        and return the complete API response.
        """

        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.BASE_URL,
                    headers=headers,
                    params=params
                )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )

            result = response.json()

            # Validate API response
            if "data" not in result:
                raise HTTPException(
                    status_code=500,
                    detail="Invalid response received from AbuseIPDB."
                )

            data = result["data"]

            risk_score = data.get("abuseConfidenceScore", 0)

            # Save lookup
            create_lookup(
                db=db,
                ip=data.get("ipAddress", ip),
                source="AbuseIPDB",
                risk_score=risk_score,
                raw_response=result
            )

            return result

        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="AbuseIPDB request timed out."
            )

        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Unable to connect to AbuseIPDB: {str(exc)}"
            )

        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=str(exc)
            )