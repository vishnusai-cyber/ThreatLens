import httpx
from fastapi import HTTPException

from app.core.config import settings


class OTXService:
    BASE_URL = "https://otx.alienvault.com/api/v1"

    async def get_ip_report(self, ip: str):
        headers = {
            "X-OTX-API-KEY": settings.OTX_API_KEY
        }

        url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    url,
                    headers=headers
                )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )

            return response.json()

        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="AlienVault OTX request timed out."
            )

        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=500,
                detail=f"AlienVault OTX connection error: {str(exc)}"
            )