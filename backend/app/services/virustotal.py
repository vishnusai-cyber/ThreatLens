import httpx

from app.core.config import settings


BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalService:

    def __init__(self):
        self.headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY
        }

    async def get_ip_report(self, ip: str):

        url = f"{BASE_URL}/ip_addresses/{ip}"

        async with httpx.AsyncClient(timeout=30) as client:

            response = await client.get(
                url,
                headers=self.headers
            )

            response.raise_for_status()

            return response.json()