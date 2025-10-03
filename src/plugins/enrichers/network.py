"""Network and BGP/ASN enrichment using BGPView API."""

import logging
from typing import Dict, Any, Optional
import aiohttp

from .base import BaseEnricher
from .models import NetworkData
from .rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class NetworkEnricher(BaseEnricher):
    """BGP and ASN information enricher using BGPView API."""

    plugin_name = "network"

    BGP_VIEW_API = "https://api.bgpview.io"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize network enricher.

        Args:
            config: Configuration dictionary
        """
        super().__init__(config)
        self.rate_limiter = get_rate_limiter()

    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP with network/ASN data.

        Args:
            ip_address: IP address to enrich

        Returns:
            Network data dictionary

        Raises:
            Exception: If API call fails
        """
        try:
            # Rate limit
            await self.rate_limiter.acquire("bgpview", timeout=30)

            async with aiohttp.ClientSession() as session:
                # Get IP info
                url = f"{self.BGP_VIEW_API}/ip/{ip_address}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        self.logger.warning(f"BGPView returned {resp.status} for {ip_address}")
                        return {}

                    data = await resp.json()

                    if data.get("status") != "ok":
                        return {}

                    ip_data = data.get("data", {})

                    # Get prefix info
                    prefixes = ip_data.get("prefixes", [])
                    prefix_info = prefixes[0] if prefixes else {}

                    asn = prefix_info.get("asn", {}).get("asn")

                    result = NetworkData(
                        asn=asn,
                        asn_name=prefix_info.get("asn", {}).get("name"),
                        asn_org=prefix_info.get("asn", {}).get("description"),
                        cidr=prefix_info.get("prefix"),
                        source=self.plugin_name,
                        confidence=0.95,
                    )

                    # If we have an ASN, get more details
                    if asn:
                        await self._enrich_asn(session, asn, result)

                    return result.dict(exclude_none=True)

        except Exception as e:
            self.logger.error(f"Error enriching network for {ip_address}: {e}")
            raise

    async def _enrich_asn(self, session: aiohttp.ClientSession, asn: int, result: NetworkData):
        """Enrich with ASN details.

        Args:
            session: HTTP session
            asn: ASN number
            result: NetworkData to update
        """
        try:
            await self.rate_limiter.acquire("bgpview", timeout=30)

            url = f"{self.BGP_VIEW_API}/asn/{asn}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return

                data = await resp.json()
                if data.get("status") != "ok":
                    return

                asn_data = data.get("data", {})

                # Update result with additional info
                if not result.asn_name:
                    result.asn_name = asn_data.get("name")

                if not result.asn_org:
                    result.asn_org = asn_data.get("description_short") or asn_data.get("description_full")

                # Get peering info
                peers = asn_data.get("peers", [])
                result.peers = [p.get("asn") for p in peers[:10]]  # Limit to 10

                upstreams = asn_data.get("upstreams", [])
                result.upstreams = [u.get("asn") for u in upstreams[:10]]

                downstreams = asn_data.get("downstreams", [])
                result.downstreams = [d.get("asn") for d in downstreams[:10]]

        except Exception as e:
            self.logger.debug(f"Error enriching ASN {asn}: {e}")

    async def health_check(self) -> bool:
        """Check if BGPView API is accessible.

        Returns:
            True if accessible
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.BGP_VIEW_API}/ping", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except:
            return False
