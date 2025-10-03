"""Scanner detection using GreyNoise and Shodan."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp
import shodan

from .base import BaseEnricher
from .models import ScannerData
from .rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class ScannerDetectionEnricher(BaseEnricher):
    """Scanner detection using GreyNoise and Shodan APIs."""

    plugin_name = "scanner_detection"

    GREYNOISE_API = "https://api.greynoise.io/v3/community"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize scanner detection enricher.

        Args:
            config: Configuration with API keys
        """
        super().__init__(config)
        self.greynoise_key = config.get("greynoise_api_key")
        self.shodan_key = config.get("shodan_api_key")
        self.use_greynoise = config.get("use_greynoise", True)
        self.use_shodan = config.get("use_shodan", True)
        self.shodan_client: Optional[shodan.Shodan] = None
        self.rate_limiter = get_rate_limiter()

    async def initialize(self) -> bool:
        """Initialize API clients.

        Returns:
            True if successful
        """
        try:
            if self.use_shodan and self.shodan_key:
                self.shodan_client = shodan.Shodan(self.shodan_key)
                self.logger.info("Initialized Shodan client")

            if self.use_greynoise and not self.greynoise_key:
                self.logger.warning("GreyNoise API key not provided, using community API")

            self._initialized = True
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize scanner detection: {e}")
            return False

    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Detect if IP is a scanner.

        Args:
            ip_address: IP address to check

        Returns:
            Scanner detection data dictionary
        """
        result = ScannerData(source=self.plugin_name)

        try:
            # Try GreyNoise first (faster and specifically for scanners)
            if self.use_greynoise:
                greynoise_data = await self._check_greynoise(ip_address)
                if greynoise_data:
                    self._merge_greynoise_data(result, greynoise_data)

            # If not found in GreyNoise, try Shodan
            if not result.is_scanner and self.use_shodan and self.shodan_client:
                shodan_data = await self._check_shodan(ip_address)
                if shodan_data:
                    self._merge_shodan_data(result, shodan_data)

            result.confidence = 0.90 if result.is_scanner else 0.85
            return result.dict(exclude_none=True)

        except Exception as e:
            self.logger.error(f"Error in scanner detection for {ip_address}: {e}")
            raise

    async def _check_greynoise(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against GreyNoise.

        Args:
            ip_address: IP to check

        Returns:
            GreyNoise data or None
        """
        try:
            await self.rate_limiter.acquire("greynoise", timeout=30)

            headers = {}
            if self.greynoise_key:
                headers["key"] = self.greynoise_key

            async with aiohttp.ClientSession() as session:
                url = f"{self.GREYNOISE_API}/{ip_address}"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    elif resp.status == 404:
                        # IP not seen by GreyNoise
                        return None
                    else:
                        self.logger.warning(f"GreyNoise returned {resp.status}")
                        return None

        except Exception as e:
            self.logger.debug(f"GreyNoise lookup failed for {ip_address}: {e}")
            return None

    async def _check_shodan(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against Shodan.

        Args:
            ip_address: IP to check

        Returns:
            Shodan data or None
        """
        try:
            await self.rate_limiter.acquire("shodan", timeout=30)

            # Shodan API is synchronous, run in executor
            import asyncio
            loop = asyncio.get_event_loop()
            host_info = await loop.run_in_executor(
                None,
                lambda: self.shodan_client.host(ip_address)
            )

            return host_info

        except shodan.APIError as e:
            if "No information available" in str(e):
                return None
            self.logger.debug(f"Shodan lookup failed for {ip_address}: {e}")
            return None

        except Exception as e:
            self.logger.debug(f"Shodan lookup error for {ip_address}: {e}")
            return None

    def _merge_greynoise_data(self, result: ScannerData, data: Dict[str, Any]):
        """Merge GreyNoise data into result.

        Args:
            result: ScannerData to update
            data: GreyNoise response data
        """
        # GreyNoise classification
        classification = data.get("classification")

        if classification in ["benign", "malicious", "unknown"]:
            result.is_scanner = True

            # Determine scanner type
            if classification == "benign":
                result.scanner_type = "benign"
            elif classification == "malicious":
                result.scanner_type = "malicious"
            else:
                result.scanner_type = "unknown"

            # Get name and tags
            result.scanner_name = data.get("name", "Unknown")
            result.scanner_tags = data.get("tags", [])

            # Activity info
            last_seen = data.get("last_seen")
            if last_seen:
                try:
                    result.last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                except:
                    pass

    def _merge_shodan_data(self, result: ScannerData, data: Dict[str, Any]):
        """Merge Shodan data into result.

        Args:
            result: ScannerData to update
            data: Shodan response data
        """
        # Check if it's a known scanner based on org/ISP
        org = data.get("org", "").lower()
        isp = data.get("isp", "").lower()

        scanner_keywords = [
            "shodan", "censys", "binaryedge", "shadowserver",
            "rapid7", "netcraft", "scanner", "research"
        ]

        for keyword in scanner_keywords:
            if keyword in org or keyword in isp:
                result.is_scanner = True
                result.scanner_name = org or isp
                result.scanner_type = "research"
                break

        # Get ports and services (scanning behavior)
        ports = data.get("ports", [])
        if ports:
            result.scanning_behavior.append(f"open_ports:{len(ports)}")
            if len(ports) > 10:
                result.scanning_behavior.append("many_open_ports")

        # Get hostnames
        hostnames = data.get("hostnames", [])
        for hostname in hostnames:
            hostname_lower = hostname.lower()
            for keyword in scanner_keywords:
                if keyword in hostname_lower:
                    result.is_scanner = True
                    if not result.scanner_name:
                        result.scanner_name = hostname
                    break

        # Last update
        last_update = data.get("last_update")
        if last_update:
            try:
                result.last_seen = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
            except:
                pass

    async def health_check(self) -> bool:
        """Check if APIs are accessible.

        Returns:
            True if at least one API is accessible
        """
        if self.use_shodan and self.shodan_client:
            try:
                info = self.shodan_client.info()
                if info:
                    return True
            except:
                pass

        # Can't easily health check GreyNoise without making a real query
        return True  # Assume it's up
