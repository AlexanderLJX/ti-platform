"""Cloud infrastructure detection (AWS, Azure, GCP)."""

import json
import logging
import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import aiohttp

from .base import BaseEnricher
from .models import CloudData

logger = logging.getLogger(__name__)


class CloudDetectionEnricher(BaseEnricher):
    """Cloud infrastructure detection for major providers."""

    plugin_name = "cloud_detection"

    # Cloud provider IP range URLs
    CLOUD_SOURCES = {
        "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_latest.json",
        "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize cloud detection enricher.

        Args:
            config: Configuration with cloud providers list and cache path
        """
        super().__init__(config)
        self.providers = config.get("providers", ["aws", "azure", "gcp"])
        self.cache_dir = Path(config.get("cache_dir", "data/enrichment/cloud_ranges"))
        self.update_frequency = config.get("update_frequency", 86400)  # 24 hours
        self.ranges: Dict[str, List[Dict[str, Any]]] = {}

    async def initialize(self) -> bool:
        """Load cloud IP ranges.

        Returns:
            True if successful
        """
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

            # Load ranges for each provider
            for provider in self.providers:
                if provider in self.CLOUD_SOURCES:
                    await self._load_provider_ranges(provider)

            self.logger.info(f"Loaded cloud ranges for {len(self.ranges)} providers")
            self._initialized = True
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize cloud detection: {e}")
            return False

    async def _load_provider_ranges(self, provider: str):
        """Load IP ranges for a cloud provider.

        Args:
            provider: Provider name (aws, azure, gcp)
        """
        cache_file = self.cache_dir / f"{provider}_ranges.json"

        # Check if cache exists and is recent
        if cache_file.exists():
            age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if age.total_seconds() < self.update_frequency:
                # Use cached data
                with open(cache_file, 'r') as f:
                    self.ranges[provider] = json.load(f)
                self.logger.info(f"Loaded cached {provider} ranges ({len(self.ranges[provider])} entries)")
                return

        # Download fresh data
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.CLOUD_SOURCES[provider], timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ranges = self._parse_provider_data(provider, data)
                        self.ranges[provider] = ranges

                        # Cache the data
                        with open(cache_file, 'w') as f:
                            json.dump(ranges, f)

                        self.logger.info(f"Downloaded {provider} ranges ({len(ranges)} entries)")
                    else:
                        self.logger.error(f"Failed to download {provider} ranges: HTTP {resp.status}")

        except Exception as e:
            self.logger.error(f"Error downloading {provider} ranges: {e}")

            # Try to use old cache if available
            if cache_file.exists():
                with open(cache_file, 'r') as f:
                    self.ranges[provider] = json.load(f)
                self.logger.warning(f"Using stale cached {provider} ranges")

    def _parse_provider_data(self, provider: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse provider-specific JSON format.

        Args:
            provider: Provider name
            data: Raw JSON data

        Returns:
            List of CIDR ranges with metadata
        """
        ranges = []

        if provider == "aws":
            for prefix in data.get("prefixes", []):
                ranges.append({
                    "cidr": prefix.get("ip_prefix"),
                    "region": prefix.get("region"),
                    "service": prefix.get("service"),
                    "network_border_group": prefix.get("network_border_group"),
                })

        elif provider == "azure":
            for value in data.get("values", []):
                for cidr in value.get("properties", {}).get("addressPrefixes", []):
                    # Only IPv4
                    if ":" not in cidr:
                        ranges.append({
                            "cidr": cidr,
                            "region": value.get("properties", {}).get("region"),
                            "service": value.get("name"),
                        })

        elif provider == "gcp":
            for prefix in data.get("prefixes", []):
                if "ipv4Prefix" in prefix:
                    ranges.append({
                        "cidr": prefix.get("ipv4Prefix"),
                        "region": prefix.get("scope"),
                        "service": "gcp",
                    })

        return ranges

    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Detect if IP belongs to cloud infrastructure.

        Args:
            ip_address: IP address to check

        Returns:
            Cloud detection data dictionary
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)

            # Check each provider
            for provider, ranges in self.ranges.items():
                for range_info in ranges:
                    cidr = range_info.get("cidr")
                    if not cidr:
                        continue

                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in network:
                            # Match found!
                            data = CloudData(
                                is_cloud=True,
                                cloud_provider=provider,
                                cloud_region=range_info.get("region"),
                                cloud_service=range_info.get("service"),
                                cloud_zone=range_info.get("network_border_group"),
                                source=self.plugin_name,
                                confidence=0.99,  # Official ranges are authoritative
                            )
                            return data.dict(exclude_none=True)

                    except ValueError:
                        # Invalid CIDR, skip
                        continue

            # No match found
            return CloudData(is_cloud=False, confidence=0.99).dict(exclude_none=True)

        except Exception as e:
            self.logger.error(f"Error checking cloud for {ip_address}: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if cloud ranges are loaded.

        Returns:
            True if ranges available
        """
        return len(self.ranges) > 0

    async def cleanup(self):
        """Clean up resources."""
        self.ranges.clear()
        await super().cleanup()
