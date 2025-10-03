"""Threat intelligence using VirusTotal, AlienVault OTX, and AbuseIPDB."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
import aiohttp

from .base import BaseEnricher
from .models import ThreatData
from .rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class ThreatIntelligenceEnricher(BaseEnricher):
    """Threat intelligence aggregator."""

    plugin_name = "threat_intelligence"

    VT_API = "https://www.virustotal.com/api/v3"
    OTX_API = "https://otx.alienvault.com/api/v1"
    ABUSE_API = "https://api.abuseipdb.com/api/v2"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize threat intelligence enricher.

        Args:
            config: Configuration with API keys
        """
        super().__init__(config)
        self.vt_key = config.get("virustotal_api_key")
        self.otx_key = config.get("otx_api_key")
        self.abuse_key = config.get("abuseipdb_api_key")
        self.use_vt = config.get("use_virustotal", True) and self.vt_key
        self.use_otx = config.get("use_otx", True) and self.otx_key
        self.use_abuse = config.get("use_abuseipdb", True) and self.abuse_key
        self.rate_limiter = get_rate_limiter()

    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP with threat intelligence.

        Args:
            ip_address: IP address to check

        Returns:
            Threat intelligence data dictionary
        """
        result = ThreatData(sources=[], confidence=0.0)

        try:
            # Aggregate data from multiple sources
            vt_data = None
            otx_data = None
            abuse_data = None

            if self.use_vt:
                vt_data = await self._check_virustotal(ip_address)
                if vt_data:
                    result.sources.append("virustotal")

            if self.use_otx:
                otx_data = await self._check_otx(ip_address)
                if otx_data:
                    result.sources.append("alienvault_otx")

            if self.use_abuse:
                abuse_data = await self._check_abuseipdb(ip_address)
                if abuse_data:
                    result.sources.append("abuseipdb")

            # Merge data
            self._merge_threat_data(result, vt_data, otx_data, abuse_data)

            # Calculate confidence based on sources
            if len(result.sources) >= 2:
                result.confidence = 0.90
            elif len(result.sources) == 1:
                result.confidence = 0.75
            else:
                result.confidence = 0.50

            return result.dict(exclude_none=True)

        except Exception as e:
            self.logger.error(f"Error in threat intelligence for {ip_address}: {e}")
            raise

    async def _check_virustotal(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against VirusTotal.

        Args:
            ip_address: IP to check

        Returns:
            VT data or None
        """
        try:
            await self.rate_limiter.acquire("virustotal", timeout=30)

            headers = {"x-apikey": self.vt_key}

            async with aiohttp.ClientSession() as session:
                url = f"{self.VT_API}/ip_addresses/{ip_address}"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        self.logger.warning(f"VirusTotal returned {resp.status}")
                        return None

        except Exception as e:
            self.logger.debug(f"VirusTotal lookup failed for {ip_address}: {e}")
            return None

    async def _check_otx(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against AlienVault OTX.

        Args:
            ip_address: IP to check

        Returns:
            OTX data or None
        """
        try:
            await self.rate_limiter.acquire("alienvault_otx", timeout=30)

            headers = {"X-OTX-API-KEY": self.otx_key}

            async with aiohttp.ClientSession() as session:
                url = f"{self.OTX_API}/indicators/IPv4/{ip_address}/general"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return None

        except Exception as e:
            self.logger.debug(f"OTX lookup failed for {ip_address}: {e}")
            return None

    async def _check_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check IP against AbuseIPDB.

        Args:
            ip_address: IP to check

        Returns:
            AbuseIPDB data or None
        """
        try:
            await self.rate_limiter.acquire("abuseipdb", timeout=60)

            headers = {"Key": self.abuse_key, "Accept": "application/json"}
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}

            async with aiohttp.ClientSession() as session:
                url = f"{self.ABUSE_API}/check"
                async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return None

        except Exception as e:
            self.logger.debug(f"AbuseIPDB lookup failed for {ip_address}: {e}")
            return None

    def _merge_threat_data(
        self,
        result: ThreatData,
        vt_data: Optional[Dict],
        otx_data: Optional[Dict],
        abuse_data: Optional[Dict]
    ):
        """Merge threat data from multiple sources.

        Args:
            result: ThreatData to update
            vt_data: VirusTotal data
            otx_data: OTX data
            abuse_data: AbuseIPDB data
        """
        malicious_count = 0
        total_sources = 0

        # VirusTotal
        if vt_data:
            total_sources += 1
            attributes = vt_data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0 or suspicious > 0:
                malicious_count += 1
                result.is_malicious = True

            # Reputation score from VT (0-100, where higher is worse)
            total_detections = sum(stats.values())
            if total_detections > 0:
                vt_score = int(((malicious + suspicious * 0.5) / total_detections) * 100)
                result.reputation_score = vt_score

        # AlienVault OTX
        if otx_data:
            total_sources += 1
            pulse_count = otx_data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                malicious_count += 1
                result.is_malicious = True

                # Get pulses for threat types
                pulses = otx_data.get("pulse_info", {}).get("pulses", [])
                for pulse in pulses[:5]:  # Limit to first 5
                    tags = pulse.get("tags", [])
                    result.attack_types.extend(tags[:3])

        # AbuseIPDB
        if abuse_data:
            total_sources += 1
            data = abuse_data.get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            report_count = data.get("totalReports", 0)

            if abuse_score > 50 or report_count > 5:
                malicious_count += 1
                result.is_malicious = True

            result.abuse_report_count = report_count

            # Update reputation score (weighted average)
            if result.reputation_score:
                result.reputation_score = int((result.reputation_score + abuse_score) / 2)
            else:
                result.reputation_score = abuse_score

            # Get abuse categories
            categories = data.get("usageType")
            if categories:
                result.abuse_categories.append(categories)

            # Get timestamps
            last_reported = data.get("lastReportedAt")
            if last_reported:
                try:
                    result.last_seen_malicious = datetime.fromisoformat(last_reported.replace("Z", "+00:00"))
                except:
                    pass

        # Determine threat level based on reputation score
        if result.reputation_score:
            if result.reputation_score >= 75:
                result.threat_level = "critical"
            elif result.reputation_score >= 50:
                result.threat_level = "high"
            elif result.reputation_score >= 25:
                result.threat_level = "medium"
            else:
                result.threat_level = "low"
        elif result.is_malicious:
            result.threat_level = "medium"
        else:
            result.threat_level = "low"

        # Deduplicate lists
        result.attack_types = list(set(result.attack_types))
        result.abuse_categories = list(set(result.abuse_categories))

    async def health_check(self) -> bool:
        """Check if at least one threat intel API is accessible.

        Returns:
            True if accessible
        """
        # Just check if we have at least one API configured
        return self.use_vt or self.use_otx or self.use_abuse
