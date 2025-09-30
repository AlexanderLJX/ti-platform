"""IOC enrichment engine with multiple data sources."""

import asyncio
import logging
import time
from typing import List, Optional, Dict, Any
from pathlib import Path
import aiohttp
import validators
import tldextract
import ipaddress

from ...core.models import (
    Indicator, IOCEnrichment, GeolocationData, ASNData, 
    ReputationData, ThreatClassification, IndicatorType
)

logger = logging.getLogger(__name__)


class EnrichmentConfig:
    """Configuration for enrichment services."""
    
    def __init__(self, config: Dict[str, Any]):
        self.maxmind_db_path = config.get('maxmind_db_path')
        self.virustotal_api_key = config.get('virustotal_api_key')
        self.ipinfo_api_key = config.get('ipinfo_api_key')
        self.urlvoid_api_key = config.get('urlvoid_api_key')
        self.rate_limit_per_minute = config.get('rate_limit_per_minute', 60)
        self.request_timeout = config.get('request_timeout', 30)
        self.max_concurrent_requests = config.get('max_concurrent_requests', 5)


class IOCEnrichmentEngine:
    """Main IOC enrichment engine."""
    
    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self.session = None
        self._rate_limiter = asyncio.Semaphore(config.max_concurrent_requests)
        self._last_request_time = {}
    
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=100)
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def enrich_indicators(self, indicators: List[Indicator]) -> List[Indicator]:
        """Enrich a batch of indicators with external data sources."""
        logger.info(f"Starting enrichment of {len(indicators)} indicators")
        start_time = time.time()
        
        enriched_indicators = []
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        tasks = []
        for indicator in indicators:
            if not indicator.is_enriched:
                task = self._enrich_single_indicator(indicator, semaphore)
                tasks.append(task)
            else:
                enriched_indicators.append(indicator)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Enrichment error: {result}")
                elif result:
                    enriched_indicators.append(result)
        
        processing_time = time.time() - start_time
        logger.info(f"Enriched {len(enriched_indicators)} indicators in {processing_time:.2f}s")
        
        return enriched_indicators
    
    async def _enrich_single_indicator(self, indicator: Indicator, semaphore: asyncio.Semaphore) -> Optional[Indicator]:
        """Enrich a single indicator."""
        async with semaphore:
            try:
                enrichment = IOCEnrichment()
                enrichment_sources = []
                
                # Determine enrichment strategies based on indicator type
                if indicator.type == IndicatorType.IP:
                    enrichment = await self._enrich_ip_indicator(indicator, enrichment)
                    enrichment_sources.extend(['geolocation', 'asn', 'reputation'])
                elif indicator.type in [IndicatorType.DOMAIN, IndicatorType.FQDN]:
                    enrichment = await self._enrich_domain_indicator(indicator, enrichment)
                    enrichment_sources.extend(['reputation', 'dns'])
                elif indicator.type == IndicatorType.URL:
                    enrichment = await self._enrich_url_indicator(indicator, enrichment)
                    enrichment_sources.extend(['reputation', 'url_analysis'])
                elif indicator.type in [IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256]:
                    enrichment = await self._enrich_hash_indicator(indicator, enrichment)
                    enrichment_sources.extend(['malware_analysis'])
                
                # Set enrichment metadata
                enrichment.enriched_at = time.time()
                enrichment.enrichment_sources = enrichment_sources
                
                # Update indicator
                indicator.enrichment = enrichment
                indicator.is_enriched = True
                
                return indicator
                
            except Exception as e:
                logger.error(f"Error enriching indicator {indicator.value}: {e}")
                return indicator
    
    async def _enrich_ip_indicator(self, indicator: Indicator, enrichment: IOCEnrichment) -> IOCEnrichment:
        """Enrich IP address indicator."""
        try:
            ip_addr = ipaddress.ip_address(indicator.value)
            
            # Skip private/local IPs for external enrichment
            if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_multicast:
                logger.info(f"Skipping private/local IP: {indicator.value}")
                return enrichment
            
            # Geolocation enrichment
            enrichment.geolocation = await self._get_ip_geolocation(indicator.value)
            
            # ASN enrichment
            enrichment.asn = await self._get_ip_asn_data(indicator.value)
            
            # Reputation enrichment
            enrichment.reputation = await self._get_ip_reputation(indicator.value)
            
            return enrichment
            
        except ValueError:
            logger.warning(f"Invalid IP address: {indicator.value}")
            return enrichment
    
    async def _enrich_domain_indicator(self, indicator: Indicator, enrichment: IOCEnrichment) -> IOCEnrichment:
        """Enrich domain indicator."""
        try:
            # Validate domain
            if not validators.domain(indicator.value):
                logger.warning(f"Invalid domain: {indicator.value}")
                return enrichment
            
            # Reputation enrichment
            enrichment.reputation = await self._get_domain_reputation(indicator.value)
            
            # DNS resolution data
            enrichment.dns_data = await self._get_dns_data(indicator.value)
            
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching domain {indicator.value}: {e}")
            return enrichment
    
    async def _enrich_url_indicator(self, indicator: Indicator, enrichment: IOCEnrichment) -> IOCEnrichment:
        """Enrich URL indicator."""
        try:
            # Validate URL
            if not validators.url(indicator.value):
                logger.warning(f"Invalid URL: {indicator.value}")
                return enrichment
            
            # Extract domain for domain-based enrichment
            extracted = tldextract.extract(indicator.value)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Reputation enrichment
            enrichment.reputation = await self._get_url_reputation(indicator.value)
            
            # DNS data for the domain
            enrichment.dns_data = await self._get_dns_data(domain)
            
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching URL {indicator.value}: {e}")
            return enrichment
    
    async def _enrich_hash_indicator(self, indicator: Indicator, enrichment: IOCEnrichment) -> IOCEnrichment:
        """Enrich hash indicator."""
        try:
            # Validate hash format
            hash_value = indicator.value.lower()
            
            if indicator.type == IndicatorType.HASH_MD5 and len(hash_value) != 32:
                logger.warning(f"Invalid MD5 hash: {indicator.value}")
                return enrichment
            elif indicator.type == IndicatorType.HASH_SHA1 and len(hash_value) != 40:
                logger.warning(f"Invalid SHA1 hash: {indicator.value}")
                return enrichment
            elif indicator.type == IndicatorType.HASH_SHA256 and len(hash_value) != 64:
                logger.warning(f"Invalid SHA256 hash: {indicator.value}")
                return enrichment
            
            # Malware reputation enrichment
            enrichment.reputation = await self._get_hash_reputation(hash_value)
            
            # Threat classification
            enrichment.threat_classification = await self._get_hash_threat_classification(hash_value)
            
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching hash {indicator.value}: {e}")
            return enrichment
    
    async def _get_ip_geolocation(self, ip: str) -> Optional[GeolocationData]:
        """Get geolocation data for IP address."""
        try:
            if self.config.maxmind_db_path and Path(self.config.maxmind_db_path).exists():
                # Use MaxMind local database
                return await self._get_maxmind_geolocation(ip)
            elif self.config.ipinfo_api_key:
                # Use IPinfo API
                return await self._get_ipinfo_geolocation(ip)
            else:
                logger.warning("No geolocation service configured")
                return None
                
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip}: {e}")
            return None
    
    async def _get_maxmind_geolocation(self, ip: str) -> Optional[GeolocationData]:
        """Get geolocation from MaxMind database."""
        try:
            import maxminddb
            
            with maxminddb.open_database(self.config.maxmind_db_path) as reader:
                response = reader.get(ip)
                
                if not response:
                    return None
                
                country = response.get('country', {})
                city = response.get('city', {})
                location = response.get('location', {})
                
                return GeolocationData(
                    country=country.get('names', {}).get('en'),
                    country_code=country.get('iso_code'),
                    city=city.get('names', {}).get('en'),
                    latitude=location.get('latitude'),
                    longitude=location.get('longitude'),
                    timezone=location.get('time_zone')
                )
                
        except Exception as e:
            logger.error(f"MaxMind geolocation error for {ip}: {e}")
            return None
    
    async def _get_ipinfo_geolocation(self, ip: str) -> Optional[GeolocationData]:
        """Get geolocation from IPinfo API."""
        try:
            await self._rate_limit('ipinfo')
            
            url = f"https://ipinfo.io/{ip}/json?token={self.config.ipinfo_api_key}"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Parse location coordinates
                    loc = data.get('loc', '').split(',')
                    latitude = float(loc[0]) if len(loc) > 0 and loc[0] else None
                    longitude = float(loc[1]) if len(loc) > 1 and loc[1] else None
                    
                    return GeolocationData(
                        country=data.get('country'),
                        region=data.get('region'),
                        city=data.get('city'),
                        latitude=latitude,
                        longitude=longitude,
                        timezone=data.get('timezone')
                    )
                else:
                    logger.warning(f"IPinfo API error {response.status} for {ip}")
                    return None
                    
        except Exception as e:
            logger.error(f"IPinfo geolocation error for {ip}: {e}")
            return None
    
    async def _get_ip_asn_data(self, ip: str) -> Optional[ASNData]:
        """Get ASN data for IP address."""
        try:
            if self.config.ipinfo_api_key:
                await self._rate_limit('ipinfo')
                
                url = f"https://ipinfo.io/{ip}/json?token={self.config.ipinfo_api_key}"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Parse ASN from org field (format: "AS#### Organization Name")
                        org = data.get('org', '')
                        if org.startswith('AS'):
                            asn_str = org.split()[0][2:]  # Remove 'AS' prefix
                            try:
                                asn = int(asn_str)
                                organization = ' '.join(org.split()[1:])
                                
                                return ASNData(
                                    asn=asn,
                                    organization=organization
                                )
                            except ValueError:
                                pass
                    
            return None
            
        except Exception as e:
            logger.error(f"ASN data error for {ip}: {e}")
            return None
    
    async def _get_ip_reputation(self, ip: str) -> Optional[ReputationData]:
        """Get reputation data for IP address."""
        return await self._get_virustotal_ip_reputation(ip)
    
    async def _get_domain_reputation(self, domain: str) -> Optional[ReputationData]:
        """Get reputation data for domain."""
        return await self._get_virustotal_domain_reputation(domain)
    
    async def _get_url_reputation(self, url: str) -> Optional[ReputationData]:
        """Get reputation data for URL."""
        return await self._get_virustotal_url_reputation(url)
    
    async def _get_hash_reputation(self, hash_value: str) -> Optional[ReputationData]:
        """Get reputation data for hash."""
        return await self._get_virustotal_hash_reputation(hash_value)
    
    async def _get_virustotal_ip_reputation(self, ip: str) -> Optional[ReputationData]:
        """Get VirusTotal reputation for IP."""
        if not self.config.virustotal_api_key:
            return None
        
        try:
            await self._rate_limit('virustotal')
            
            headers = {'x-apikey': self.config.virustotal_api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return ReputationData(
                        malicious_count=stats.get('malicious', 0),
                        suspicious_count=stats.get('suspicious', 0),
                        clean_count=stats.get('harmless', 0) + stats.get('undetected', 0),
                        total_sources=sum(stats.values()) if stats else 0,
                        last_checked=time.time()
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal IP reputation error for {ip}: {e}")
        
        return None
    
    async def _get_virustotal_domain_reputation(self, domain: str) -> Optional[ReputationData]:
        """Get VirusTotal reputation for domain."""
        if not self.config.virustotal_api_key:
            return None
        
        try:
            await self._rate_limit('virustotal')
            
            headers = {'x-apikey': self.config.virustotal_api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return ReputationData(
                        malicious_count=stats.get('malicious', 0),
                        suspicious_count=stats.get('suspicious', 0),
                        clean_count=stats.get('harmless', 0) + stats.get('undetected', 0),
                        total_sources=sum(stats.values()) if stats else 0,
                        last_checked=time.time()
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal domain reputation error for {domain}: {e}")
        
        return None
    
    async def _get_virustotal_url_reputation(self, url: str) -> Optional[ReputationData]:
        """Get VirusTotal reputation for URL."""
        if not self.config.virustotal_api_key:
            return None
        
        try:
            await self._rate_limit('virustotal')
            
            # URL needs to be base64 encoded for VT API
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {'x-apikey': self.config.virustotal_api_key}
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            async with self.session.get(api_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return ReputationData(
                        malicious_count=stats.get('malicious', 0),
                        suspicious_count=stats.get('suspicious', 0),
                        clean_count=stats.get('harmless', 0) + stats.get('undetected', 0),
                        total_sources=sum(stats.values()) if stats else 0,
                        last_checked=time.time()
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal URL reputation error for {url}: {e}")
        
        return None
    
    async def _get_virustotal_hash_reputation(self, hash_value: str) -> Optional[ReputationData]:
        """Get VirusTotal reputation for hash."""
        if not self.config.virustotal_api_key:
            return None
        
        try:
            await self._rate_limit('virustotal')
            
            headers = {'x-apikey': self.config.virustotal_api_key}
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    
                    return ReputationData(
                        malicious_count=stats.get('malicious', 0),
                        suspicious_count=stats.get('suspicious', 0),
                        clean_count=stats.get('harmless', 0) + stats.get('undetected', 0),
                        total_sources=sum(stats.values()) if stats else 0,
                        last_checked=time.time()
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal hash reputation error for {hash_value}: {e}")
        
        return None
    
    async def _get_hash_threat_classification(self, hash_value: str) -> Optional[ThreatClassification]:
        """Get threat classification for hash."""
        # This would integrate with threat intelligence databases
        # For now, return empty classification
        return ThreatClassification()
    
    async def _get_dns_data(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get DNS resolution data for domain."""
        try:
            import socket
            
            # Get A records
            try:
                a_records = socket.gethostbyname_ex(domain)[2]
            except socket.gaierror:
                a_records = []
            
            return {
                'a_records': a_records,
                'resolved_at': time.time()
            }
            
        except Exception as e:
            logger.error(f"DNS resolution error for {domain}: {e}")
            return None
    
    async def _rate_limit(self, service: str):
        """Apply rate limiting for external APIs."""
        now = time.time()
        last_request = self._last_request_time.get(service, 0)
        
        # Simple rate limiting - 1 request per second per service
        if now - last_request < 1.0:
            await asyncio.sleep(1.0 - (now - last_request))
        
        self._last_request_time[service] = time.time()