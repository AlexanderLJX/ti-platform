"""Comprehensive IP enricher orchestrating all enrichment modules."""

import asyncio
import logging
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime

from .base import BaseEnricher
from .models import EnrichedIPProfile
from .cache import EnrichmentCache
from .rate_limiter import get_rate_limiter, configure_default_limits
from .geolocation import GeolocationEnricher
from .cloud_detection import CloudDetectionEnricher
from .network import NetworkEnricher
from .scanner_detection import ScannerDetectionEnricher
from .threat_intelligence import ThreatIntelligenceEnricher

logger = logging.getLogger(__name__)


class ComprehensiveIPEnricher:
    """Orchestrates all IP enrichment modules."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize comprehensive enricher.

        Args:
            config: Enrichment configuration dictionary
        """
        self.config = config
        self.cache = EnrichmentCache(
            db_path=config.get("cache", {}).get("db_path", "data/enrichment/cache.db"),
            enabled=config.get("cache", {}).get("enabled", True)
        )
        self.rate_limiter = get_rate_limiter()

        # Initialize modules
        self.modules: Dict[str, BaseEnricher] = {}
        self._init_modules()

        # Configure rate limits
        configure_default_limits()

        self.logger = logging.getLogger(__name__)

    def _init_modules(self):
        """Initialize all enrichment modules."""
        modules_config = self.config.get("modules", {})

        # Geolocation
        if modules_config.get("geolocation", {}).get("enabled", True):
            self.modules["geolocation"] = GeolocationEnricher(
                config=modules_config.get("geolocation", {})
            )

        # Cloud detection
        if modules_config.get("cloud", {}).get("enabled", True):
            self.modules["cloud"] = CloudDetectionEnricher(
                config=modules_config.get("cloud", {})
            )

        # Network/ASN
        if modules_config.get("network", {}).get("enabled", True):
            self.modules["network"] = NetworkEnricher(
                config=modules_config.get("network", {})
            )

        # Scanner detection
        if modules_config.get("scanner", {}).get("enabled", True):
            self.modules["scanner"] = ScannerDetectionEnricher(
                config=modules_config.get("scanner", {})
            )

        # Threat intelligence
        if modules_config.get("threat", {}).get("enabled", True):
            self.modules["threat"] = ThreatIntelligenceEnricher(
                config=modules_config.get("threat", {})
            )

        self.logger.info(f"Initialized {len(self.modules)} enrichment modules")

    async def initialize(self) -> bool:
        """Initialize all modules and cache.

        Returns:
            True if successful
        """
        try:
            # Initialize cache
            await self.cache.initialize()

            # Initialize all modules
            init_tasks = [
                module.initialize()
                for module in self.modules.values()
            ]

            results = await asyncio.gather(*init_tasks, return_exceptions=True)

            # Log any failures
            for name, result in zip(self.modules.keys(), results):
                if isinstance(result, Exception):
                    self.logger.error(f"Failed to initialize {name}: {result}")
                elif not result:
                    self.logger.warning(f"Failed to initialize {name}")
                else:
                    self.logger.info(f"Initialized {name} module")

            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize enricher: {e}")
            return False

    async def enrich_ip(
        self,
        ip_address: str,
        modules: Optional[List[str]] = None,
        use_cache: bool = True
    ) -> EnrichedIPProfile:
        """Enrich a single IP address.

        Args:
            ip_address: IP address to enrich
            modules: List of module names to use (None = all enabled)
            use_cache: Whether to use caching

        Returns:
            EnrichedIPProfile with all available data
        """
        start_time = datetime.utcnow()

        # Validate IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return EnrichedIPProfile(
                ip_address=ip_address,
                is_valid=False,
                errors=["Invalid IP address format"]
            )

        # Create profile
        profile = EnrichedIPProfile(
            ip_address=ip_address,
            is_private=ip_obj.is_private,
            is_reserved=ip_obj.is_reserved,
            version=ip_obj.version,
        )

        # Skip private/reserved IPs if configured
        if self.config.get("skip_private_ips", True) and (ip_obj.is_private or ip_obj.is_reserved):
            profile.errors.append("Skipped private/reserved IP")
            return profile

        # Determine which modules to use
        if modules:
            active_modules = {k: v for k, v in self.modules.items() if k in modules}
        else:
            active_modules = self.modules

        # Check cache first
        if use_cache:
            cache_results = await self._check_cache(ip_address, active_modules.keys())
        else:
            cache_results = {}

        # Enrich with each module
        tasks = []
        module_names = []

        for name, module in active_modules.items():
            if name in cache_results:
                # Use cached data
                self._apply_cached_data(profile, name, cache_results[name])
            else:
                # Need to enrich
                tasks.append(module.safe_enrich(ip_address))
                module_names.append(name)

        # Run enrichments in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for name, result in zip(module_names, results):
                if isinstance(result, Exception):
                    profile.errors.append(f"{name}: {str(result)}")
                    self.logger.error(f"Error in {name} for {ip_address}: {result}")
                elif result:
                    # Apply enrichment data
                    self._apply_enrichment_data(profile, name, result)

                    # Cache the result
                    if use_cache:
                        await self.cache.set(ip_address, name, result)

        # Calculate enrichment duration
        profile.enrichment_duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        profile.last_updated = datetime.utcnow()

        return profile

    async def enrich_batch(
        self,
        ip_addresses: List[str],
        modules: Optional[List[str]] = None,
        parallel: int = 10,
        use_cache: bool = True
    ) -> List[EnrichedIPProfile]:
        """Enrich multiple IP addresses.

        Args:
            ip_addresses: List of IP addresses
            modules: List of module names to use (None = all)
            parallel: Number of parallel enrichments
            use_cache: Whether to use caching

        Returns:
            List of EnrichedIPProfile objects
        """
        semaphore = asyncio.Semaphore(parallel)

        async def enrich_with_limit(ip: str) -> EnrichedIPProfile:
            async with semaphore:
                return await self.enrich_ip(ip, modules=modules, use_cache=use_cache)

        self.logger.info(f"Enriching {len(ip_addresses)} IPs with {parallel} parallel workers")

        tasks = [enrich_with_limit(ip) for ip in ip_addresses]
        results = await asyncio.gather(*tasks)

        return results

    async def _check_cache(
        self,
        ip_address: str,
        module_names: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Check cache for all modules.

        Args:
            ip_address: IP address
            module_names: List of module names

        Returns:
            Dictionary of cached data by module
        """
        cache_results = {}

        for name in module_names:
            cached = await self.cache.get(ip_address, name)
            if cached:
                cache_results[name] = cached
                self.logger.debug(f"Cache hit for {ip_address}/{name}")

        return cache_results

    def _apply_cached_data(
        self,
        profile: EnrichedIPProfile,
        module_name: str,
        data: Dict[str, Any]
    ):
        """Apply cached data to profile.

        Args:
            profile: Profile to update
            module_name: Module name
            data: Cached data
        """
        profile.cache_hit = True
        profile.enrichment_sources.append(f"{module_name} (cached)")

        # Apply based on module type
        self._apply_enrichment_data(profile, module_name, data)

    def _apply_enrichment_data(
        self,
        profile: EnrichedIPProfile,
        module_name: str,
        data: Dict[str, Any]
    ):
        """Apply enrichment data to profile.

        Args:
            profile: Profile to update
            module_name: Module name
            data: Enrichment data
        """
        if not data:
            return

        # Add source
        if module_name not in profile.enrichment_sources:
            profile.enrichment_sources.append(module_name)

        # Get confidence
        confidence = data.get("confidence", 0.0)
        profile.confidence_scores[module_name] = confidence

        # Apply data based on module
        if module_name == "geolocation":
            from .models import GeolocationData
            profile.geolocation = GeolocationData(**data)

        elif module_name == "cloud":
            from .models import CloudData
            profile.cloud = CloudData(**data)

        elif module_name == "network":
            from .models import NetworkData
            profile.network = NetworkData(**data)

        elif module_name == "scanner":
            from .models import ScannerData
            profile.scanner = ScannerData(**data)

        elif module_name == "threat":
            from .models import ThreatData
            profile.threat = ThreatData(**data)

        # Store raw data
        profile.raw_data[module_name] = data

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Cache stats dictionary
        """
        return await self.cache.get_stats()

    async def cleanup(self):
        """Clean up all resources."""
        # Cleanup modules
        for module in self.modules.values():
            await module.cleanup()

        # Close cache
        await self.cache.close()

        self.logger.info("Comprehensive enricher cleanup completed")
