"""Base enricher class for IP enrichment plugins."""

import logging
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from datetime import datetime

from .models import EnrichedIPProfile


logger = logging.getLogger(__name__)


class BaseEnricher(ABC):
    """Abstract base class for IP enrichment plugins."""

    plugin_type = "enricher"
    plugin_name = "base"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize enricher.

        Args:
            config: Configuration dictionary for the enricher
        """
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.logger = logging.getLogger(f"{__name__}.{self.plugin_name}")
        self._initialized = False

    @abstractmethod
    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Enrich an IP address with this module's data.

        Args:
            ip_address: IP address to enrich

        Returns:
            Dictionary containing enrichment data

        Raises:
            Exception: If enrichment fails
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the enrichment service is healthy.

        Returns:
            True if service is accessible, False otherwise
        """
        pass

    async def initialize(self) -> bool:
        """Initialize the enricher (load databases, test connections, etc.).

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing {self.plugin_name} enricher")
            self._initialized = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize {self.plugin_name}: {e}")
            return False

    async def cleanup(self):
        """Clean up resources."""
        self.logger.info(f"Cleaning up {self.plugin_name} enricher")
        self._initialized = False

    def get_confidence(self) -> float:
        """Get confidence score for this enricher.

        Returns:
            Confidence score between 0.0 and 1.0
        """
        return self.config.get("confidence", 0.8)

    def is_enabled(self) -> bool:
        """Check if enricher is enabled.

        Returns:
            True if enabled, False otherwise
        """
        return self.enabled

    def is_initialized(self) -> bool:
        """Check if enricher is initialized.

        Returns:
            True if initialized, False otherwise
        """
        return self._initialized

    async def safe_enrich(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Safely enrich an IP with error handling.

        Args:
            ip_address: IP address to enrich

        Returns:
            Enrichment data or None if failed
        """
        if not self.is_enabled():
            self.logger.debug(f"{self.plugin_name} is disabled, skipping")
            return None

        if not self.is_initialized():
            self.logger.warning(f"{self.plugin_name} not initialized, attempting init")
            if not await self.initialize():
                return None

        try:
            start_time = datetime.utcnow()
            result = await self.enrich(ip_address)
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000

            if result:
                result['enrichment_duration_ms'] = duration
                result['source'] = self.plugin_name
                result['confidence'] = self.get_confidence()

            return result

        except Exception as e:
            self.logger.error(f"Error enriching {ip_address} with {self.plugin_name}: {e}")
            return None

    def __str__(self) -> str:
        """String representation."""
        return f"{self.plugin_name} (enabled={self.enabled}, initialized={self._initialized})"
