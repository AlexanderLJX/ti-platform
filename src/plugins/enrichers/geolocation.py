"""Geolocation enrichment using MaxMind GeoIP2."""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
import geoip2.database
import geoip2.errors

from .base import BaseEnricher
from .models import GeolocationData

logger = logging.getLogger(__name__)


class GeolocationEnricher(BaseEnricher):
    """MaxMind GeoIP2 geolocation enricher."""

    plugin_name = "geolocation"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize geolocation enricher.

        Args:
            config: Configuration with 'database_path' key
        """
        super().__init__(config)
        self.db_path = Path(config.get("database_path", "data/enrichment/GeoLite2-City.mmdb"))
        self.reader: Optional[geoip2.database.Reader] = None

    async def initialize(self) -> bool:
        """Initialize GeoIP2 database reader.

        Returns:
            True if successful
        """
        try:
            if not self.db_path.exists():
                self.logger.warning(
                    f"GeoIP2 database not found at {self.db_path}. "
                    f"Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                )
                return False

            self.reader = geoip2.database.Reader(str(self.db_path))
            self.logger.info(f"Loaded GeoIP2 database from {self.db_path}")
            self._initialized = True
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize GeoIP2 database: {e}")
            return False

    async def enrich(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP with geolocation data.

        Args:
            ip_address: IP address to enrich

        Returns:
            Geolocation data dictionary

        Raises:
            Exception: If lookup fails
        """
        if not self.reader:
            raise Exception("GeoIP2 reader not initialized")

        try:
            response = self.reader.city(ip_address)

            data = GeolocationData(
                country=response.country.name,
                country_code=response.country.iso_code,
                city=response.city.name,
                region=response.subdivisions.most_specific.name if response.subdivisions else None,
                postal_code=response.postal.code,
                latitude=response.location.latitude,
                longitude=response.location.longitude,
                timezone=response.location.time_zone,
                accuracy_radius=response.location.accuracy_radius,
                source=self.plugin_name,
                confidence=0.95,  # MaxMind is highly accurate
            )

            return data.dict(exclude_none=True)

        except geoip2.errors.AddressNotFoundError:
            self.logger.debug(f"No geolocation data for {ip_address}")
            return {}

        except Exception as e:
            self.logger.error(f"Error enriching {ip_address}: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if GeoIP2 database is accessible.

        Returns:
            True if database accessible
        """
        try:
            return self.reader is not None and self.db_path.exists()
        except:
            return False

    async def cleanup(self):
        """Close database reader."""
        if self.reader:
            self.reader.close()
            self.reader = None
        await super().cleanup()
