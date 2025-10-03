"""Caching layer for IP enrichment data."""

import json
import sqlite3
import hashlib
import aiosqlite
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """SQLite-based cache for IP enrichment data."""

    def __init__(self, db_path: str = "data/enrichment/cache.db", enabled: bool = True):
        """Initialize cache.

        Args:
            db_path: Path to SQLite database
            enabled: Whether caching is enabled
        """
        self.db_path = Path(db_path)
        self.enabled = enabled
        self._conn: Optional[aiosqlite.Connection] = None

        # Default TTLs (in seconds)
        self.default_ttls = {
            "geolocation": 2592000,  # 30 days
            "network": 604800,  # 7 days
            "cloud": 86400,  # 24 hours
            "threat": 21600,  # 6 hours
            "anonymization": 86400,  # 24 hours
            "scanner": 43200,  # 12 hours
            "certificates": 604800,  # 7 days
            "passive_dns": -1,  # Never expire (historical data)
        }

    async def initialize(self) -> bool:
        """Initialize cache database.

        Returns:
            True if successful
        """
        if not self.enabled:
            logger.info("Cache is disabled")
            return True

        try:
            # Create directory if needed
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            # Connect to database
            self._conn = await aiosqlite.connect(str(self.db_path))

            # Create table
            await self._conn.execute("""
                CREATE TABLE IF NOT EXISTS enrichment_cache (
                    ip_address TEXT NOT NULL,
                    module TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER NOT NULL,
                    PRIMARY KEY (ip_address, module)
                )
            """)

            # Create index on timestamp for cleanup
            await self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON enrichment_cache(timestamp)
            """)

            await self._conn.commit()
            logger.info(f"Cache initialized at {self.db_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize cache: {e}")
            return False

    async def get(self, ip_address: str, module: str) -> Optional[Dict[str, Any]]:
        """Get cached enrichment data.

        Args:
            ip_address: IP address
            module: Enrichment module name

        Returns:
            Cached data or None if not found/expired
        """
        if not self.enabled or not self._conn:
            return None

        try:
            cursor = await self._conn.execute(
                """
                SELECT data, timestamp, ttl
                FROM enrichment_cache
                WHERE ip_address = ? AND module = ?
                """,
                (ip_address, module),
            )

            row = await cursor.fetchone()

            if not row:
                return None

            data_json, timestamp, ttl = row
            cache_time = datetime.fromtimestamp(timestamp)

            # Check if expired (unless TTL is -1 for permanent)
            if ttl != -1:
                age = (datetime.utcnow() - cache_time).total_seconds()
                if age > ttl:
                    # Expired, delete it
                    await self.delete(ip_address, module)
                    return None

            # Parse and return data
            data = json.loads(data_json)
            data['cache_hit'] = True
            data['cache_age_seconds'] = (datetime.utcnow() - cache_time).total_seconds()

            return data

        except Exception as e:
            logger.error(f"Error getting cache for {ip_address}/{module}: {e}")
            return None

    async def set(
        self,
        ip_address: str,
        module: str,
        data: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> bool:
        """Set cached enrichment data.

        Args:
            ip_address: IP address
            module: Enrichment module name
            data: Data to cache
            ttl: Time to live in seconds (None = use default)

        Returns:
            True if successful
        """
        if not self.enabled or not self._conn:
            return False

        try:
            if ttl is None:
                ttl = self.default_ttls.get(module, 3600)

            data_json = json.dumps(data, default=str)
            timestamp = int(datetime.utcnow().timestamp())

            await self._conn.execute(
                """
                INSERT OR REPLACE INTO enrichment_cache
                (ip_address, module, data, timestamp, ttl)
                VALUES (?, ?, ?, ?, ?)
                """,
                (ip_address, module, data_json, timestamp, ttl),
            )

            await self._conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error setting cache for {ip_address}/{module}: {e}")
            return False

    async def delete(self, ip_address: str, module: str) -> bool:
        """Delete cached data.

        Args:
            ip_address: IP address
            module: Enrichment module name

        Returns:
            True if successful
        """
        if not self.enabled or not self._conn:
            return False

        try:
            await self._conn.execute(
                "DELETE FROM enrichment_cache WHERE ip_address = ? AND module = ?",
                (ip_address, module),
            )
            await self._conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error deleting cache for {ip_address}/{module}: {e}")
            return False

    async def clear_ip(self, ip_address: str) -> bool:
        """Clear all cached data for an IP.

        Args:
            ip_address: IP address

        Returns:
            True if successful
        """
        if not self.enabled or not self._conn:
            return False

        try:
            await self._conn.execute(
                "DELETE FROM enrichment_cache WHERE ip_address = ?",
                (ip_address,),
            )
            await self._conn.commit()
            return True

        except Exception as e:
            logger.error(f"Error clearing cache for {ip_address}: {e}")
            return False

    async def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        if not self.enabled or not self._conn:
            return 0

        try:
            now = int(datetime.utcnow().timestamp())

            cursor = await self._conn.execute(
                """
                DELETE FROM enrichment_cache
                WHERE ttl != -1 AND (timestamp + ttl) < ?
                RETURNING ip_address
                """,
                (now,),
            )

            rows = await cursor.fetchall()
            count = len(rows)

            await self._conn.commit()
            logger.info(f"Cleaned up {count} expired cache entries")
            return count

        except Exception as e:
            logger.error(f"Error cleaning up cache: {e}")
            return 0

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        if not self.enabled or not self._conn:
            return {"enabled": False}

        try:
            # Total entries
            cursor = await self._conn.execute(
                "SELECT COUNT(*) FROM enrichment_cache"
            )
            total = (await cursor.fetchone())[0]

            # Entries by module
            cursor = await self._conn.execute(
                """
                SELECT module, COUNT(*)
                FROM enrichment_cache
                GROUP BY module
                """
            )
            by_module = {row[0]: row[1] for row in await cursor.fetchall()}

            # Database size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            return {
                "enabled": True,
                "total_entries": total,
                "by_module": by_module,
                "db_size_mb": db_size / (1024 * 1024),
                "db_path": str(self.db_path),
            }

        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {"enabled": True, "error": str(e)}

    async def close(self):
        """Close database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None
            logger.info("Cache connection closed")
