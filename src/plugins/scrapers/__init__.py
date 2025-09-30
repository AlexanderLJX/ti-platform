"""Built-in scraper plugins."""

from ...scrapers.mandiant.scraper import MandiantScraper
from ...scrapers.crowdstrike.scraper import CrowdStrikeScraper
from ...core.plugin_system.registry import plugin_registry

# Register built-in scrapers
plugin_registry.register_scraper("mandiant", MandiantScraper)
plugin_registry.register_scraper("crowdstrike", CrowdStrikeScraper)