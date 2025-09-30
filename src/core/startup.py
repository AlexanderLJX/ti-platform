"""Platform startup and initialization."""

import logging
from pathlib import Path
from typing import List

from .plugin_system.registry import plugin_registry

logger = logging.getLogger(__name__)


def initialize_platform():
    """Initialize the threat intelligence platform.
    
    This function should be called during platform startup to:
    - Load built-in plugins
    - Discover external plugins
    - Initialize plugin registry
    """
    logger.info("Initializing Threat Intelligence Platform...")
    
    try:
        # Load built-in plugins
        _load_builtin_plugins()
        
        # Discover external plugins
        _discover_external_plugins()
        
        # Log plugin status
        _log_plugin_status()
        
        logger.info("Platform initialization completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Platform initialization failed: {e}")
        return False


def _load_builtin_plugins():
    """Load built-in plugins from the plugins package."""
    logger.info("Loading built-in plugins...")
    
    try:
        # Import plugins to trigger registration
        import src.plugins.scrapers  # This triggers plugin registration
        import src.plugins.exporters  # This triggers plugin registration
        
        logger.info("Built-in plugins loaded successfully")
        
    except Exception as e:
        logger.error(f"Error loading built-in plugins: {e}")
        raise


def _discover_external_plugins():
    """Discover and load external plugins from plugin directories."""
    logger.info("Discovering external plugins...")
    
    # Plugin directories to search
    plugin_dirs = [
        Path("plugins"),  # Local plugins directory
        Path.home() / ".ti-platform" / "plugins",  # User plugins
    ]
    
    try:
        plugin_registry.discover_plugins(plugin_dirs)
        logger.info("External plugin discovery completed")
        
    except Exception as e:
        logger.warning(f"Error during external plugin discovery: {e}")


def _log_plugin_status():
    """Log the status of all loaded plugins."""
    try:
        scrapers = plugin_registry.get_available_scrapers()
        enrichers = plugin_registry.get_available_enrichers()
        exporters = plugin_registry.get_available_exporters()
        processors = plugin_registry.get_available_processors()
        
        logger.info(f"Plugin registry status:")
        logger.info(f"  Scrapers: {len(scrapers)} ({', '.join(scrapers)})")
        logger.info(f"  Enrichers: {len(enrichers)} ({', '.join(enrichers)})")
        logger.info(f"  Exporters: {len(exporters)} ({', '.join(exporters)})")
        logger.info(f"  Processors: {len(processors)} ({', '.join(processors)})")
        
    except Exception as e:
        logger.warning(f"Error logging plugin status: {e}")


def cleanup_platform():
    """Cleanup platform resources on shutdown."""
    logger.info("Cleaning up platform resources...")
    
    try:
        # Cleanup all plugin instances
        plugin_registry.cleanup_all_instances()
        logger.info("Platform cleanup completed")
        
    except Exception as e:
        logger.error(f"Error during platform cleanup: {e}")


def get_platform_info():
    """Get platform information and status."""
    return {
        "version": "0.2.0",
        "name": "Threat Intelligence Platform",
        "plugins": {
            "scrapers": plugin_registry.get_available_scrapers(),
            "enrichers": plugin_registry.get_available_enrichers(), 
            "exporters": plugin_registry.get_available_exporters(),
            "processors": plugin_registry.get_available_processors()
        }
    }