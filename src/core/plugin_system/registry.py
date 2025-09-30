"""Plugin registry and management system."""

import logging
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Type, Optional, Any
from abc import ABC, abstractmethod

from ..models import PluginInfo, PluginStatus

logger = logging.getLogger(__name__)


class BasePlugin(ABC):
    """Base class for all plugins in the threat intelligence platform."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.plugin_config = config
        self.status = PluginStatus.INACTIVE
    
    @property
    @abstractmethod
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        pass
    
    @abstractmethod
    def health_check(self) -> bool:
        """Check if plugin is healthy and operational."""
        pass


class PluginRegistry:
    """Central registry for managing all plugins."""
    
    def __init__(self):
        self.scrapers: Dict[str, Type[BasePlugin]] = {}
        self.enrichers: Dict[str, Type[BasePlugin]] = {}
        self.exporters: Dict[str, Type[BasePlugin]] = {}
        self.processors: Dict[str, Type[BasePlugin]] = {}
        self._instances: Dict[str, BasePlugin] = {}
    
    def register_scraper(self, name: str, plugin_class: Type[BasePlugin]) -> None:
        """Register a scraper plugin."""
        if not issubclass(plugin_class, BasePlugin):
            raise ValueError(f"Plugin {name} must inherit from BasePlugin")
        
        self.scrapers[name] = plugin_class
        logger.info(f"Registered scraper plugin: {name}")
    
    def register_enricher(self, name: str, plugin_class: Type[BasePlugin]) -> None:
        """Register an enricher plugin."""
        if not issubclass(plugin_class, BasePlugin):
            raise ValueError(f"Plugin {name} must inherit from BasePlugin")
        
        self.enrichers[name] = plugin_class
        logger.info(f"Registered enricher plugin: {name}")
    
    def register_exporter(self, name: str, plugin_class: Type[BasePlugin]) -> None:
        """Register an exporter plugin."""
        if not issubclass(plugin_class, BasePlugin):
            raise ValueError(f"Plugin {name} must inherit from BasePlugin")
        
        self.exporters[name] = plugin_class
        logger.info(f"Registered exporter plugin: {name}")
    
    def register_processor(self, name: str, plugin_class: Type[BasePlugin]) -> None:
        """Register a processor plugin."""
        if not issubclass(plugin_class, BasePlugin):
            raise ValueError(f"Plugin {name} must inherit from BasePlugin")
        
        self.processors[name] = plugin_class
        logger.info(f"Registered processor plugin: {name}")
    
    def get_available_scrapers(self) -> List[str]:
        """Get list of available scraper plugins."""
        return list(self.scrapers.keys())
    
    def get_available_enrichers(self) -> List[str]:
        """Get list of available enricher plugins."""
        return list(self.enrichers.keys())
    
    def get_available_exporters(self) -> List[str]:
        """Get list of available exporter plugins."""
        return list(self.exporters.keys())
    
    def get_available_processors(self) -> List[str]:
        """Get list of available processor plugins."""
        return list(self.processors.keys())
    
    def get_plugin_instance(self, plugin_type: str, name: str, config: Dict[str, Any]) -> Optional[BasePlugin]:
        """Get or create a plugin instance."""
        instance_key = f"{plugin_type}:{name}"
        
        if instance_key in self._instances:
            return self._instances[instance_key]
        
        plugin_registries = {
            "scraper": self.scrapers,
            "enricher": self.enrichers,
            "exporter": self.exporters,
            "processor": self.processors
        }
        
        registry = plugin_registries.get(plugin_type)
        if not registry or name not in registry:
            logger.error(f"Plugin {plugin_type}:{name} not found")
            return None
        
        try:
            plugin_class = registry[name]
            instance = plugin_class(name, config)
            
            if instance.initialize():
                instance.status = PluginStatus.ACTIVE
                self._instances[instance_key] = instance
                logger.info(f"Created and initialized plugin instance: {instance_key}")
                return instance
            else:
                logger.error(f"Failed to initialize plugin: {instance_key}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating plugin instance {instance_key}: {e}")
            return None
    
    def cleanup_all_instances(self) -> None:
        """Cleanup all plugin instances."""
        for instance_key, instance in self._instances.items():
            try:
                instance.cleanup()
                instance.status = PluginStatus.INACTIVE
                logger.info(f"Cleaned up plugin instance: {instance_key}")
            except Exception as e:
                logger.error(f"Error cleaning up plugin {instance_key}: {e}")
        
        self._instances.clear()
    
    def discover_plugins(self, plugin_dirs: List[Path]) -> None:
        """Auto-discover plugins from specified directories."""
        for plugin_dir in plugin_dirs:
            if not plugin_dir.exists():
                continue
            
            logger.info(f"Discovering plugins in: {plugin_dir}")
            
            for plugin_file in plugin_dir.rglob("*.py"):
                if plugin_file.name.startswith("_"):
                    continue
                
                self._load_plugin_from_file(plugin_file)
    
    def _load_plugin_from_file(self, plugin_file: Path) -> None:
        """Load plugin from a Python file."""
        try:
            # Create module spec and load module
            spec = importlib.util.spec_from_file_location(
                f"plugin_{plugin_file.stem}", 
                plugin_file
            )
            if not spec or not spec.loader:
                return
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BasePlugin) and 
                    obj is not BasePlugin and 
                    hasattr(obj, 'PLUGIN_TYPE')):
                    
                    plugin_type = getattr(obj, 'PLUGIN_TYPE')
                    plugin_name = getattr(obj, 'PLUGIN_NAME', name.lower())
                    
                    # Register based on plugin type
                    if plugin_type == "scraper":
                        self.register_scraper(plugin_name, obj)
                    elif plugin_type == "enricher":
                        self.register_enricher(plugin_name, obj)
                    elif plugin_type == "exporter":
                        self.register_exporter(plugin_name, obj)
                    elif plugin_type == "processor":
                        self.register_processor(plugin_name, obj)
                    
        except Exception as e:
            logger.error(f"Error loading plugin from {plugin_file}: {e}")


# Global plugin registry instance
plugin_registry = PluginRegistry()