"""Built-in export plugins."""

from .stix_exporter import STIXExporter, MISPExporter
from .csv_exporter import CSVExporter, JSONExporter, OpenIOCExporter
from ...core.plugin_system.registry import plugin_registry

# Register built-in exporters
plugin_registry.register_exporter("stix", STIXExporter)
plugin_registry.register_exporter("misp", MISPExporter)
plugin_registry.register_exporter("csv", CSVExporter)
plugin_registry.register_exporter("json", JSONExporter)
plugin_registry.register_exporter("openioc", OpenIOCExporter)