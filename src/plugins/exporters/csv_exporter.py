"""CSV and JSON exporter plugins."""

import logging
import json
import csv
from typing import List, Dict, Any
from pathlib import Path
import pandas as pd

from ...core.plugin_system.registry import BasePlugin
from ...core.models import Indicator, PluginInfo, IndicatorType

logger = logging.getLogger(__name__)


class CSVExporter(BasePlugin):
    """CSV format exporter with enrichment data."""
    
    PLUGIN_TYPE = "exporter"
    PLUGIN_NAME = "csv"
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
    
    @property
    def plugin_info(self) -> PluginInfo:
        return PluginInfo(
            name="CSV Exporter",
            version="1.0.0",
            description="Export indicators to CSV format with enrichment data",
            author="Threat Intelligence Platform",
            plugin_type=self.PLUGIN_TYPE,
            supported_indicators=list(IndicatorType),
            required_config=["output_path"],
            optional_config=["include_enrichment", "flatten_data"]
        )
    
    def initialize(self) -> bool:
        """Initialize the CSV exporter."""
        logger.info("CSV exporter initialized successfully")
        return True
    
    def cleanup(self) -> None:
        """Cleanup CSV exporter resources."""
        pass
    
    def health_check(self) -> bool:
        """Check if CSV exporter is healthy."""
        return True
    
    def export_indicators(self, indicators: List[Indicator], output_path: Path) -> bool:
        """Export indicators to CSV format."""
        try:
            if not indicators:
                logger.warning("No indicators to export")
                return True
            
            # Convert indicators to records
            records = []
            include_enrichment = self.config.get('include_enrichment', True)
            flatten_data = self.config.get('flatten_data', True)
            
            for indicator in indicators:
                record = self._indicator_to_record(indicator, include_enrichment, flatten_data)
                records.append(record)
            
            # Create DataFrame
            df = pd.DataFrame(records)
            
            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.suffix.lower() == '.csv':
                df.to_csv(output_path, index=False, encoding='utf-8')
            else:
                # Default to CSV
                csv_path = output_path.with_suffix('.csv')
                df.to_csv(csv_path, index=False, encoding='utf-8')
            
            logger.info(f"Exported {len(records)} indicators to CSV format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV format: {e}")
            return False
    
    def _indicator_to_record(self, indicator: Indicator, include_enrichment: bool, flatten_data: bool) -> Dict[str, Any]:
        """Convert indicator to flat record."""
        record = {
            'value': indicator.value,
            'type': indicator.type,
            'confidence': indicator.confidence,
            'threat_actor_name': indicator.threat_actor_name,
            'threat_actor_id': indicator.threat_actor_id,
            'source': indicator.source,
            'last_seen': indicator.last_seen,
            'first_seen': indicator.first_seen,
            'ic_score': indicator.ic_score,
            'malicious_confidence': indicator.malicious_confidence,
            'created_at': indicator.created_at,
            'is_enriched': indicator.is_enriched
        }
        
        # Add enrichment data if requested and available
        if include_enrichment and indicator.enrichment:
            if flatten_data:
                record.update(self._flatten_enrichment(indicator.enrichment))
            else:
                record['enrichment'] = indicator.enrichment.dict()
        
        # Add metadata
        if indicator.metadata:
            if flatten_data:
                for key, value in indicator.metadata.items():
                    record[f'metadata_{key}'] = value
            else:
                record['metadata'] = indicator.metadata
        
        return record
    
    def _flatten_enrichment(self, enrichment) -> Dict[str, Any]:
        """Flatten enrichment data for CSV export."""
        flat = {}
        
        if enrichment.geolocation:
            geo = enrichment.geolocation
            flat.update({
                'geo_country': geo.country,
                'geo_country_code': geo.country_code,
                'geo_region': geo.region,
                'geo_city': geo.city,
                'geo_latitude': geo.latitude,
                'geo_longitude': geo.longitude,
                'geo_timezone': geo.timezone
            })
        
        if enrichment.asn:
            asn = enrichment.asn
            flat.update({
                'asn_number': asn.asn,
                'asn_organization': asn.organization,
                'asn_network': asn.network
            })
        
        if enrichment.reputation:
            rep = enrichment.reputation
            flat.update({
                'rep_malicious_count': rep.malicious_count,
                'rep_suspicious_count': rep.suspicious_count,
                'rep_clean_count': rep.clean_count,
                'rep_total_sources': rep.total_sources,
                'rep_score': rep.reputation_score,
                'rep_threat_level': rep.threat_level,
                'rep_last_checked': rep.last_checked
            })
        
        if enrichment.threat_classification:
            tc = enrichment.threat_classification
            flat.update({
                'threat_categories': ', '.join(tc.categories) if tc.categories else None,
                'threat_families': ', '.join(tc.families) if tc.families else None,
                'threat_tactics': ', '.join(tc.tactics) if tc.tactics else None,
                'threat_techniques': ', '.join(tc.techniques) if tc.techniques else None
            })
        
        flat.update({
            'enriched_at': enrichment.enriched_at,
            'enrichment_sources': ', '.join(enrichment.enrichment_sources) if enrichment.enrichment_sources else None
        })
        
        return flat


class JSONExporter(BasePlugin):
    """JSON format exporter with full data structure."""
    
    PLUGIN_TYPE = "exporter"
    PLUGIN_NAME = "json"
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
    
    @property
    def plugin_info(self) -> PluginInfo:
        return PluginInfo(
            name="JSON Exporter",
            version="1.0.0",
            description="Export indicators to JSON format with full data structure",
            author="Threat Intelligence Platform",
            plugin_type=self.PLUGIN_TYPE,
            supported_indicators=list(IndicatorType),
            required_config=["output_path"],
            optional_config=["pretty_print", "include_metadata"]
        )
    
    def initialize(self) -> bool:
        """Initialize the JSON exporter."""
        logger.info("JSON exporter initialized successfully")
        return True
    
    def cleanup(self) -> None:
        """Cleanup JSON exporter resources."""
        pass
    
    def health_check(self) -> bool:
        """Check if JSON exporter is healthy."""
        return True
    
    def export_indicators(self, indicators: List[Indicator], output_path: Path) -> bool:
        """Export indicators to JSON format."""
        try:
            if not indicators:
                logger.warning("No indicators to export")
                return True
            
            # Convert indicators to dictionaries
            data = []
            include_metadata = self.config.get('include_metadata', True)
            
            for indicator in indicators:
                indicator_dict = indicator.dict()
                
                # Remove metadata if not requested
                if not include_metadata and 'metadata' in indicator_dict:
                    del indicator_dict['metadata']
                
                data.append(indicator_dict)
            
            # Create output structure
            output_data = {
                "indicators": data,
                "total_count": len(data),
                "export_timestamp": pd.Timestamp.now().isoformat(),
                "format_version": "1.0"
            }
            
            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            pretty_print = self.config.get('pretty_print', True)
            indent = 2 if pretty_print else None
            
            if output_path.suffix.lower() == '.json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=indent, default=str, ensure_ascii=False)
            else:
                # Default to JSON
                json_path = output_path.with_suffix('.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=indent, default=str, ensure_ascii=False)
            
            logger.info(f"Exported {len(data)} indicators to JSON format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSON format: {e}")
            return False


class OpenIOCExporter(BasePlugin):
    """OpenIOC format exporter."""
    
    PLUGIN_TYPE = "exporter"
    PLUGIN_NAME = "openioc"
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
    
    @property
    def plugin_info(self) -> PluginInfo:
        return PluginInfo(
            name="OpenIOC Exporter",
            version="1.0.0",
            description="Export indicators to OpenIOC XML format",
            author="Threat Intelligence Platform",
            plugin_type=self.PLUGIN_TYPE,
            supported_indicators=[
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA1,
                IndicatorType.HASH_SHA256
            ],
            required_config=["output_path"],
            optional_config=["ioc_name", "description"]
        )
    
    def initialize(self) -> bool:
        """Initialize the OpenIOC exporter."""
        logger.info("OpenIOC exporter initialized successfully")
        return True
    
    def cleanup(self) -> None:
        """Cleanup OpenIOC exporter resources."""
        pass
    
    def health_check(self) -> bool:
        """Check if OpenIOC exporter is healthy."""
        return True
    
    def export_indicators(self, indicators: List[Indicator], output_path: Path) -> bool:
        """Export indicators to OpenIOC format."""
        try:
            if not indicators:
                logger.warning("No indicators to export")
                return True
            
            # Create OpenIOC XML structure
            xml_content = self._create_openioc_xml(indicators)
            
            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.suffix.lower() == '.xml':
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
            else:
                # Default to XML
                xml_path = output_path.with_suffix('.xml')
                with open(xml_path, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
            
            logger.info(f"Exported {len(indicators)} indicators to OpenIOC format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to OpenIOC format: {e}")
            return False
    
    def _create_openioc_xml(self, indicators: List[Indicator]) -> str:
        """Create OpenIOC XML content."""
        ioc_name = self.config.get('ioc_name', 'Threat Intelligence IOCs')
        description = self.config.get('description', 'IOCs exported from Threat Intelligence Platform')
        
        xml_parts = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<ioc xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="threat-intel-ioc" last-modified="' + pd.Timestamp.now().isoformat() + '" xmlns="http://schemas.mandiant.com/2010/ioc">',
            f'  <short_description>{ioc_name}</short_description>',
            f'  <description>{description}</description>',
            '  <authored_by>Threat Intelligence Platform</authored_by>',
            '  <authored_date>' + pd.Timestamp.now().strftime('%Y-%m-%dT%H:%M:%S') + '</authored_date>',
            '  <links/>',
            '  <definition>'
        ]
        
        # Add OR logic for all indicators
        if len(indicators) > 1:
            xml_parts.append('    <Indicator operator="OR" id="root">')
        
        for i, indicator in enumerate(indicators):
            indicator_xml = self._indicator_to_openioc(indicator, f"indicator_{i}")
            if indicator_xml:
                xml_parts.append(f'      {indicator_xml}')
        
        if len(indicators) > 1:
            xml_parts.append('    </Indicator>')
        
        xml_parts.extend([
            '  </definition>',
            '</ioc>'
        ])
        
        return '\n'.join(xml_parts)
    
    def _indicator_to_openioc(self, indicator: Indicator, indicator_id: str) -> str:
        """Convert indicator to OpenIOC IndicatorItem."""
        search_map = self._get_openioc_search_map(indicator)
        if not search_map:
            return ""
        
        return f'<IndicatorItem id="{indicator_id}" condition="is" preserve-case="false" negate="false">' + \
               f'<Context document="Network" search="{search_map}" type="mir"/>' + \
               f'<Content type="string">{indicator.value}</Content>' + \
               '</IndicatorItem>'
    
    def _get_openioc_search_map(self, indicator: Indicator) -> str:
        """Get OpenIOC search map for indicator type."""
        mapping = {
            IndicatorType.IP: "Network/IP",
            IndicatorType.DOMAIN: "Network/DNS",
            IndicatorType.URL: "Network/URL",
            IndicatorType.HASH_MD5: "FileItem/Md5sum",
            IndicatorType.HASH_SHA1: "FileItem/Sha1sum",
            IndicatorType.HASH_SHA256: "FileItem/Sha256sum"
        }
        
        return mapping.get(indicator.type, "")