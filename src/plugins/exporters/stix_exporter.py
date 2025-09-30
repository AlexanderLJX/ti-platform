"""STIX format exporter plugin."""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import json

from ...core.plugin_system.registry import BasePlugin
from ...core.models import Indicator, PluginInfo, IndicatorType

try:
    from stix2 import Indicator as STIXIndicator, Bundle, Identity, TLP_WHITE
    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False

logger = logging.getLogger(__name__)


class STIXExporter(BasePlugin):
    """STIX 2.1 format exporter."""
    
    PLUGIN_TYPE = "exporter"
    PLUGIN_NAME = "stix"
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.identity = None
    
    @property
    def plugin_info(self) -> PluginInfo:
        return PluginInfo(
            name="STIX Exporter",
            version="1.0.0",
            description="Export indicators in STIX 2.1 format",
            author="Threat Intelligence Platform",
            plugin_type=self.PLUGIN_TYPE,
            supported_indicators=[
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.EMAIL,
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA1,
                IndicatorType.HASH_SHA256
            ],
            required_config=["output_path"],
            optional_config=["organization_name", "organization_identity"]
        )
    
    def initialize(self) -> bool:
        """Initialize the STIX exporter."""
        if not STIX_AVAILABLE:
            logger.error("stix2 library not available. Install with: pip install stix2")
            return False
        
        # Create organization identity
        org_name = self.config.get('organization_name', 'Threat Intelligence Platform')
        self.identity = Identity(
            name=org_name,
            identity_class="organization"
        )
        
        logger.info("STIX exporter initialized successfully")
        return True
    
    def cleanup(self) -> None:
        """Cleanup STIX exporter resources."""
        self.identity = None
    
    def health_check(self) -> bool:
        """Check if STIX exporter is healthy."""
        return STIX_AVAILABLE and self.identity is not None
    
    def export_indicators(self, indicators: List[Indicator], output_path: Path) -> bool:
        """Export indicators to STIX format."""
        try:
            if not indicators:
                logger.warning("No indicators to export")
                return True
            
            # Convert indicators to STIX objects
            stix_indicators = []
            for indicator in indicators:
                stix_indicator = self._convert_to_stix(indicator)
                if stix_indicator:
                    stix_indicators.append(stix_indicator)
            
            if not stix_indicators:
                logger.warning("No valid STIX indicators created")
                return True
            
            # Create STIX bundle
            bundle = Bundle(
                objects=[self.identity] + stix_indicators,
                allow_custom=True
            )
            
            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.suffix.lower() == '.json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(bundle.serialize(pretty=True))
            else:
                # Default to JSON
                json_path = output_path.with_suffix('.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    f.write(bundle.serialize(pretty=True))
            
            logger.info(f"Exported {len(stix_indicators)} indicators to STIX format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to STIX format: {e}")
            return False
    
    def _convert_to_stix(self, indicator: Indicator) -> Optional[STIXIndicator]:
        """Convert platform indicator to STIX indicator."""
        try:
            # Map indicator type to STIX pattern
            pattern = self._create_stix_pattern(indicator)
            if not pattern:
                logger.warning(f"Unsupported indicator type for STIX: {indicator.type}")
                return None
            
            # Map confidence
            confidence = self._map_confidence(indicator.confidence)
            
            # Create labels based on threat actor and source
            labels = ["malicious-activity"]
            if indicator.threat_actor_name and indicator.threat_actor_name.lower() != "unknown":
                labels.append("attribution")
            
            # Create STIX indicator
            stix_indicator = STIXIndicator(
                pattern=pattern,
                labels=labels,
                confidence=confidence,
                created_by_ref=self.identity.id
            )
            
            # Add custom properties
            custom_properties = {
                "x_ti_platform_source": indicator.source,
                "x_ti_platform_actor": indicator.threat_actor_name,
                "x_ti_platform_created": indicator.created_at.isoformat()
            }
            
            if indicator.ic_score is not None:
                custom_properties["x_ti_platform_ic_score"] = indicator.ic_score
            
            if indicator.enrichment:
                custom_properties.update(self._add_enrichment_properties(indicator.enrichment))
            
            # Add custom properties to STIX indicator
            for key, value in custom_properties.items():
                setattr(stix_indicator, key, value)
            
            return stix_indicator
            
        except Exception as e:
            logger.error(f"Error converting indicator {indicator.value} to STIX: {e}")
            return None
    
    def _create_stix_pattern(self, indicator: Indicator) -> Optional[str]:
        """Create STIX pattern from indicator."""
        value = indicator.value
        
        if indicator.type == IndicatorType.IP:
            return f"[ipv4-addr:value = '{value}']"
        elif indicator.type in [IndicatorType.DOMAIN, IndicatorType.FQDN]:
            return f"[domain-name:value = '{value}']"
        elif indicator.type == IndicatorType.URL:
            return f"[url:value = '{value}']"
        elif indicator.type == IndicatorType.EMAIL:
            return f"[email-addr:value = '{value}']"
        elif indicator.type == IndicatorType.HASH_MD5:
            return f"[file:hashes.MD5 = '{value}']"
        elif indicator.type == IndicatorType.HASH_SHA1:
            return f"[file:hashes.SHA-1 = '{value}']"
        elif indicator.type == IndicatorType.HASH_SHA256:
            return f"[file:hashes.SHA-256 = '{value}']"
        else:
            return None
    
    def _map_confidence(self, confidence) -> int:
        """Map platform confidence to STIX confidence (0-100)."""
        if not confidence:
            return 50  # Default medium confidence
        
        confidence_str = str(confidence).lower()
        if confidence_str == "high":
            return 85
        elif confidence_str == "medium":
            return 50
        elif confidence_str == "low":
            return 15
        else:
            return 50
    
    def _add_enrichment_properties(self, enrichment) -> Dict[str, Any]:
        """Add enrichment data as custom STIX properties."""
        properties = {}
        
        if enrichment.geolocation:
            geo = enrichment.geolocation
            properties.update({
                "x_ti_platform_country": geo.country,
                "x_ti_platform_country_code": geo.country_code,
                "x_ti_platform_city": geo.city
            })
        
        if enrichment.asn:
            asn = enrichment.asn
            properties.update({
                "x_ti_platform_asn": asn.asn,
                "x_ti_platform_org": asn.organization
            })
        
        if enrichment.reputation:
            rep = enrichment.reputation
            properties.update({
                "x_ti_platform_malicious_count": rep.malicious_count,
                "x_ti_platform_reputation_score": rep.reputation_score
            })
        
        return properties


class MISPExporter(BasePlugin):
    """MISP format exporter."""
    
    PLUGIN_TYPE = "exporter"
    PLUGIN_NAME = "misp"
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
    
    @property
    def plugin_info(self) -> PluginInfo:
        return PluginInfo(
            name="MISP Exporter",
            version="1.0.0",
            description="Export indicators in MISP JSON format",
            author="Threat Intelligence Platform",
            plugin_type=self.PLUGIN_TYPE,
            supported_indicators=[
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.EMAIL,
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA1,
                IndicatorType.HASH_SHA256
            ],
            required_config=["output_path"],
            optional_config=["event_info", "threat_level"]
        )
    
    def initialize(self) -> bool:
        """Initialize the MISP exporter."""
        logger.info("MISP exporter initialized successfully")
        return True
    
    def cleanup(self) -> None:
        """Cleanup MISP exporter resources."""
        pass
    
    def health_check(self) -> bool:
        """Check if MISP exporter is healthy."""
        return True
    
    def export_indicators(self, indicators: List[Indicator], output_path: Path) -> bool:
        """Export indicators to MISP format."""
        try:
            if not indicators:
                logger.warning("No indicators to export")
                return True
            
            # Create MISP event structure
            event = {
                "Event": {
                    "info": self.config.get('event_info', 'Threat Intelligence Import'),
                    "threat_level_id": self.config.get('threat_level', 3),
                    "analysis": 2,  # Completed
                    "distribution": 0,  # Your organization only
                    "date": datetime.now().strftime('%Y-%m-%d'),
                    "published": False,
                    "Attribute": []
                }
            }
            
            # Convert indicators to MISP attributes
            for indicator in indicators:
                misp_attr = self._convert_to_misp_attribute(indicator)
                if misp_attr:
                    event["Event"]["Attribute"].append(misp_attr)
            
            if not event["Event"]["Attribute"]:
                logger.warning("No valid MISP attributes created")
                return True
            
            # Save to file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            if output_path.suffix.lower() == '.json':
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(event, f, indent=2, default=str)
            else:
                # Default to JSON
                json_path = output_path.with_suffix('.json')
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(event, f, indent=2, default=str)
            
            logger.info(f"Exported {len(event['Event']['Attribute'])} indicators to MISP format: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to MISP format: {e}")
            return False
    
    def _convert_to_misp_attribute(self, indicator: Indicator) -> Optional[Dict[str, Any]]:
        """Convert platform indicator to MISP attribute."""
        try:
            # Map indicator type to MISP type
            misp_type = self._map_to_misp_type(indicator.type)
            if not misp_type:
                return None
            
            attribute = {
                "type": misp_type,
                "value": indicator.value,
                "category": "Network activity",
                "to_ids": True,
                "distribution": 0,
                "comment": f"Source: {indicator.source}, Actor: {indicator.threat_actor_name}"
            }
            
            # Add tags
            tags = []
            if indicator.threat_actor_name and indicator.threat_actor_name.lower() != "unknown":
                tags.append({"name": f"threat-actor:{indicator.threat_actor_name}"})
            
            tags.append({"name": f"source:{indicator.source}"})
            
            if indicator.confidence:
                tags.append({"name": f"confidence:{indicator.confidence}"})
            
            if tags:
                attribute["Tag"] = tags
            
            return attribute
            
        except Exception as e:
            logger.error(f"Error converting indicator {indicator.value} to MISP: {e}")
            return None
    
    def _map_to_misp_type(self, indicator_type: IndicatorType) -> Optional[str]:
        """Map platform indicator type to MISP type."""
        mapping = {
            IndicatorType.IP: "ip-dst",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.FQDN: "hostname",
            IndicatorType.URL: "url",
            IndicatorType.EMAIL: "email-src",
            IndicatorType.HASH_MD5: "md5",
            IndicatorType.HASH_SHA1: "sha1",
            IndicatorType.HASH_SHA256: "sha256"
        }
        
        return mapping.get(indicator_type)