"""Data models for threat intelligence scraping."""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, validator
import ipaddress
import validators


class ConfidenceLevel(str, Enum):
    """Confidence levels for indicators."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class IndicatorType(str, Enum):
    """Types of indicators."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FQDN = "fqdn"
    EMAIL = "email"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    YARA_RULE = "yara_rule"
    OTHER = "other"


class ScrapingStatus(str, Enum):
    """Status of scraping operations."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PluginStatus(str, Enum):
    """Status of plugins."""
    INACTIVE = "inactive"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"


class ThreatLevel(str, Enum):
    """Threat levels for classification."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatActor(BaseModel):
    """Model for threat actor information."""
    name: str = Field(..., description="Threat actor name")
    slug: Optional[str] = Field(None, description="URL slug or identifier")
    url: Optional[str] = Field(None, description="Full URL or ID")
    source: str = Field(..., description="Source platform (mandiant, crowdstrike)")
    active: bool = Field(True, description="Whether to scrape this actor")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        """Pydantic configuration."""
        str_strip_whitespace = True


class Indicator(BaseModel):
    """Model for threat indicators."""
    value: str = Field(..., description="The indicator value")
    type: IndicatorType = Field(..., description="Type of indicator")
    confidence: Optional[ConfidenceLevel] = Field(None, description="Confidence level")
    threat_actor_name: str = Field(..., description="Associated threat actor")
    threat_actor_id: Optional[str] = Field(None, description="Threat actor identifier")
    source: str = Field(..., description="Source platform")
    last_seen: Optional[datetime] = Field(None, description="Last seen date")
    first_seen: Optional[datetime] = Field(None, description="First seen date")
    ic_score: Optional[float] = Field(None, description="IC score (0-100)")
    malicious_confidence: Optional[str] = Field(None, description="Original confidence value")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    created_at: datetime = Field(default_factory=datetime.now, description="When record was created")
    enrichment: Optional['IOCEnrichment'] = Field(None, description="Enrichment data")
    is_enriched: bool = Field(default=False, description="Whether indicator has been enriched")

    @validator('value')
    def clean_value(cls, v):
        """Clean the indicator value."""
        if not v:
            raise ValueError("Indicator value cannot be empty")
        return str(v).strip()

    @validator('confidence', pre=True)
    def parse_confidence(cls, v, values):
        """Parse confidence from various formats."""
        if v is None:
            return None
        
        if isinstance(v, str):
            v_lower = v.lower()
            if v_lower in ['low', 'medium', 'high']:
                return v.title()
        
        # Try to convert IC score to confidence
        ic_score = values.get('ic_score')
        if ic_score is not None:
            try:
                score = float(ic_score)
                if 0 <= score < 25:
                    return ConfidenceLevel.LOW
                elif 25 <= score < 75:
                    return ConfidenceLevel.MEDIUM
                elif 75 <= score <= 100:
                    return ConfidenceLevel.HIGH
            except (ValueError, TypeError):
                pass
        
        return v

    class Config:
        """Pydantic configuration."""
        str_strip_whitespace = True
        use_enum_values = True


class ScrapingJob(BaseModel):
    """Model for scraping job tracking."""
    id: str = Field(..., description="Unique job identifier")
    source: str = Field(..., description="Source platform")
    threat_actor: ThreatActor = Field(..., description="Threat actor being scraped")
    status: ScrapingStatus = Field(default=ScrapingStatus.PENDING, description="Job status")
    started_at: Optional[datetime] = Field(None, description="When job started")
    completed_at: Optional[datetime] = Field(None, description="When job completed")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    indicators_count: int = Field(default=0, description="Number of indicators found")
    file_path: Optional[str] = Field(None, description="Path to downloaded file")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional job metadata")

    class Config:
        """Pydantic configuration."""
        str_strip_whitespace = True
        use_enum_values = True


class ScrapingConfig(BaseModel):
    """Model for scraper configuration."""
    source: str = Field(..., description="Source platform name")
    enabled: bool = Field(True, description="Whether scraper is enabled")
    name: str = Field(..., description="Display name")
    base_url: str = Field(..., description="Base URL")
    login_url: str = Field(..., description="Login URL")
    download_timeout: int = Field(30, description="Download timeout in seconds")
    retry_attempts: int = Field(3, description="Number of retry attempts")
    profile_path: str = Field(..., description="Chrome profile path")
    download_path: str = Field(..., description="Download directory")
    output_path: str = Field(..., description="Output directory")

    class Config:
        """Pydantic configuration."""
        str_strip_whitespace = True


class ProcessingResult(BaseModel):
    """Model for processing results."""
    total_indicators: int = Field(0, description="Total indicators processed")
    valid_indicators: int = Field(0, description="Valid indicators")
    filtered_indicators: int = Field(0, description="Indicators filtered out")
    errors: List[str] = Field(default_factory=list, description="Processing errors")
    processing_time: float = Field(0.0, description="Processing time in seconds")
    output_files: List[str] = Field(default_factory=list, description="Generated output files")
    
    class Config:
        """Pydantic configuration."""
        str_strip_whitespace = True


class GeolocationData(BaseModel):
    """Geolocation enrichment data."""
    country: Optional[str] = Field(None, description="Country name")
    country_code: Optional[str] = Field(None, description="ISO country code")
    region: Optional[str] = Field(None, description="Region/state")
    city: Optional[str] = Field(None, description="City name")
    latitude: Optional[float] = Field(None, description="Latitude coordinate")
    longitude: Optional[float] = Field(None, description="Longitude coordinate")
    timezone: Optional[str] = Field(None, description="Timezone")
    
    class Config:
        str_strip_whitespace = True


class ASNData(BaseModel):
    """ASN enrichment data."""
    asn: Optional[int] = Field(None, description="ASN number")
    organization: Optional[str] = Field(None, description="Organization name")
    network: Optional[str] = Field(None, description="Network CIDR")
    
    class Config:
        str_strip_whitespace = True


class ReputationData(BaseModel):
    """Reputation enrichment data."""
    malicious_count: int = Field(default=0, description="Number of sources marking as malicious")
    suspicious_count: int = Field(default=0, description="Number of sources marking as suspicious")
    clean_count: int = Field(default=0, description="Number of sources marking as clean")
    total_sources: int = Field(default=0, description="Total sources checked")
    reputation_score: Optional[float] = Field(None, description="Overall reputation score (0-100)")
    threat_level: Optional[ThreatLevel] = Field(None, description="Assessed threat level")
    last_checked: Optional[datetime] = Field(None, description="Last reputation check")
    
    class Config:
        str_strip_whitespace = True
        use_enum_values = True


class ThreatClassification(BaseModel):
    """Threat classification data."""
    categories: List[str] = Field(default_factory=list, description="Threat categories")
    families: List[str] = Field(default_factory=list, description="Malware families")
    tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    
    class Config:
        str_strip_whitespace = True


class IOCEnrichment(BaseModel):
    """Comprehensive IOC enrichment data."""
    geolocation: Optional[GeolocationData] = Field(None, description="Geographic information")
    asn: Optional[ASNData] = Field(None, description="ASN information")
    reputation: Optional[ReputationData] = Field(None, description="Reputation data")
    threat_classification: Optional[ThreatClassification] = Field(None, description="Threat classification")
    whois_data: Optional[Dict[str, Any]] = Field(None, description="WHOIS information")
    dns_data: Optional[Dict[str, Any]] = Field(None, description="DNS resolution data")
    enriched_at: Optional[datetime] = Field(None, description="When enrichment was performed")
    enrichment_sources: List[str] = Field(default_factory=list, description="Sources used for enrichment")
    
    class Config:
        str_strip_whitespace = True


class PluginInfo(BaseModel):
    """Plugin metadata information."""
    name: str = Field(..., description="Plugin name")
    version: str = Field(..., description="Plugin version")
    description: str = Field(..., description="Plugin description")
    author: str = Field(..., description="Plugin author")
    plugin_type: str = Field(..., description="Type of plugin (scraper, enricher, etc.)")
    supported_indicators: List[IndicatorType] = Field(default_factory=list, description="Supported indicator types")
    required_config: List[str] = Field(default_factory=list, description="Required configuration fields")
    optional_config: List[str] = Field(default_factory=list, description="Optional configuration fields")
    
    class Config:
        str_strip_whitespace = True
        use_enum_values = True