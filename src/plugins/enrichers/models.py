"""Data models for IP enrichment."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
import ipaddress


class GeolocationData(BaseModel):
    """Geolocation information for an IP address."""
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    accuracy_radius: Optional[int] = None
    source: Optional[str] = None
    confidence: float = 0.0


class NetworkData(BaseModel):
    """Network and routing information."""
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    asn_org: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    cidr: Optional[str] = None
    network_type: Optional[str] = None  # residential, business, hosting, mobile
    peers: List[int] = Field(default_factory=list)
    upstreams: List[int] = Field(default_factory=list)
    downstreams: List[int] = Field(default_factory=list)
    source: Optional[str] = None
    confidence: float = 0.0


class CloudData(BaseModel):
    """Cloud infrastructure detection."""
    is_cloud: bool = False
    cloud_provider: Optional[str] = None  # aws, azure, gcp, cloudflare, etc.
    cloud_region: Optional[str] = None
    cloud_service: Optional[str] = None  # ec2, compute, functions, etc.
    cloud_zone: Optional[str] = None
    source: Optional[str] = None
    confidence: float = 0.0


class AnonymizationData(BaseModel):
    """Anonymization service detection."""
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_relay: bool = False
    anonymization_service: Optional[str] = None
    proxy_type: Optional[str] = None  # vpn, datacenter, residential, tor, etc.
    risk_score: Optional[int] = None  # 0-100
    source: Optional[str] = None
    confidence: float = 0.0


class ScannerData(BaseModel):
    """Internet scanner detection."""
    is_scanner: bool = False
    scanner_name: Optional[str] = None  # shodan, censys, binaryedge, etc.
    scanner_type: Optional[str] = None  # benign, malicious, research
    scanner_tags: List[str] = Field(default_factory=list)
    scanning_behavior: List[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source: Optional[str] = None
    confidence: float = 0.0


class ThreatData(BaseModel):
    """Threat intelligence and reputation."""
    reputation_score: Optional[int] = None  # 0-100, higher is worse
    threat_level: Optional[str] = None  # low, medium, high, critical
    is_malicious: bool = False
    malware_families: List[str] = Field(default_factory=list)
    attack_types: List[str] = Field(default_factory=list)
    abuse_categories: List[str] = Field(default_factory=list)
    botnet_associations: List[str] = Field(default_factory=list)
    first_seen_malicious: Optional[datetime] = None
    last_seen_malicious: Optional[datetime] = None
    abuse_report_count: int = 0
    sources: List[str] = Field(default_factory=list)
    confidence: float = 0.0


class CertificateData(BaseModel):
    """SSL/TLS certificate intelligence."""
    certificate_count: int = 0
    associated_domains: List[str] = Field(default_factory=list)
    certificate_issuers: List[str] = Field(default_factory=list)
    certificate_hashes: List[str] = Field(default_factory=list)
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    self_signed: Optional[bool] = None
    source: Optional[str] = None
    confidence: float = 0.0


class PassiveDNSData(BaseModel):
    """Passive DNS and historical data."""
    historical_domains: List[str] = Field(default_factory=list)
    domain_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    resolution_count: int = 0
    unique_domains: int = 0
    source: Optional[str] = None
    confidence: float = 0.0


class EnrichedIPProfile(BaseModel):
    """Comprehensive IP enrichment profile."""

    # Core identification
    ip_address: str
    is_valid: bool = True
    is_private: bool = False
    is_reserved: bool = False
    version: int = 4  # 4 or 6

    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    last_updated: Optional[datetime] = None

    # Enrichment data
    geolocation: Optional[GeolocationData] = None
    network: Optional[NetworkData] = None
    cloud: Optional[CloudData] = None
    anonymization: Optional[AnonymizationData] = None
    scanner: Optional[ScannerData] = None
    threat: Optional[ThreatData] = None
    certificates: Optional[CertificateData] = None
    passive_dns: Optional[PassiveDNSData] = None

    # Metadata
    enrichment_sources: List[str] = Field(default_factory=list)
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    cache_hit: bool = False
    enrichment_duration_ms: Optional[float] = None

    # Raw data from sources (optional)
    raw_data: Dict[str, Any] = Field(default_factory=dict)

    @validator('ip_address')
    def validate_ip(cls, v):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")

    def is_threat(self) -> bool:
        """Check if IP has threat indicators."""
        if not self.threat:
            return False
        return self.threat.is_malicious or (
            self.threat.reputation_score and self.threat.reputation_score > 50
        )

    def is_anonymous(self) -> bool:
        """Check if IP uses anonymization."""
        if not self.anonymization:
            return False
        return (
            self.anonymization.is_vpn
            or self.anonymization.is_proxy
            or self.anonymization.is_tor
            or self.anonymization.is_relay
        )

    def get_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        risk = 0
        weight_total = 0

        # Threat score (weight: 0.5)
        if self.threat and self.threat.reputation_score:
            risk += self.threat.reputation_score * 0.5
            weight_total += 0.5

        # Anonymization score (weight: 0.2)
        if self.anonymization:
            anon_risk = 0
            if self.anonymization.is_tor:
                anon_risk = 80
            elif self.anonymization.is_vpn or self.anonymization.is_proxy:
                anon_risk = self.anonymization.risk_score or 40
            risk += anon_risk * 0.2
            weight_total += 0.2

        # Scanner score (weight: 0.15)
        if self.scanner and self.scanner.is_scanner:
            scanner_risk = 10 if self.scanner.scanner_type == "benign" else 60
            risk += scanner_risk * 0.15
            weight_total += 0.15

        # Cloud hosting (weight: 0.15)
        if self.cloud and self.cloud.is_cloud:
            risk += 20 * 0.15  # Moderate risk for cloud
            weight_total += 0.15

        # Normalize
        if weight_total > 0:
            return int(risk)
        return 0

    def get_classification(self) -> str:
        """Get classification based on risk score."""
        risk = self.get_risk_score()
        if risk >= 75:
            return "critical"
        elif risk >= 50:
            return "high"
        elif risk >= 25:
            return "medium"
        else:
            return "low"

    def to_summary(self) -> Dict[str, Any]:
        """Generate a summary dictionary."""
        return {
            "ip_address": self.ip_address,
            "risk_score": self.get_risk_score(),
            "classification": self.get_classification(),
            "is_threat": self.is_threat(),
            "is_anonymous": self.is_anonymous(),
            "country": self.geolocation.country if self.geolocation else None,
            "asn": self.network.asn if self.network else None,
            "cloud_provider": self.cloud.cloud_provider if self.cloud else None,
            "is_scanner": self.scanner.is_scanner if self.scanner else False,
            "enrichment_sources": self.enrichment_sources,
            "timestamp": self.timestamp.isoformat(),
        }

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
