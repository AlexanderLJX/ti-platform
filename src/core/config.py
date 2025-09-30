"""Configuration management for threat intelligence scraper."""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv

from .models import ScrapingConfig, ThreatActor


class BrowserConfig(BaseModel):
    """Browser configuration."""
    headless: bool = Field(False, description="Run browser in headless mode")
    download_timeout: int = Field(30, description="Download timeout in seconds")
    page_load_timeout: int = Field(20, description="Page load timeout in seconds")
    implicit_wait: int = Field(10, description="Implicit wait timeout in seconds")
    window_size: List[int] = Field([1920, 1080], description="Browser window size")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field("INFO", description="Logging level")
    format: str = Field(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    file: str = Field("logs/threat_intel.log", description="Log file path")
    max_file_size: str = Field("10MB", description="Maximum log file size")
    backup_count: int = Field(5, description="Number of backup log files")


class DataProcessingConfig(BaseModel):
    """Data processing configuration."""
    date_filter_days: int = Field(135, description="Filter indicators older than X days")
    ic_score_thresholds: List[int] = Field([25, 75], description="IC score thresholds for confidence")
    output_formats: List[str] = Field(["csv", "json", "stix"], description="Output file formats")
    combined_output_path: str = Field("output/combined", description="Combined output directory")


class EnrichmentConfig(BaseModel):
    """IOC enrichment configuration."""
    # Geolocation Services
    maxmind_db_path: Optional[str] = Field(None, description="Path to MaxMind GeoIP database")
    ipinfo_api_key: Optional[str] = Field(None, description="IPinfo.io API key")
    
    # Reputation Services
    virustotal_api_key: Optional[str] = Field(None, description="VirusTotal API key")
    urlvoid_api_key: Optional[str] = Field(None, description="URLVoid API key")
    
    # Rate Limiting
    rate_limit_per_minute: int = Field(60, description="API requests per minute")
    request_timeout: int = Field(30, description="HTTP request timeout in seconds")
    max_concurrent_requests: int = Field(5, description="Maximum concurrent API requests")
    
    # Cache Settings
    enable_cache: bool = Field(True, description="Enable enrichment result caching")
    cache_duration_hours: int = Field(24, description="Cache duration in hours")
    
    # Enrichment Options
    auto_enrich: bool = Field(False, description="Automatically enrich all IOCs")
    enrichment_sources: List[str] = Field(
        ["geolocation", "asn", "reputation"], 
        description="Enabled enrichment sources"
    )
    skip_private_ips: bool = Field(True, description="Skip enrichment for private IP addresses")


class ThreatActorsConfig(BaseModel):
    """Threat actors configuration."""
    sources: Dict[str, str] = Field(default_factory=dict, description="Threat actor source files")


class AppConfig(BaseModel):
    """Main application configuration."""
    scrapers: Dict[str, ScrapingConfig] = Field(default_factory=dict, description="Scraper configurations")
    browser: BrowserConfig = Field(default_factory=BrowserConfig, description="Browser settings")
    logging: LoggingConfig = Field(default_factory=LoggingConfig, description="Logging settings")
    data_processing: DataProcessingConfig = Field(default_factory=DataProcessingConfig, description="Data processing settings")
    threat_actors: ThreatActorsConfig = Field(default_factory=ThreatActorsConfig, description="Threat actor configurations")
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig, description="IOC enrichment settings")


class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path or "config.yml")
        self.base_dir = Path.cwd()
        self._config: Optional[AppConfig] = None
        self._credentials: Dict[str, str] = {}
        
        # Load environment variables
        load_dotenv()
        self._load_credentials()
    
    def _load_credentials(self):
        """Load credentials from environment variables."""
        credential_keys = [
            'MANDIANT_EMAIL', 'MANDIANT_PASSWORD', 'MANDIANT_TOTP_SECRET',
            'CROWDSTRIKE_EMAIL', 'CROWDSTRIKE_PASSWORD', 'CROWDSTRIKE_TOTP_SECRET'
        ]
        
        for key in credential_keys:
            value = os.getenv(key)
            if value:
                self._credentials[key] = value
    
    def load_config(self) -> AppConfig:
        """Load configuration from file.
        
        Returns:
            Loaded configuration
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If config is invalid
        """
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            # Convert scrapers to ScrapingConfig objects
            if 'scrapers' in config_data:
                scrapers = {}
                for name, scraper_config in config_data['scrapers'].items():
                    scraper_config['source'] = name
                    scrapers[name] = ScrapingConfig(**scraper_config)
                config_data['scrapers'] = scrapers
            
            self._config = AppConfig(**config_data)
            return self._config
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}")
    
    def get_config(self) -> AppConfig:
        """Get current configuration, loading if necessary.
        
        Returns:
            Current configuration
        """
        if self._config is None:
            self.load_config()
        return self._config
    
    def get_scraper_config(self, source: str) -> ScrapingConfig:
        """Get configuration for a specific scraper.
        
        Args:
            source: Scraper source name
            
        Returns:
            Scraper configuration
            
        Raises:
            KeyError: If scraper not found
        """
        config = self.get_config()
        if source not in config.scrapers:
            raise KeyError(f"Scraper '{source}' not found in configuration")
        return config.scrapers[source]
    
    def get_credentials(self, source: str) -> Dict[str, str]:
        """Get credentials for a source.
        
        Args:
            source: Source name (mandiant, crowdstrike)
            
        Returns:
            Dictionary with email, password, and optionally totp_secret keys
            
        Raises:
            ValueError: If credentials not found
        """
        email_key = f"{source.upper()}_EMAIL"
        password_key = f"{source.upper()}_PASSWORD"
        totp_key = f"{source.upper()}_TOTP_SECRET"
        
        email = self._credentials.get(email_key)
        password = self._credentials.get(password_key)
        totp_secret = self._credentials.get(totp_key)
        
        if not email or not password:
            missing = []
            if not email:
                missing.append(email_key)
            if not password:
                missing.append(password_key)
            raise ValueError(f"Missing credentials: {', '.join(missing)}")
        
        credentials = {
            'email': email,
            'password': password
        }
        
        # Add TOTP secret if available
        if totp_secret:
            credentials['totp_secret'] = totp_secret
        
        return credentials
    
    def load_threat_actors(self, source: str) -> List[ThreatActor]:
        """Load threat actors for a source.
        
        Args:
            source: Source name
            
        Returns:
            List of threat actors
            
        Raises:
            FileNotFoundError: If threat actor file not found
            ValueError: If file is invalid
        """
        config = self.get_config()
        
        # First try configured file if it exists
        if source in config.threat_actors.sources:
            ta_file = Path(config.threat_actors.sources[source])
            if not ta_file.exists():
                ta_file = self.base_dir / ta_file
            
            if ta_file.exists():
                if ta_file.suffix.lower() == '.csv':
                    return self._load_threat_actors_from_csv(ta_file, source)
                else:
                    return self._load_threat_actors_from_yaml(ta_file, source)
        
        # Fall back to CSV file in root directory
        csv_path = self.base_dir / f"ta_{source}.csv"
        if csv_path.exists():
            return self._load_threat_actors_from_csv(csv_path, source)
        
        # No file found
        raise FileNotFoundError(f"No threat actors file found for source: {source}")
    
    def _load_threat_actors_from_csv(self, file_path: Path, source: str) -> List[ThreatActor]:
        """Load threat actors from CSV file.
        
        Args:
            file_path: Path to CSV file
            source: Source name
            
        Returns:
            List of threat actors
        """
        import pandas as pd
        
        try:
            df = pd.read_csv(file_path)
            threat_actors = []
            
            for _, row in df.iterrows():
                ta = ThreatActor(
                    name=row.get('TA', row.get('name', '')),
                    url=row.get('url', ''),
                    source=source,
                    active=row.get('active', True)
                )
                threat_actors.append(ta)
            
            return threat_actors
            
        except Exception as e:
            raise ValueError(f"Error loading threat actors from CSV: {e}")
    
    def _load_threat_actors_from_yaml(self, file_path: Path, source: str) -> List[ThreatActor]:
        """Load threat actors from YAML file.
        
        Args:
            file_path: Path to YAML file
            source: Source name
            
        Returns:
            List of threat actors
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            threat_actors = []
            for ta_data in data.get('threat_actors', []):
                ta_data['source'] = source
                ta = ThreatActor(**ta_data)
                threat_actors.append(ta)
            
            return threat_actors
            
        except Exception as e:
            raise ValueError(f"Error loading threat actors from YAML: {e}")
    
    def validate_paths(self):
        """Validate and create necessary directories.
        
        Raises:
            OSError: If directories cannot be created
        """
        config = self.get_config()
        
        # Create directories for each scraper
        for scraper_config in config.scrapers.values():
            for path_attr in ['profile_path', 'download_path', 'output_path']:
                path = Path(getattr(scraper_config, path_attr))
                if not path.is_absolute():
                    path = self.base_dir / path
                path.mkdir(parents=True, exist_ok=True)
        
        # Create data processing directories
        combined_path = Path(config.data_processing.combined_output_path)
        if not combined_path.is_absolute():
            combined_path = self.base_dir / combined_path
        combined_path.mkdir(parents=True, exist_ok=True)
        
        # Create logs directory
        log_file = Path(config.logging.file)
        if not log_file.is_absolute():
            log_file = self.base_dir / log_file
        log_file.parent.mkdir(parents=True, exist_ok=True)


# Global config manager instance
config_manager = ConfigManager()