"""Custom exception classes for the threat intelligence scraper."""


class ThreatIntelScraperError(Exception):
    """Base exception class for scraper errors."""
    pass


class ConfigurationError(ThreatIntelScraperError):
    """Raised when there are configuration issues."""
    pass


class AuthenticationError(ThreatIntelScraperError):
    """Raised when authentication fails."""
    pass


class ScrapingError(ThreatIntelScraperError):
    """Raised when scraping operations fail."""
    pass


class DataProcessingError(ThreatIntelScraperError):
    """Raised when data processing fails."""
    pass


class WebDriverError(ThreatIntelScraperError):
    """Raised when WebDriver operations fail."""
    pass