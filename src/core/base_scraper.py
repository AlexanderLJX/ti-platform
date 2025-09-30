"""Base scraper class with common functionality."""

import time
import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from .models import ThreatActor, ScrapingJob, ScrapingStatus, ScrapingConfig
from .config import ConfigManager
from ..utils.selenium_helper import SeleniumHelper
from ..utils.auth_handler import AuthHandler
from ..utils.file_handler import FileHandler

logger = logging.getLogger(__name__)


class BaseScraper(ABC):
    """Abstract base class for threat intelligence scrapers."""
    
    def __init__(self, source: str, config_manager: ConfigManager):
        """Initialize base scraper.
        
        Args:
            source: Source name (mandiant, crowdstrike)
            config_manager: Configuration manager instance
        """
        self.source = source
        self.config_manager = config_manager
        self.config = config_manager.get_scraper_config(source)
        self.app_config = config_manager.get_config()
        
        # Initialize components
        self.selenium_helper = SeleniumHelper(
            config=self.app_config.browser,
            profile_path=self.config.profile_path,
            download_path=self.config.download_path
        )
        self.auth_handler = None  # Will be initialized after driver setup
        self.file_handler = FileHandler(self.config.download_path)
        
        # State
        self.driver = None
        self.is_authenticated = False
        self.current_job: Optional[ScrapingJob] = None
        
        # Setup logging
        self.logger = logging.getLogger(f"{__name__}.{source}")
    
    def setup(self) -> bool:
        """Set up the scraper (driver, authentication, etc.).
        
        Returns:
            True if setup successful, False otherwise
        """
        try:
            self.logger.info(f"Setting up {self.source} scraper")
            
            # Setup WebDriver
            self.driver = self.selenium_helper.setup_driver()
            if not self.driver:
                self.logger.error("Failed to setup WebDriver")
                return False
            
            # Initialize auth handler with driver
            self.auth_handler = AuthHandler(self.selenium_helper)
            
            # Validate configuration paths
            self.config_manager.validate_paths()
            
            self.logger.info(f"{self.source} scraper setup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Setup failed for {self.source}: {e}")
            return False
    
    def cleanup(self):
        """Clean up resources."""
        try:
            if self.selenium_helper:
                self.selenium_helper.quit_driver()
            
            if self.file_handler:
                self.file_handler.cleanup_temp_files()
            
            self.logger.info(f"{self.source} scraper cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup error for {self.source}: {e}")
    
    def authenticate(self) -> bool:
        """Authenticate with the target platform.
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            self.logger.info(f"Starting authentication for {self.source}")
            
            # Navigate to login page
            if not self.selenium_helper.navigate_to(self.config.login_url):
                self.logger.error("Failed to navigate to login page")
                return False
            
            # Check if already logged in
            success_indicators, login_indicators = self._get_auth_indicators()
            if self.auth_handler.check_login_status(success_indicators, login_indicators):
                self.logger.info("Already authenticated")
                self.is_authenticated = True
                return self._post_login_navigation()
            
            # Get credentials
            try:
                credentials = self.config_manager.get_credentials(self.source)
            except ValueError as e:
                self.logger.error(f"Credentials error: {e}")
                return False
            
            # Perform login
            email_selector, password_selector, submit_selectors, next_selector = self._get_login_selectors()
            
            if not self.auth_handler.perform_login(
                credentials=credentials,
                email_selector=email_selector,
                password_selector=password_selector,
                submit_selectors=submit_selectors,
                next_selector=next_selector
            ):
                self.logger.error("Login failed")
                return False
            
            # Handle 2FA if required
            token_selectors, submit_selectors = self._get_2fa_selectors()
            
            # Check if TOTP secret is available for automatic 2FA
            totp_secret = credentials.get('totp_secret')
            if totp_secret:
                self.logger.info("Using automatic 2FA with TOTP secret")
                if not self.auth_handler.handle_2fa_automatic(
                    token_selectors=token_selectors,
                    submit_selectors=submit_selectors,
                    totp_secret=totp_secret
                ):
                    self.logger.error("Automatic 2FA failed")
                    return False
            else:
                self.logger.info("No TOTP secret found, falling back to manual 2FA")
                if not self.auth_handler.handle_2fa_manual(
                    token_selectors=token_selectors,
                    submit_selectors=submit_selectors,
                    prompt_message=f"Enter your {self.source} 2FA token: "
                ):
                    self.logger.error("Manual 2FA failed")
                    return False
            
            # Verify login success
            if not self.auth_handler.verify_login_success(
                success_indicators=success_indicators,
                failure_indicators=login_indicators
            ):
                self.logger.error("Login verification failed")
                return False
            
            # Post-login navigation
            if not self._post_login_navigation():
                self.logger.error("Post-login navigation failed")
                return False
            
            self.is_authenticated = True
            self.logger.info(f"Authentication successful for {self.source}")
            return True
            
        except Exception as e:
            self.logger.error(f"Authentication failed for {self.source}: {e}")
            return False
    
    def scrape_threat_actor(self, threat_actor: ThreatActor) -> ScrapingJob:
        """Scrape indicators for a single threat actor.
        
        Args:
            threat_actor: Threat actor to scrape
            
        Returns:
            ScrapingJob with results
        """
        job = ScrapingJob(
            id=f"{self.source}_{threat_actor.name}_{int(time.time())}",
            source=self.source,
            threat_actor=threat_actor,
            status=ScrapingStatus.PENDING
        )
        
        self.current_job = job
        
        try:
            self.logger.info(f"Starting scrape for {threat_actor.name}")
            job.status = ScrapingStatus.IN_PROGRESS
            job.started_at = time.time()
            
            # Ensure we're authenticated
            if not self.is_authenticated and not self.authenticate():
                raise Exception("Authentication required but failed")
            
            # Perform scraping
            download_path = self._scrape_threat_actor_indicators(threat_actor)
            if not download_path:
                raise Exception("Failed to download indicators")
            
            # Validate downloaded file
            validation = self.file_handler.validate_csv_file(download_path)
            if not validation['valid']:
                raise Exception(f"Invalid CSV file: {validation['errors']}")
            
            # Add metadata to CSV
            metadata = {
                'threat_actor_name': threat_actor.name,
                'threat_actor_id': threat_actor.url or threat_actor.slug,
                'source': self.source
            }
            
            if not self.file_handler.add_metadata_to_csv(download_path, metadata):
                self.logger.warning("Failed to add metadata to CSV")
            
            # Update job
            job.status = ScrapingStatus.COMPLETED
            job.completed_at = time.time()
            job.indicators_count = validation['row_count']
            job.file_path = download_path
            
            self.logger.info(f"Scraping completed for {threat_actor.name}: {job.indicators_count} indicators")
            
        except Exception as e:
            job.status = ScrapingStatus.FAILED
            job.error_message = str(e)
            job.completed_at = time.time()
            
            self.logger.error(f"Scraping failed for {threat_actor.name}: {e}")
        
        return job
    
    def scrape_all_threat_actors(self) -> List[ScrapingJob]:
        """Scrape indicators for all configured threat actors.
        
        Returns:
            List of ScrapingJob results
        """
        try:
            # Load threat actors
            threat_actors = self.config_manager.load_threat_actors(self.source)
            active_actors = [ta for ta in threat_actors if ta.active]
            
            self.logger.info(f"Found {len(active_actors)} active threat actors for {self.source}")
            
            if not active_actors:
                self.logger.warning("No active threat actors found")
                return []
            
            # Authenticate once
            if not self.authenticate():
                self.logger.error("Authentication failed, cannot proceed with scraping")
                return []
            
            # Scrape each threat actor
            jobs = []
            for i, threat_actor in enumerate(active_actors, 1):
                self.logger.info(f"Processing {i}/{len(active_actors)}: {threat_actor.name}")
                
                job = self.scrape_threat_actor(threat_actor)
                jobs.append(job)
                
                # Add delay between requests
                if i < len(active_actors):
                    delay = 2  # Default delay
                    self.logger.info(f"Waiting {delay}s before next request...")
                    time.sleep(delay)
            
            # Summary
            successful = len([j for j in jobs if j.status == ScrapingStatus.COMPLETED])
            failed = len([j for j in jobs if j.status == ScrapingStatus.FAILED])
            total_indicators = sum(j.indicators_count for j in jobs)
            
            self.logger.info(f"Scraping summary: {successful} successful, {failed} failed, "
                           f"{total_indicators} total indicators")
            
            return jobs
            
        except Exception as e:
            self.logger.error(f"Error in scrape_all_threat_actors: {e}")
            return []
    
    @abstractmethod
    def _get_auth_indicators(self) -> Tuple[List, List]:
        """Get authentication status indicators.
        
        Returns:
            Tuple of (success_indicators, login_indicators)
        """
        pass
    
    @abstractmethod
    def _get_login_selectors(self) -> Tuple:
        """Get login form selectors.
        
        Returns:
            Tuple of (email_selector, password_selector, submit_selectors, next_selector)
        """
        pass
    
    @abstractmethod
    def _get_2fa_selectors(self) -> Tuple[List, List]:
        """Get 2FA form selectors.
        
        Returns:
            Tuple of (token_selectors, submit_selectors)
        """
        pass
    
    @abstractmethod
    def _post_login_navigation(self) -> bool:
        """Navigate to appropriate page after login.
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def _scrape_threat_actor_indicators(self, threat_actor: ThreatActor) -> Optional[str]:
        """Scrape indicators for a threat actor (source-specific implementation).
        
        Args:
            threat_actor: Threat actor to scrape
            
        Returns:
            Path to downloaded file, or None if failed
        """
        pass