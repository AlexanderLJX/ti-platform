"""Mandiant scraper implementation."""

import time
import logging
from typing import Optional, Tuple, List, Dict, Any
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException

from ...core.base_scraper import BaseScraper
from ...core.plugin_system.registry import BasePlugin
from ...core.models import ThreatActor, PluginInfo, IndicatorType
from ...core.config import ConfigManager
from . import selectors

logger = logging.getLogger(__name__)


class MandiantScraper(BaseScraper, BasePlugin):
    """Mandiant Advantage scraper implementation with plugin support."""
    
    PLUGIN_TYPE = "scraper"
    PLUGIN_NAME = "mandiant"
    
    def __init__(self, config_manager: ConfigManager):
        """Initialize Mandiant scraper.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__("mandiant", config_manager)
        # Initialize plugin interface with simple config dict
        plugin_config = {"source": "mandiant", "config_manager": config_manager}
        BasePlugin.__init__(self, "mandiant", plugin_config)
        self.logger = logging.getLogger(f"{__name__}.mandiant")
    
    def _get_auth_indicators(self) -> Tuple[List, List]:
        """Get authentication status indicators.
        
        Returns:
            Tuple of (success_indicators, login_indicators)
        """
        success_indicators = selectors.SUCCESS_URL_INDICATORS.copy()
        login_indicators = selectors.LOGIN_FORM_INDICATORS.copy()
        return success_indicators, login_indicators
    
    def _get_login_selectors(self) -> Tuple:
        """Get login form selectors.
        
        Returns:
            Tuple of (email_selector, password_selector, submit_selectors, next_selector)
        """
        email_selector = selectors.EMAIL_FIELD
        password_selector = selectors.PASSWORD_FIELD
        submit_selectors = [selectors.SIGN_IN_BUTTON]
        next_selector = selectors.NEXT_BUTTON
        
        return email_selector, password_selector, submit_selectors, next_selector
    
    def _get_2fa_selectors(self) -> Tuple[List, List]:
        """Get 2FA form selectors.
        
        Returns:
            Tuple of (token_selectors, submit_selectors)
        """
        token_selectors = [selectors.TOKEN_FIELD]
        submit_selectors = [selectors.TOKEN_SUBMIT_BUTTON]
        return token_selectors, submit_selectors
    
    def _post_login_navigation(self) -> bool:
        """Navigate to Mandiant Advantage after login.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            current_url = self.selenium_helper.get_current_url()
            
            # If we're still on login domain, navigate to advantage
            if "login.mandiant.com" in current_url:
                self.logger.info("Navigating from login domain to advantage...")
                if not self.selenium_helper.navigate_to("https://advantage.mandiant.com"):
                    return False
            
            # Verify we're on advantage domain
            final_url = self.selenium_helper.get_current_url()
            if "advantage.mandiant.com" not in final_url:
                self.logger.error(f"Not on advantage domain: {final_url}")
                return False
            
            self.logger.info("Successfully navigated to Mandiant Advantage")
            return True
            
        except Exception as e:
            self.logger.error(f"Post-login navigation failed: {e}")
            return False
    
    def _scrape_threat_actor_indicators(self, threat_actor: ThreatActor) -> Optional[str]:
        """Scrape indicators for a Mandiant threat actor.
        
        Args:
            threat_actor: Threat actor to scrape
            
        Returns:
            Path to downloaded file, or None if failed
        """
        try:
            # Clean the actor ID (remove anything after #)
            clean_actor_id = threat_actor.url.split('#')[0] if threat_actor.url else threat_actor.slug
            if not clean_actor_id:
                self.logger.error(f"No valid actor ID for {threat_actor.name}")
                return None
            
            # Construct URL
            url = f"https://advantage.mandiant.com/actors/{clean_actor_id}"
            self.logger.info(f"Processing actor: {threat_actor.name} ({clean_actor_id})")
            self.logger.debug(f"URL: {url}")
            
            # Navigate to actor page
            if not self.selenium_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to actor page for {threat_actor.name}")
                return None
            
            # Step 1: Find and click "Take Action" button
            take_action_button = self._find_take_action_button()
            if not take_action_button:
                self.logger.error(f"Take Action button not found for {threat_actor.name}")
                return None
            
            # Click Take Action to open dropdown
            if not self.selenium_helper.click_element_safe(take_action_button):
                self.logger.error(f"Failed to click Take Action button for {threat_actor.name}")
                return None
            
            time.sleep(2)  # Wait for dropdown to appear
            self.logger.info(f"Opened Take Action dropdown for {threat_actor.name}")
            
            # Step 2: Find and click "Download Indicators" option
            download_option = self._find_download_indicators_option()
            if not download_option:
                self.logger.error(f"Download Indicators option not found for {threat_actor.name}")
                return None
            
            # Get files before download
            files_before = self.file_handler.get_files_before_download()
            
            # Click Download Indicators
            if not self.selenium_helper.click_element_safe(download_option):
                self.logger.error(f"Failed to click Download Indicators for {threat_actor.name}")
                return None
            
            self.logger.info(f"Clicked Download Indicators for {threat_actor.name}")
            
            # Step 3: Wait for download to complete
            downloaded_file = self.file_handler.wait_for_download(
                timeout=self.config.download_timeout,
                initial_files=files_before
            )
            
            if not downloaded_file:
                self.logger.error(f"Download timeout for {threat_actor.name}")
                return None
            
            self.logger.info(f"Download completed for {threat_actor.name}: {downloaded_file}")
            return downloaded_file
            
        except Exception as e:
            self.logger.error(f"Error downloading indicators for {threat_actor.name}: {e}")
            return None
    
    def _find_take_action_button(self):
        """Find the Take Action button using multiple selectors.
        
        Returns:
            Take Action button element or None
        """
        for by, value in selectors.TAKE_ACTION_SELECTORS:
            try:
                element = self.selenium_helper.find_element_safe(by, value)
                if element and element.is_displayed():
                    return element
            except Exception:
                continue
        
        return None
    
    def _find_download_indicators_option(self):
        """Find the Download Indicators option in dropdown.
        
        Returns:
            Download Indicators option element or None
        """
        for by, value in selectors.DOWNLOAD_INDICATORS_SELECTORS:
            try:
                if by == By.XPATH:
                    # For XPath selectors, find all matching elements and check text
                    elements = self.selenium_helper.find_elements_safe(by, value)
                    for element in elements:
                        if element.is_displayed() and "download indicators" in element.text.lower():
                            return element
                else:
                    element = self.selenium_helper.find_element_safe(by, value)
                    if element and element.is_displayed():
                        return element
            except Exception:
                continue
        
        return None
    
    # Plugin interface methods
    @property
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        return PluginInfo(
            name="Mandiant Advantage Scraper",
            version="1.0.0",
            description="Scrape threat intelligence from Mandiant Advantage platform",
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
            required_config=["base_url", "login_url", "download_path"],
            optional_config=["download_timeout", "retry_attempts"]
        )
    
    def initialize(self) -> bool:
        """Initialize the plugin. Return True if successful."""
        try:
            return self.setup()
        except Exception as e:
            logger.error(f"Failed to initialize Mandiant scraper plugin: {e}")
            return False
    
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        super().cleanup()
    
    def health_check(self) -> bool:
        """Check if plugin is healthy and operational."""
        try:
            # Basic health check - can we access the login page?
            if not self.selenium_helper or not self.selenium_helper.driver:
                return False
            
            current_url = self.selenium_helper.get_current_url()
            return "mandiant.com" in current_url.lower() or current_url == "about:blank"
        except Exception:
            return False