"""CrowdStrike scraper implementation."""

import time
import logging
from typing import Optional, Tuple, List, Dict, Any
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from ...core.base_scraper import BaseScraper
from ...core.plugin_system.registry import BasePlugin
from ...core.models import ThreatActor, PluginInfo, IndicatorType
from ...core.config import ConfigManager
from . import selectors

logger = logging.getLogger(__name__)


class CrowdStrikeScraper(BaseScraper, BasePlugin):
    """CrowdStrike Falcon scraper implementation with plugin support."""
    
    PLUGIN_TYPE = "scraper"
    PLUGIN_NAME = "crowdstrike"
    
    def __init__(self, config_manager: ConfigManager):
        """Initialize CrowdStrike scraper.
        
        Args:
            config_manager: Configuration manager instance
        """
        super().__init__("crowdstrike", config_manager)
        # Initialize plugin interface with simple config dict
        plugin_config = {"source": "crowdstrike", "config_manager": config_manager}
        BasePlugin.__init__(self, "crowdstrike", plugin_config)
        self.logger = logging.getLogger(f"{__name__}.crowdstrike")
    
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
        submit_selectors = [selectors.LOGIN_BUTTON]
        next_selector = selectors.CONTINUE_BUTTON
        
        return email_selector, password_selector, submit_selectors, next_selector
    
    def _get_2fa_selectors(self) -> Tuple[List, List]:
        """Get 2FA form selectors.
        
        Returns:
            Tuple of (token_selectors, submit_selectors)
        """
        token_selectors = selectors.TOKEN_FIELDS
        submit_selectors = [selectors.TOKEN_SUBMIT_BUTTON]
        return token_selectors, submit_selectors
    
    def _post_login_navigation(self) -> bool:
        """Navigate to intelligence page after login.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            current_url = self.selenium_helper.get_current_url()
            
            # Navigate to intelligence page if not already there
            if "intelligence-v2/actors" not in current_url:
                self.logger.info("Navigating to intelligence page...")
                if not self.selenium_helper.navigate_to(selectors.INTELLIGENCE_URL):
                    return False
            
            # Verify we're on the correct page
            final_url = self.selenium_helper.get_current_url()
            if "falcon.crowdstrike.com" not in final_url:
                self.logger.error(f"Not on CrowdStrike domain: {final_url}")
                return False
            
            self.logger.info("Successfully navigated to CrowdStrike Intelligence")
            return True
            
        except Exception as e:
            self.logger.error(f"Post-login navigation failed: {e}")
            return False
    
    def _scrape_threat_actor_indicators(self, threat_actor: ThreatActor) -> Optional[str]:
        """Scrape indicators for a CrowdStrike threat actor using robust waiting and clicking strategy.

        Args:
            threat_actor: Threat actor to scrape

        Returns:
            Path to downloaded file, or None if failed
        """
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException

        try:
            # Use slug or URL as actor identifier
            actor_slug = threat_actor.slug or threat_actor.url
            if not actor_slug:
                self.logger.error(f"No valid actor slug for {threat_actor.name}")
                return None

            # Construct the indicators URL
            url = selectors.get_indicators_url(actor_slug)
            self.logger.info(f"Processing actor: {threat_actor.name} ({actor_slug})")
            self.logger.debug(f"URL: {url}")

            # Navigate to indicators page
            if not self.selenium_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to indicators page for {threat_actor.name}")
                return None

            # Step 1: Use explicit wait for export button to be clickable
            export_button_selector = (By.CSS_SELECTOR, 'div[data-test-selector="file-export"] button[data-test-selector="falcon-popover-trigger"]')

            try:
                self.logger.info(f"Waiting for Export button to become clickable for {threat_actor.name}...")
                wait = WebDriverWait(self.driver, 30)
                export_button = wait.until(EC.element_to_be_clickable(export_button_selector))
                self.logger.info(f"Export button is ready for {threat_actor.name}")
            except TimeoutException:
                self.logger.error(f"Timeout: Export button not found or not clickable for {threat_actor.name}")
                return None

            # Step 2: Click export button
            self.logger.info(f"Clicking the Export button for {threat_actor.name}...")
            if not self.selenium_helper.click_element_safe(export_button, use_js=True):
                self.logger.error(f"Failed to click export button for {threat_actor.name}")
                return None

            # Step 3: Wait for CSV option and click it
            try:
                self.logger.info(f"Waiting for CSV button for {threat_actor.name}...")
                csv_button = WebDriverWait(self.driver, 10).until(EC.element_to_be_clickable(selectors.CSV_BUTTON))

                if not self.selenium_helper.click_element_safe(csv_button, use_js=True):
                    self.logger.error(f"Failed to click CSV button for {threat_actor.name}")
                    return None

                self.logger.info(f"CSV export initiated for {threat_actor.name}")
            except TimeoutException:
                self.logger.error(f"CSV button did not appear for {threat_actor.name}")
                return None

            # Step 4: Wait for download to be ready
            if not self._wait_for_download_ready(threat_actor.name):
                self.logger.error(f"Download not ready for {threat_actor.name}")
                return None

            # Step 5: Download the file
            files_before = self.file_handler.get_files_before_download()

            download_button = self.selenium_helper.find_element_safe(*selectors.DOWNLOAD_BUTTON)
            if not download_button:
                self.logger.error(f"Download button not found for {threat_actor.name}")
                return None

            if not self.selenium_helper.click_element_safe(download_button, use_js=True):
                self.logger.error(f"Failed to click download button for {threat_actor.name}")
                return None

            self.logger.info(f"Download started for {threat_actor.name}")

            # Wait for file download
            downloaded_file = self.file_handler.wait_for_download(
                timeout=self.config.download_timeout,
                initial_files=files_before
            )

            if not downloaded_file:
                self.logger.error(f"Download timeout for {threat_actor.name}")
                return None

            # Step 6: Clean up server file
            self._cleanup_server_file(threat_actor.name)

            self.logger.info(f"Download completed for {threat_actor.name}: {downloaded_file}")
            return downloaded_file

        except Exception as e:
            self.logger.error(f"An unexpected error occurred while downloading indicators for {threat_actor.name}: {e}")
            return None
    
    def _wait_for_page_ready(self, actor_name: str, timeout: int = 20) -> bool:
        """Wait for page to load AND export button to be ready.

        This combines both checks for efficiency - returns as soon as export button is found.

        Args:
            actor_name: Actor name for logging
            timeout: Timeout in seconds

        Returns:
            True if page ready and export button found, False otherwise
        """
        self.logger.info(f"Waiting for page to be ready for {actor_name}...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if export button is ready (primary goal) - use immediate check, no wait
            for by, value in selectors.EXPORT_BUTTON_SELECTORS:
                try:
                    # Don't use find_element_safe as it has built-in waits
                    # Use direct find_element for immediate check
                    element = self.driver.find_element(by, value)
                    if element and element.is_displayed() and element.is_enabled():
                        elapsed = time.time() - start_time
                        self.logger.info(f"Export button ready for {actor_name} (found in {elapsed:.1f}s)")
                        return True
                except NoSuchElementException:
                    continue
                except Exception:
                    continue

            time.sleep(0.3)  # Quick checks

        self.logger.warning(f"Timeout waiting for page to be ready for {actor_name}")
        return False

    def _wait_for_page_load(self, actor_name: str, timeout: int = 10) -> bool:
        """Wait for page loading indicators to disappear.

        Args:
            actor_name: Actor name for logging
            timeout: Timeout in seconds

        Returns:
            True if page loaded, False if timeout
        """
        self.logger.info(f"Waiting for page to load for {actor_name}...")

        start_time = time.time()
        last_log_time = start_time

        while time.time() - start_time < timeout:
            loading_found = False

            for selector in selectors.LOADING_SELECTORS:
                try:
                    loading_element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if loading_element.is_displayed():
                        loading_found = True
                        # Log every 3 seconds to show progress
                        if time.time() - last_log_time >= 3:
                            self.logger.debug(f"Still loading ({selector} visible)...")
                            last_log_time = time.time()
                        break
                except NoSuchElementException:
                    continue

            if not loading_found:
                self.logger.info(f"Page loaded for {actor_name}")
                return True

            time.sleep(0.5)  # Check more frequently

        self.logger.warning(f"Page load timeout for {actor_name} - proceeding anyway")
        return False
    
    def _wait_for_export_button_ready(self, actor_name: str, timeout: int = 15):
        """Wait for export button to be ready and clickable.

        Args:
            actor_name: Actor name for logging
            timeout: Timeout in seconds

        Returns:
            True if button found, False otherwise
        """
        self.logger.info(f"Waiting for export button to be ready for {actor_name}...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            for by, value in selectors.EXPORT_BUTTON_SELECTORS:
                try:
                    element = self.selenium_helper.find_element_safe(by, value, timeout=2)
                    if element and element.is_displayed() and element.is_enabled():
                        self.logger.info(f"Export button ready for {actor_name} (selector: {by}={value})")
                        return True
                except Exception:
                    continue

            time.sleep(1)

        self.logger.warning(f"Export button timeout for {actor_name}")
        return False
    
    def _click_export_button_with_retry(self, actor_name: str, max_retries: int = 3) -> bool:
        """Click export button with retry logic.

        Args:
            actor_name: Actor name for logging
            max_retries: Maximum number of retry attempts

        Returns:
            True if successful, False otherwise
        """
        self.logger.info(f"Starting export button click for {actor_name}")

        from selenium.webdriver.common.action_chains import ActionChains

        for attempt in range(max_retries):
            try:
                self.logger.info(f"Clicking export button (attempt {attempt + 1}/{max_retries}) for {actor_name}")

                # Find the export button
                export_button = None
                button_selector = None

                for by, value in selectors.EXPORT_BUTTON_SELECTORS:
                    try:
                        element = self.selenium_helper.find_element_safe(by, value, timeout=5)
                        if element and element.is_displayed() and element.is_enabled():
                            export_button = element
                            button_selector = (by, value)
                            self.logger.info(f"Found export button with selector: {by}={value}")
                            break
                    except Exception as e:
                        self.logger.debug(f"Selector {by}={value} failed: {e}")
                        continue

                if not export_button:
                    self.logger.warning(f"Could not find export button on attempt {attempt + 1}")
                    time.sleep(2)
                    continue

                # Scroll button into view
                self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", export_button)
                time.sleep(0.5)

                # Click using ActionChains (most reliable for modern web apps)
                try:
                    actions = ActionChains(self.driver)
                    actions.move_to_element(export_button).pause(0.5).click().perform()
                    self.logger.info("Export button clicked")
                except Exception as e:
                    self.logger.warning(f"ActionChains click failed, trying JavaScript: {e}")
                    # Fallback to JavaScript click
                    self.driver.execute_script("arguments[0].click();", export_button)
                    self.logger.info("Export button clicked via JavaScript")

                # Wait for dropdown to open
                time.sleep(2)

                # Check if dropdown opened
                dropdown_opened = False

                # Check 1: aria-expanded attribute
                try:
                    button_check = self.driver.find_element(*button_selector)
                    aria_expanded = button_check.get_attribute("aria-expanded")
                    if aria_expanded == "true":
                        dropdown_opened = True
                        self.logger.info(f"Export dropdown opened (verified via aria-expanded)")
                except Exception as e:
                    self.logger.debug(f"Could not check aria-expanded: {e}")

                # Check 2: CSV button visibility
                if not dropdown_opened:
                    try:
                        csv_button = self.selenium_helper.find_element_safe(*selectors.CSV_BUTTON, timeout=2)
                        if csv_button and csv_button.is_displayed():
                            dropdown_opened = True
                            self.logger.info(f"Export dropdown opened (verified via CSV button)")
                    except Exception:
                        pass

                if dropdown_opened:
                    return True

                self.logger.warning(f"Dropdown did not open after attempt {attempt + 1}, retrying...")
                time.sleep(1)

            except Exception as e:
                self.logger.error(f"Error on attempt {attempt + 1}: {e}")
                time.sleep(2)

        self.logger.error(f"Failed to click export button after {max_retries} attempts for {actor_name}")
        return False
    
    def _wait_for_download_ready(self, actor_name: str, timeout: int = 90) -> bool:
        """Wait for download to be prepared and ready.
        
        Args:
            actor_name: Actor name for logging
            timeout: Timeout in seconds
            
        Returns:
            True if download ready, False if timeout
        """
        self.logger.info(f"Waiting for download to be ready for {actor_name}...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                download_button = self.selenium_helper.find_element_safe(*selectors.DOWNLOAD_BUTTON)
                if download_button and download_button.is_displayed() and download_button.is_enabled():
                    self.logger.info(f"Download ready for {actor_name}")
                    return True
            except Exception:
                pass
            
            elapsed = int(time.time() - start_time)
            if elapsed % 10 == 0:  # Log every 10 seconds
                self.logger.debug(f"Still waiting for download for {actor_name} ({elapsed}s)...")
            
            time.sleep(3)
        
        self.logger.warning(f"Download not ready within timeout for {actor_name}")
        return False
    
    def _cleanup_server_file(self, actor_name: str):
        """Clean up the file on the server after download.
        
        Args:
            actor_name: Actor name for logging
        """
        try:
            delete_button = self.selenium_helper.find_element_safe(*selectors.DELETE_BUTTON)
            if delete_button:
                self.selenium_helper.click_element_safe(delete_button)
                self.logger.info(f"Server file deleted for {actor_name}")
            else:
                self.logger.debug(f"Delete button not found for {actor_name}")
        except Exception as e:
            self.logger.warning(f"Could not delete server file for {actor_name}: {e}")
    
    # Plugin interface methods
    @property
    def plugin_info(self) -> PluginInfo:
        """Return plugin metadata."""
        return PluginInfo(
            name="CrowdStrike Falcon Scraper",
            version="1.0.0",
            description="Scrape threat intelligence from CrowdStrike Falcon platform",
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
            logger.error(f"Failed to initialize CrowdStrike scraper plugin: {e}")
            return False
    
    def cleanup(self) -> None:
        """Cleanup plugin resources."""
        super().cleanup()
    
    def health_check(self) -> bool:
        """Check if plugin is healthy and operational."""
        try:
            # Basic health check - can we access the platform?
            if not self.selenium_helper or not self.selenium_helper.driver:
                return False
            
            current_url = self.selenium_helper.get_current_url()
            return "crowdstrike.com" in current_url.lower() or current_url == "about:blank"
        except Exception:
            return False