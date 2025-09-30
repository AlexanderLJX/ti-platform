"""Selenium utility functions and helpers."""

import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import (
    TimeoutException, 
    NoSuchElementException,
    WebDriverException,
    ElementNotInteractableException
)
from webdriver_manager.chrome import ChromeDriverManager

from ..core.config import BrowserConfig

logger = logging.getLogger(__name__)


class SeleniumHelper:
    """Helper class for common Selenium operations."""
    
    def __init__(self, config: BrowserConfig, profile_path: str, download_path: str):
        """Initialize Selenium helper.
        
        Args:
            config: Browser configuration
            profile_path: Path to Chrome profile directory
            download_path: Path to download directory
        """
        self.config = config
        self.profile_path = Path(profile_path)
        self.download_path = Path(download_path)
        self.driver: Optional[webdriver.Chrome] = None
        self.wait: Optional[WebDriverWait] = None
        
        # Ensure directories exist
        self.profile_path.mkdir(parents=True, exist_ok=True)
        self.download_path.mkdir(parents=True, exist_ok=True)
    
    def setup_driver(self) -> webdriver.Chrome:
        """Set up Chrome WebDriver with configured options.
        
        Returns:
            Configured Chrome WebDriver instance
            
        Raises:
            WebDriverException: If driver setup fails
        """
        try:
            chrome_options = Options()
            
            # Profile settings
            chrome_options.add_argument(f"--user-data-dir={self.profile_path.absolute()}")
            chrome_options.add_argument("--profile-directory=Default")
            
            # Download preferences
            prefs = {
                "download.default_directory": str(self.download_path.absolute()),
                "download.prompt_for_download": False,
                "download.directory_upgrade": True,
                "safebrowsing.enabled": True,
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0
            }
            chrome_options.add_experimental_option("prefs", prefs)
            
            # Browser options
            if self.config.headless:
                chrome_options.add_argument("--headless")
            
            # Anti-detection options
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Window size
            if self.config.window_size:
                chrome_options.add_argument(f"--window-size={self.config.window_size[0]},{self.config.window_size[1]}")
            
            # Create service and driver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Configure timeouts
            self.driver.implicitly_wait(self.config.implicit_wait)
            self.driver.set_page_load_timeout(self.config.page_load_timeout)
            
            # Create WebDriverWait instance
            self.wait = WebDriverWait(self.driver, self.config.page_load_timeout)
            
            # Hide automation indicators
            self.driver.execute_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            
            logger.info("Chrome WebDriver setup completed successfully")
            return self.driver
            
        except Exception as e:
            logger.error(f"Failed to setup Chrome WebDriver: {e}")
            raise WebDriverException(f"Driver setup failed: {e}")
    
    def quit_driver(self):
        """Quit the WebDriver and clean up resources."""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("WebDriver closed successfully")
            except Exception as e:
                logger.warning(f"Error closing WebDriver: {e}")
            finally:
                self.driver = None
                self.wait = None
    
    def navigate_to(self, url: str, wait_time: int = 3) -> bool:
        """Navigate to a URL with error handling.
        
        Args:
            url: URL to navigate to
            wait_time: Time to wait after navigation
            
        Returns:
            True if navigation successful, False otherwise
        """
        try:
            logger.info(f"Navigating to: {url}")
            self.driver.get(url)
            time.sleep(wait_time)
            return True
        except Exception as e:
            logger.error(f"Failed to navigate to {url}: {e}")
            return False
    
    def find_element_safe(self, by: By, value: str, timeout: int = None) -> Optional[Any]:
        """Find element with timeout and error handling.
        
        Args:
            by: By locator type
            value: Locator value
            timeout: Timeout in seconds (uses default if None)
            
        Returns:
            Element if found, None otherwise
        """
        try:
            timeout = timeout or self.config.page_load_timeout
            wait = WebDriverWait(self.driver, timeout)
            element = wait.until(EC.presence_of_element_located((by, value)))
            return element
        except TimeoutException:
            logger.debug(f"Element not found: {by}={value}")
            return None
        except Exception as e:
            logger.error(f"Error finding element {by}={value}: {e}")
            return None
    
    def find_elements_safe(self, by: By, value: str) -> List[Any]:
        """Find multiple elements with error handling.
        
        Args:
            by: By locator type
            value: Locator value
            
        Returns:
            List of elements (empty if none found)
        """
        try:
            elements = self.driver.find_elements(by, value)
            return elements
        except Exception as e:
            logger.error(f"Error finding elements {by}={value}: {e}")
            return []
    
    def click_element_safe(self, element: Any, use_js: bool = False) -> bool:
        """Click element with error handling and retry logic.
        
        Args:
            element: Element to click
            use_js: Whether to use JavaScript click
            
        Returns:
            True if click successful, False otherwise
        """
        try:
            # Scroll element into view
            self.driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
            time.sleep(0.5)
            
            if use_js:
                self.driver.execute_script("arguments[0].click();", element)
            else:
                element.click()
            
            return True
        except ElementNotInteractableException:
            logger.warning("Element not interactable, trying JavaScript click")
            try:
                self.driver.execute_script("arguments[0].click();", element)
                return True
            except Exception as e:
                logger.error(f"JavaScript click failed: {e}")
                return False
        except Exception as e:
            logger.error(f"Failed to click element: {e}")
            return False
    
    def send_keys_safe(self, element: Any, text: str, clear_first: bool = True) -> bool:
        """Send keys to element with error handling.
        
        Args:
            element: Element to send keys to
            text: Text to send
            clear_first: Whether to clear element first
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if clear_first:
                element.clear()
            element.send_keys(text)
            return True
        except Exception as e:
            logger.error(f"Failed to send keys to element: {e}")
            return False
    
    def wait_for_element_clickable(self, by: By, value: str, timeout: int = None) -> Optional[Any]:
        """Wait for element to be clickable.
        
        Args:
            by: By locator type
            value: Locator value
            timeout: Timeout in seconds
            
        Returns:
            Element if clickable, None otherwise
        """
        try:
            timeout = timeout or self.config.page_load_timeout
            wait = WebDriverWait(self.driver, timeout)
            element = wait.until(EC.element_to_be_clickable((by, value)))
            return element
        except TimeoutException:
            logger.debug(f"Element not clickable: {by}={value}")
            return None
        except Exception as e:
            logger.error(f"Error waiting for clickable element {by}={value}: {e}")
            return None
    
    def wait_for_page_load(self, timeout: int = None) -> bool:
        """Wait for page to be fully loaded.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            True if page loaded, False if timeout
        """
        try:
            timeout = timeout or self.config.page_load_timeout
            wait = WebDriverWait(self.driver, timeout)
            wait.until(lambda driver: driver.execute_script("return document.readyState") == "complete")
            return True
        except TimeoutException:
            logger.warning("Page load timeout")
            return False
        except Exception as e:
            logger.error(f"Error waiting for page load: {e}")
            return False
    
    def remove_overlays(self):
        """Remove common overlay elements that might block interactions."""
        try:
            overlay_selectors = [
                '.overlay', '.modal-backdrop', '[class*="overlay"]',
                '.loading', '[data-test-selector="loading"]',
                '.spinner', '[aria-label*="loading" i]'
            ]
            
            for selector in overlay_selectors:
                try:
                    overlays = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for overlay in overlays:
                        if overlay.is_displayed():
                            self.driver.execute_script("arguments[0].style.display = 'none';", overlay)
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error removing overlays: {e}")
    
    def get_current_url(self) -> str:
        """Get current URL safely.
        
        Returns:
            Current URL or empty string if error
        """
        try:
            return self.driver.current_url
        except Exception as e:
            logger.error(f"Error getting current URL: {e}")
            return ""
    
    def is_element_present(self, by: By, value: str) -> bool:
        """Check if element is present on page.
        
        Args:
            by: By locator type
            value: Locator value
            
        Returns:
            True if element present, False otherwise
        """
        try:
            self.driver.find_element(by, value)
            return True
        except NoSuchElementException:
            return False
        except Exception as e:
            logger.error(f"Error checking element presence {by}={value}: {e}")
            return False
    
    def take_screenshot(self, file_path: str) -> bool:
        """Take screenshot and save to file.
        
        Args:
            file_path: Path to save screenshot
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.driver.save_screenshot(file_path)
            logger.info(f"Screenshot saved: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            return False