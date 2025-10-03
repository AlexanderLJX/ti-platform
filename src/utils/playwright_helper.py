"""Playwright utility functions and helpers."""

import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page, Locator, Error, TimeoutError as PlaywrightTimeoutError

from ..core.config import BrowserConfig

logger = logging.getLogger(__name__)


class PlaywrightHelper:
    """Helper class for common Playwright operations."""

    def __init__(self, config: BrowserConfig, profile_path: str, download_path: str):
        """Initialize Playwright helper.

        Args:
            config: Browser configuration
            profile_path: Path to browser profile directory (state storage)
            download_path: Path to download directory
        """
        self.config = config
        self.profile_path = Path(profile_path)
        self.download_path = Path(download_path)

        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        # Ensure directories exist
        self.profile_path.mkdir(parents=True, exist_ok=True)
        self.download_path.mkdir(parents=True, exist_ok=True)

        # State file for authentication persistence
        self.state_file = self.profile_path / "state.json"

    def setup_browser(self) -> Page:
        """Set up Playwright browser with configured options.

        Returns:
            Configured Page instance

        Raises:
            Error: If browser setup fails
        """
        try:
            self.playwright = sync_playwright().start()

            # Launch browser (viewport goes in context, not launch)
            launch_options = {
                "headless": self.config.headless,
            }

            self.browser = self.playwright.chromium.launch(**launch_options)

            # Create context with persistent state
            context_options = {
                "accept_downloads": True,
                "bypass_csp": True,
                "ignore_https_errors": True,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

            # Set viewport size if configured (context-level setting)
            if self.config.window_size:
                context_options["viewport"] = {
                    "width": self.config.window_size[0],
                    "height": self.config.window_size[1]
                }

            # Load saved state if exists
            if self.state_file.exists():
                context_options["storage_state"] = str(self.state_file)
                logger.info("Loaded saved browser state")

            self.context = self.browser.new_context(**context_options)

            # Set default timeouts
            self.context.set_default_timeout(self.config.page_load_timeout * 1000)
            self.context.set_default_navigation_timeout(self.config.page_load_timeout * 1000)

            # Create page
            self.page = self.context.new_page()

            logger.info("Playwright browser setup completed successfully")
            return self.page

        except Exception as e:
            logger.error(f"Failed to setup Playwright browser: {e}")
            raise Error(f"Browser setup failed: {e}")

    def save_state(self):
        """Save browser context state for persistent authentication."""
        try:
            if self.context:
                self.context.storage_state(path=str(self.state_file))
                logger.info("Browser state saved successfully")
        except Exception as e:
            logger.warning(f"Failed to save browser state: {e}")

    def quit_browser(self):
        """Close the browser and clean up resources."""
        try:
            if self.page:
                self.page.close()
                self.page = None

            if self.context:
                self.context.close()
                self.context = None

            if self.browser:
                self.browser.close()
                self.browser = None

            if self.playwright:
                self.playwright.stop()
                self.playwright = None

            logger.info("Browser closed successfully")

        except Exception as e:
            logger.warning(f"Error closing browser: {e}")

    def navigate_to(self, url: str, wait_time: int = 3, wait_until: str = "domcontentloaded") -> bool:
        """Navigate to a URL with error handling.

        Args:
            url: URL to navigate to
            wait_time: Time to wait after navigation
            wait_until: Wait strategy (load, domcontentloaded, networkidle, commit)

        Returns:
            True if navigation successful, False otherwise
        """
        try:
            logger.info(f"Navigating to: {url}")

            # Use longer timeout for networkidle (SPAs take time)
            timeout = 60000 if wait_until == "networkidle" else self.config.page_load_timeout * 1000

            # Try primary navigation
            try:
                self.page.goto(url, wait_until=wait_until, timeout=timeout)
            except Exception as nav_error:
                # If navigation fails, check if we still ended up at the URL
                if url in self.page.url:
                    logger.warning(f"Navigation had errors but reached destination: {nav_error}")
                else:
                    raise nav_error

            time.sleep(wait_time)
            return True
        except Exception as e:
            logger.error(f"Failed to navigate to {url}: {e}")
            return False

    def find_element_safe(self, selector: str, timeout: int = None) -> Optional[Locator]:
        """Find element with timeout and error handling.

        Args:
            selector: CSS selector or text selector
            timeout: Timeout in milliseconds (uses default if None)

        Returns:
            Locator if found, None otherwise
        """
        try:
            timeout_ms = (timeout * 1000) if timeout else (self.config.page_load_timeout * 1000)
            locator = self.page.locator(selector)
            locator.wait_for(state="visible", timeout=timeout_ms)
            return locator
        except PlaywrightTimeoutError:
            logger.debug(f"Element not found: {selector}")
            return None
        except Exception as e:
            logger.error(f"Error finding element {selector}: {e}")
            return None

    def find_elements_safe(self, selector: str) -> List[Locator]:
        """Find multiple elements with error handling.

        Args:
            selector: CSS selector

        Returns:
            List of Locators (empty if none found)
        """
        try:
            locator = self.page.locator(selector)
            count = locator.count()
            return [locator.nth(i) for i in range(count)]
        except Exception as e:
            logger.error(f"Error finding elements {selector}: {e}")
            return []

    def click_element_safe(self, locator: Locator, use_js: bool = False) -> bool:
        """Click element with error handling and retry logic.

        Args:
            locator: Locator to click
            use_js: Whether to use JavaScript click (force=True)

        Returns:
            True if click successful, False otherwise
        """
        try:
            # Scroll into view
            locator.scroll_into_view_if_needed()
            time.sleep(0.5)

            if use_js:
                locator.click(force=True)
            else:
                locator.click()

            return True
        except Exception as e:
            logger.error(f"Failed to click element: {e}")
            # Try force click as fallback
            try:
                locator.click(force=True)
                return True
            except Exception as e2:
                logger.error(f"Force click also failed: {e2}")
                return False

    def send_keys_safe(self, locator: Locator, text: str, clear_first: bool = True) -> bool:
        """Send keys to element with error handling.

        Args:
            locator: Locator to send keys to
            text: Text to send
            clear_first: Whether to clear element first

        Returns:
            True if successful, False otherwise
        """
        try:
            if clear_first:
                locator.fill("")
            locator.type(text, delay=50)  # 50ms delay between keystrokes for realism
            return True
        except Exception as e:
            logger.error(f"Failed to send keys to element: {e}")
            return False

    def wait_for_element_clickable(self, selector: str, timeout: int = None) -> Optional[Locator]:
        """Wait for element to be clickable.

        Args:
            selector: CSS selector
            timeout: Timeout in seconds

        Returns:
            Locator if clickable, None otherwise
        """
        try:
            timeout_ms = (timeout * 1000) if timeout else (self.config.page_load_timeout * 1000)
            locator = self.page.locator(selector)
            locator.wait_for(state="visible", timeout=timeout_ms)

            # Check if enabled
            if locator.is_enabled():
                return locator
            return None
        except PlaywrightTimeoutError:
            logger.debug(f"Element not clickable: {selector}")
            return None
        except Exception as e:
            logger.error(f"Error waiting for clickable element {selector}: {e}")
            return None

    def wait_for_page_load(self, timeout: int = None) -> bool:
        """Wait for page to be fully loaded.

        Args:
            timeout: Timeout in seconds

        Returns:
            True if page loaded, False if timeout
        """
        try:
            timeout_ms = (timeout * 1000) if timeout else (self.config.page_load_timeout * 1000)
            self.page.wait_for_load_state("networkidle", timeout=timeout_ms)
            return True
        except PlaywrightTimeoutError:
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
                    locator = self.page.locator(selector)
                    count = locator.count()
                    for i in range(count):
                        elem = locator.nth(i)
                        if elem.is_visible():
                            elem.evaluate("element => element.style.display = 'none'")
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
            return self.page.url
        except Exception as e:
            logger.error(f"Error getting current URL: {e}")
            return ""

    def is_element_present(self, selector: str) -> bool:
        """Check if element is present on page.

        Args:
            selector: CSS selector

        Returns:
            True if element present, False otherwise
        """
        try:
            return self.page.locator(selector).count() > 0
        except Exception as e:
            logger.error(f"Error checking element presence {selector}: {e}")
            return False

    def take_screenshot(self, file_path: str) -> bool:
        """Take screenshot and save to file.

        Args:
            file_path: Path to save screenshot

        Returns:
            True if successful, False otherwise
        """
        try:
            self.page.screenshot(path=file_path, full_page=True)
            logger.info(f"Screenshot saved: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            return False

    def wait_for_selector(self, selector: str, timeout: int = None, state: str = "visible") -> bool:
        """Wait for selector to reach specified state.

        Args:
            selector: CSS selector
            timeout: Timeout in seconds
            state: State to wait for (visible, hidden, attached, detached)

        Returns:
            True if selector reached state, False otherwise
        """
        try:
            timeout_ms = (timeout * 1000) if timeout else (self.config.page_load_timeout * 1000)
            self.page.wait_for_selector(selector, state=state, timeout=timeout_ms)
            return True
        except PlaywrightTimeoutError:
            logger.debug(f"Timeout waiting for selector {selector} to be {state}")
            return False
        except Exception as e:
            logger.error(f"Error waiting for selector {selector}: {e}")
            return False

    def evaluate(self, script: str, *args) -> Any:
        """Execute JavaScript in page context.

        Args:
            script: JavaScript code to execute
            *args: Arguments to pass to script

        Returns:
            Result of script execution
        """
        try:
            return self.page.evaluate(script, *args)
        except Exception as e:
            logger.error(f"Error evaluating script: {e}")
            return None

    def click_by_selector(self, selector: str, use_js: bool = False) -> bool:
        """Click element by selector with error handling.

        Args:
            selector: CSS selector
            use_js: Whether to use force click

        Returns:
            True if click successful, False otherwise
        """
        try:
            locator = self.page.locator(selector)
            return self.click_element_safe(locator, use_js=use_js)
        except Exception as e:
            logger.error(f"Failed to click selector {selector}: {e}")
            return False

    def wait_for_download(self, action_func, timeout: int = 30, custom_filename: Optional[str] = None) -> Optional[str]:
        """Wait for download to complete after performing an action.

        Args:
            action_func: Function to execute that triggers download
            timeout: Timeout in seconds
            custom_filename: Optional custom filename to use instead of suggested filename

        Returns:
            Path to downloaded file, or None if failed
        """
        try:
            # Start waiting for download before clicking
            with self.page.expect_download(timeout=timeout * 1000) as download_info:
                # Perform the action that triggers download
                action_func()

            download = download_info.value

            # Use custom filename if provided, otherwise use suggested filename
            if custom_filename:
                # Preserve the extension from the original filename
                original_filename = download.suggested_filename
                extension = original_filename.rsplit('.', 1)[-1] if '.' in original_filename else 'csv'
                # Ensure custom filename has extension
                if not custom_filename.endswith(f'.{extension}'):
                    filename = f"{custom_filename}.{extension}"
                else:
                    filename = custom_filename
            else:
                filename = download.suggested_filename

            # Save to our download directory
            download_path = self.download_path / filename
            download.save_as(str(download_path))

            logger.info(f"Download completed: {download_path}")
            return str(download_path)

        except PlaywrightTimeoutError:
            logger.warning(f"Download timeout after {timeout} seconds")
            return None
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return None
