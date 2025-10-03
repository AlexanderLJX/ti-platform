"""Authentication and 2FA handling utilities for Playwright."""

import time
import logging
import pyotp
from typing import Optional, Dict, Any
from playwright.sync_api import Page, Locator, TimeoutError as PlaywrightTimeoutError

from .playwright_helper import PlaywrightHelper

logger = logging.getLogger(__name__)


class PlaywrightAuthHandler:
    """Handles authentication flows including 2FA for Playwright."""

    def __init__(self, playwright_helper: PlaywrightHelper):
        """Initialize authentication handler.

        Args:
            playwright_helper: Playwright helper instance
        """
        self.pw = playwright_helper
        self.page = playwright_helper.page

    def check_login_status(self, success_indicators: list, login_indicators: list) -> bool:
        """Check if user is already logged in.

        Args:
            success_indicators: List of strings (URLs) or selectors indicating successful login
            login_indicators: List of selectors indicating login page

        Returns:
            True if already logged in, False otherwise
        """
        try:
            current_url = self.pw.get_current_url().lower()

            # First check URL-based success indicators
            for indicator in success_indicators:
                if isinstance(indicator, str) and indicator.lower() in current_url:
                    logger.info(f"Already logged in based on URL: {indicator}")
                    return True

            # Check if we're on a login/auth page by URL
            if '/login' in current_url or '/auth' in current_url or '/signin' in current_url:
                # Double-check by looking for login form elements
                login_form_found = False
                for selector in login_indicators:
                    if self.pw.is_element_present(selector):
                        login_form_found = True
                        break

                if login_form_found:
                    logger.info("On login page with login form detected, not logged in")
                    return False
                else:
                    logger.info("On login URL but no form found - assuming logged in (redirected)")
                    return True

            # Check for login form elements
            for selector in login_indicators:
                if self.pw.is_element_present(selector):
                    logger.info("Login form detected, not logged in")
                    return False

            # If no login form found, assume logged in
            logger.info("No login form detected, assuming logged in")
            return True

        except Exception as e:
            logger.error(f"Error checking login status: {e}")
            return False

    def perform_login(
        self,
        credentials: Dict[str, str],
        email_selector: str,
        password_selector: str,
        submit_selectors: list,
        next_selector: Optional[str] = None
    ) -> bool:
        """Perform login with credentials.

        Args:
            credentials: Dict with 'email' and 'password' keys
            email_selector: CSS selector for email field
            password_selector: CSS selector for password field
            submit_selectors: List of CSS selectors for submit buttons
            next_selector: Optional CSS selector for next button after email

        Returns:
            True if login steps completed, False otherwise
        """
        try:
            # Step 1: Enter email
            email_locator = self.pw.find_element_safe(email_selector, timeout=10)
            if not email_locator:
                logger.error("Email field not found")
                return False

            if not self.pw.send_keys_safe(email_locator, credentials['email']):
                logger.error("Failed to enter email")
                return False

            logger.info(f"Email entered: {credentials['email']}")

            # Step 2: Click next if required
            if next_selector:
                time.sleep(1)  # Wait for button to be ready
                next_locator = self.pw.find_element_safe(next_selector)
                if next_locator:
                    # Use force click to bypass overlays
                    if not self.pw.click_element_safe(next_locator, use_js=True):
                        logger.error("Failed to click next button")
                        return False

                    logger.info("Next button clicked")
                    time.sleep(3)  # Wait for password field to appear

            # Step 3: Enter password
            password_locator = self.pw.wait_for_element_clickable(password_selector, timeout=10)
            if not password_locator:
                logger.error("Password field not found")
                return False

            if not self.pw.send_keys_safe(password_locator, credentials['password']):
                logger.error("Failed to enter password")
                return False

            logger.info("Password entered")

            # Step 4: Submit form
            time.sleep(1)  # Wait for button to be ready
            submit_success = False
            for submit_selector in submit_selectors:
                submit_locator = self.pw.find_element_safe(submit_selector)
                if submit_locator and submit_locator.is_visible():
                    # Use force click to bypass overlays
                    if self.pw.click_element_safe(submit_locator, use_js=True):
                        logger.info("Login form submitted")
                        submit_success = True
                        break

            if not submit_success:
                logger.error("Failed to submit login form")
                return False

            # Wait for response
            time.sleep(5)
            return True

        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False

    def handle_2fa_automatic(
        self,
        token_selectors: list,
        submit_selectors: list,
        totp_secret: str
    ) -> bool:
        """Handle 2FA with automatic TOTP generation.

        Args:
            token_selectors: List of CSS selectors for token fields
            submit_selectors: List of CSS selectors for submit buttons
            totp_secret: Base32 encoded TOTP secret key

        Returns:
            True if 2FA completed, False otherwise
        """
        try:
            # Check if 2FA is required
            token_locator = None
            for selector in token_selectors:
                locator = self.pw.find_element_safe(selector, timeout=5)
                if locator and locator.is_visible():
                    token_locator = locator
                    break

            if not token_locator:
                logger.info("2FA not required")
                return True

            logger.info("2FA required - generating TOTP token")

            # Generate TOTP token
            totp = pyotp.TOTP(totp_secret)
            token = totp.now()
            logger.info(f"Generated TOTP token: {token}")

            # Handle different 2FA input types
            if len(token) == 6 and token.isdigit():
                # Check for multiple separate input fields (like CrowdStrike)
                separate_fields = self.pw.find_elements_safe("input[data-segment-index]")
                if len(separate_fields) == 6:
                    logger.info("Entering 2FA token in separate fields")
                    for i, digit in enumerate(token):
                        field_locator = self.page.locator(f"input[data-segment-index='{i}']")
                        if field_locator:
                            self.pw.send_keys_safe(field_locator, digit, clear_first=True)
                            time.sleep(0.1)
                else:
                    # Single token field
                    logger.info("Entering 2FA token in single field")
                    self.pw.send_keys_safe(token_locator, token)
            else:
                # Single token field
                logger.info("Entering 2FA token in single field")
                self.pw.send_keys_safe(token_locator, token)

            logger.info("2FA token entered")

            # Submit 2FA
            time.sleep(1)  # Wait for button to be ready
            submit_success = False
            for selector in submit_selectors:
                submit_locator = self.pw.find_element_safe(selector)
                if submit_locator and submit_locator.is_visible():
                    # Use force click to bypass overlays
                    if self.pw.click_element_safe(submit_locator, use_js=True):
                        logger.info("2FA form submitted")
                        submit_success = True
                        break

            if not submit_success:
                logger.error("Failed to submit 2FA form")
                return False

            # Wait for validation
            logger.info("Validating 2FA token...")
            time.sleep(5)

            # Check if we're still on 2FA page
            for selector in token_selectors:
                locator = self.pw.find_element_safe(selector, timeout=3)
                if locator and locator.is_visible():
                    logger.warning("Still on 2FA page, validation may have failed")
                    return False

            logger.info("2FA validation completed")

            # Save state after successful authentication
            self.pw.save_state()

            return True

        except Exception as e:
            logger.error(f"Automatic 2FA failed: {e}")
            return False

    def handle_2fa_manual(
        self,
        token_selectors: list,
        submit_selectors: list,
        prompt_message: str = "Enter your 2FA token: "
    ) -> bool:
        """Handle 2FA with manual token entry.

        Args:
            token_selectors: List of CSS selectors for token fields
            submit_selectors: List of CSS selectors for submit buttons
            prompt_message: Message to display for token input

        Returns:
            True if 2FA completed, False otherwise
        """
        try:
            # Check if 2FA is required
            token_locator = None
            for selector in token_selectors:
                locator = self.pw.find_element_safe(selector, timeout=5)
                if locator and locator.is_visible():
                    token_locator = locator
                    break

            if not token_locator:
                logger.info("2FA not required")
                return True

            logger.info("2FA required")

            # Get token from user
            token = input(prompt_message)
            if not token:
                logger.error("No 2FA token provided")
                return False

            # Handle different 2FA input types
            if len(token) == 6 and token.isdigit():
                # Check for multiple separate input fields
                separate_fields = self.pw.find_elements_safe("input[data-segment-index]")
                if len(separate_fields) == 6:
                    logger.info("Entering 2FA token in separate fields")
                    for i, digit in enumerate(token):
                        field_locator = self.page.locator(f"input[data-segment-index='{i}']")
                        if field_locator:
                            self.pw.send_keys_safe(field_locator, digit, clear_first=True)
                            time.sleep(0.1)
                else:
                    # Single token field
                    logger.info("Entering 2FA token in single field")
                    self.pw.send_keys_safe(token_locator, token)
            else:
                # Single token field
                logger.info("Entering 2FA token in single field")
                self.pw.send_keys_safe(token_locator, token)

            logger.info("2FA token entered")

            # Submit 2FA
            time.sleep(1)  # Wait for button to be ready
            submit_success = False
            for selector in submit_selectors:
                submit_locator = self.pw.find_element_safe(selector)
                if submit_locator and submit_locator.is_visible():
                    # Use force click to bypass overlays
                    if self.pw.click_element_safe(submit_locator, use_js=True):
                        logger.info("2FA form submitted")
                        submit_success = True
                        break

            if not submit_success:
                logger.error("Failed to submit 2FA form")
                return False

            # Wait for validation
            logger.info("Validating 2FA token...")
            time.sleep(5)

            # Check if we're still on 2FA page
            for selector in token_selectors:
                locator = self.pw.find_element_safe(selector, timeout=3)
                if locator and locator.is_visible():
                    logger.warning("Still on 2FA page, validation may have failed")
                    return False

            logger.info("2FA validation completed")

            # Save state after successful authentication
            self.pw.save_state()

            return True

        except Exception as e:
            logger.error(f"2FA failed: {e}")
            return False

    def verify_login_success(
        self,
        success_indicators: list,
        failure_indicators: list = None
    ) -> bool:
        """Verify that login was successful.

        Args:
            success_indicators: List of URL strings or selectors for successful login
            failure_indicators: List of selectors for failed login

        Returns:
            True if login successful, False otherwise
        """
        try:
            current_url = self.pw.get_current_url().lower()

            # Check for success indicators
            for indicator in success_indicators:
                if isinstance(indicator, str):
                    # String indicator - check URL
                    if '/' in indicator or 'http' in indicator:
                        if indicator.lower() in current_url:
                            logger.info(f"Login success verified by URL: {indicator}")
                            # Save state on successful login
                            self.pw.save_state()
                            return True
                    else:
                        # CSS selector
                        if self.pw.is_element_present(indicator):
                            logger.info(f"Login success verified by element: {indicator}")
                            # Save state on successful login
                            self.pw.save_state()
                            return True

            # Check for failure indicators
            if failure_indicators:
                for indicator in failure_indicators:
                    if isinstance(indicator, str):
                        if '/' in indicator or 'http' in indicator:
                            if indicator.lower() in current_url:
                                logger.error(f"Login failure detected by URL: {indicator}")
                                return False
                        else:
                            if self.pw.is_element_present(indicator):
                                logger.error(f"Login failure detected by element: {indicator}")
                                return False

            # If no clear indicators, assume success if not on login page
            if "login" not in current_url:
                logger.info("Login appears successful - not on login page")
                # Save state on successful login
                self.pw.save_state()
                return True

            logger.warning("Login status unclear")
            return True  # Default to success to avoid blocking

        except Exception as e:
            logger.error(f"Error verifying login success: {e}")
            return False
