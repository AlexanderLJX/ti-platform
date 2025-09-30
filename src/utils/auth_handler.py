"""Authentication and 2FA handling utilities."""

import time
import logging
import pyotp
from typing import Optional, Dict, Any, Callable
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

from .selenium_helper import SeleniumHelper

logger = logging.getLogger(__name__)


class AuthHandler:
    """Handles authentication flows including 2FA."""
    
    def __init__(self, selenium_helper: SeleniumHelper):
        """Initialize authentication handler.
        
        Args:
            selenium_helper: Selenium helper instance
        """
        self.selenium = selenium_helper
        self.driver = selenium_helper.driver
        self.wait = selenium_helper.wait
    
    def check_login_status(self, success_indicators: list, login_indicators: list) -> bool:
        """Check if user is already logged in.

        Args:
            success_indicators: List of (by, value) tuples indicating successful login
            login_indicators: List of (by, value) tuples indicating login page

        Returns:
            True if already logged in, False otherwise
        """
        try:
            current_url = self.selenium.get_current_url().lower()

            # First check URL-based success indicators (e.g., /dashboard/, /intelligence/)
            for indicator in success_indicators:
                if isinstance(indicator, str) and indicator.lower() in current_url:
                    logger.info(f"Already logged in based on URL: {indicator}")
                    return True

            # Check if we're on a login/auth page by URL
            if '/login' in current_url or '/auth' in current_url or '/signin' in current_url:
                # Double-check by looking for login form elements
                login_form_found = False
                for by, value in login_indicators:
                    if isinstance(by, str):
                        by = getattr(By, by.upper().replace(' ', '_'))

                    element = self.selenium.find_element_safe(by, value, timeout=3)
                    if element and element.is_displayed():
                        login_form_found = True
                        break

                if login_form_found:
                    logger.info("On login page with login form detected, not logged in")
                    return False
                else:
                    # On login URL but no form found - likely redirected after login
                    logger.info("On login URL but no form found - assuming logged in (redirected)")
                    return True

            # Check for login form elements
            for by, value in login_indicators:
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))

                element = self.selenium.find_element_safe(by, value, timeout=3)
                if element and element.is_displayed():
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
        email_selector: tuple,
        password_selector: tuple,
        submit_selectors: list,
        next_selector: Optional[tuple] = None
    ) -> bool:
        """Perform login with credentials.
        
        Args:
            credentials: Dict with 'email' and 'password' keys
            email_selector: (by, value) for email field
            password_selector: (by, value) for password field  
            submit_selectors: List of (by, value) tuples for submit buttons
            next_selector: Optional (by, value) for next button after email
            
        Returns:
            True if login steps completed, False otherwise
        """
        try:
            # Step 1: Enter email
            email_by, email_value = email_selector
            if isinstance(email_by, str):
                email_by = getattr(By, email_by.upper().replace(' ', '_'))
            
            email_field = self.selenium.find_element_safe(email_by, email_value)
            if not email_field:
                logger.error("Email field not found")
                return False
            
            if not self.selenium.send_keys_safe(email_field, credentials['email']):
                logger.error("Failed to enter email")
                return False
            
            logger.info(f"Email entered: {credentials['email']}")
            
            # Step 2: Click next if required
            if next_selector:
                next_by, next_value = next_selector
                if isinstance(next_by, str):
                    next_by = getattr(By, next_by.upper().replace(' ', '_'))
                
                next_button = self.selenium.find_element_safe(next_by, next_value)
                if next_button:
                    if not self.selenium.click_element_safe(next_button):
                        logger.error("Failed to click next button")
                        return False
                    
                    logger.info("Next button clicked")
                    time.sleep(3)  # Wait for password field to appear
            
            # Step 3: Enter password
            password_by, password_value = password_selector
            if isinstance(password_by, str):
                password_by = getattr(By, password_by.upper().replace(' ', '_'))
            
            password_field = self.selenium.wait_for_element_clickable(password_by, password_value)
            if not password_field:
                logger.error("Password field not found")
                return False
            
            if not self.selenium.send_keys_safe(password_field, credentials['password']):
                logger.error("Failed to enter password")
                return False
            
            logger.info("Password entered")
            
            # Step 4: Submit form
            submit_success = False
            for submit_by, submit_value in submit_selectors:
                if isinstance(submit_by, str):
                    submit_by = getattr(By, submit_by.upper().replace(' ', '_'))
                
                submit_button = self.selenium.find_element_safe(submit_by, submit_value)
                if submit_button and submit_button.is_displayed():
                    if self.selenium.click_element_safe(submit_button):
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
            token_selectors: List of (by, value) tuples for token fields
            submit_selectors: List of (by, value) tuples for submit buttons
            totp_secret: Base32 encoded TOTP secret key
            
        Returns:
            True if 2FA completed, False otherwise
        """
        try:
            # Check if 2FA is required
            token_field = None
            for by, value in token_selectors:
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))
                
                field = self.selenium.find_element_safe(by, value, timeout=5)
                if field and field.is_displayed():
                    token_field = field
                    break
            
            if not token_field:
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
                separate_fields = self.selenium.find_elements_safe(By.CSS_SELECTOR, "input[data-segment-index]")
                if len(separate_fields) == 6:
                    logger.info("Entering 2FA token in separate fields")
                    for i, digit in enumerate(token):
                        field = self.selenium.find_element_safe(By.CSS_SELECTOR, f"input[data-segment-index='{i}']")
                        if field:
                            self.selenium.send_keys_safe(field, digit, clear_first=True)
                            time.sleep(0.1)
                else:
                    # Single token field
                    logger.info("Entering 2FA token in single field")
                    self.selenium.send_keys_safe(token_field, token)
            else:
                # Single token field
                logger.info("Entering 2FA token in single field")
                self.selenium.send_keys_safe(token_field, token)
            
            logger.info("2FA token entered")
            
            # Submit 2FA
            submit_success = False
            for by, value in submit_selectors:
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))
                
                submit_button = self.selenium.find_element_safe(by, value)
                if submit_button and submit_button.is_displayed():
                    if self.selenium.click_element_safe(submit_button):
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
            for by, value in token_selectors:
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))

                field = self.selenium.find_element_safe(by, value, timeout=3)
                if field and field.is_displayed():
                    logger.warning("Still on 2FA page, validation may have failed")
                    return False
            
            logger.info("2FA validation completed")
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
            token_selectors: List of (by, value) tuples for token fields
            submit_selectors: List of (by, value) tuples for submit buttons
            prompt_message: Message to display for token input
            
        Returns:
            True if 2FA completed, False otherwise
        """
        try:
            # Check if 2FA is required
            token_field = None
            for by, value in token_selectors:
                # by should already be a By object from selectors, but handle strings as fallback
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))
                
                field = self.selenium.find_element_safe(by, value, timeout=5)
                if field and field.is_displayed():
                    token_field = field
                    break
            
            if not token_field:
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
                # Check for multiple separate input fields (like CrowdStrike)
                separate_fields = self.selenium.find_elements_safe(By.CSS_SELECTOR, "input[data-segment-index]")
                if len(separate_fields) == 6:
                    logger.info("Entering 2FA token in separate fields")
                    for i, digit in enumerate(token):
                        field = self.selenium.find_element_safe(By.CSS_SELECTOR, f"input[data-segment-index='{i}']")
                        if field:
                            self.selenium.send_keys_safe(field, digit, clear_first=True)
                            time.sleep(0.1)
                else:
                    # Single token field
                    logger.info("Entering 2FA token in single field")
                    self.selenium.send_keys_safe(token_field, token)
            else:
                # Single token field
                logger.info("Entering 2FA token in single field")
                self.selenium.send_keys_safe(token_field, token)
            
            logger.info("2FA token entered")
            
            # Submit 2FA
            submit_success = False
            for by, value in submit_selectors:
                # by should already be a By object from selectors, but handle strings as fallback
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))
                
                submit_button = self.selenium.find_element_safe(by, value)
                if submit_button and submit_button.is_displayed():
                    if self.selenium.click_element_safe(submit_button):
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
            for by, value in token_selectors:
                if isinstance(by, str):
                    by = getattr(By, by.upper().replace(' ', '_'))

                field = self.selenium.find_element_safe(by, value, timeout=3)
                if field and field.is_displayed():
                    logger.warning("Still on 2FA page, validation may have failed")
                    return False
            
            logger.info("2FA validation completed")
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
            success_indicators: List of indicators for successful login
            failure_indicators: List of indicators for failed login
            
        Returns:
            True if login successful, False otherwise
        """
        try:
            current_url = self.selenium.get_current_url().lower()
            
            # Check for success indicators
            for indicator in success_indicators:
                if isinstance(indicator, str):
                    if indicator.lower() in current_url:
                        logger.info(f"Login success verified by URL: {indicator}")
                        return True
                else:
                    # Tuple format (by, value)
                    by, value = indicator
                    if isinstance(by, str):
                        by = getattr(By, by.upper().replace(' ', '_'))
                    
                    element = self.selenium.find_element_safe(by, value, timeout=3)
                    if element:
                        logger.info(f"Login success verified by element: {by}={value}")
                        return True
            
            # Check for failure indicators
            if failure_indicators:
                for indicator in failure_indicators:
                    if isinstance(indicator, str):
                        if indicator.lower() in current_url:
                            logger.error(f"Login failure detected by URL: {indicator}")
                            return False
                    else:
                        # Tuple format (by, value)
                        by, value = indicator
                        if isinstance(by, str):
                            by = getattr(By, by.upper().replace(' ', '_'))
                        
                        element = self.selenium.find_element_safe(by, value, timeout=3)
                        if element and element.is_displayed():
                            logger.error(f"Login failure detected by element: {by}={value}")
                            return False
            
            # If no clear indicators, assume success if not on login page
            if "login" not in current_url:
                logger.info("Login appears successful - not on login page")
                return True
            
            logger.warning("Login status unclear")
            return True  # Default to success to avoid blocking
            
        except Exception as e:
            logger.error(f"Error verifying login success: {e}")
            return False