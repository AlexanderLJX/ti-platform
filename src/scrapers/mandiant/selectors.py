"""Mandiant-specific CSS selectors and XPath expressions."""

from selenium.webdriver.common.by import By

# Authentication selectors
EMAIL_FIELD = (By.ID, "email")
PASSWORD_FIELD = (By.ID, "password")
NEXT_BUTTON = (By.ID, "id_first_next")
SIGN_IN_BUTTON = (By.ID, "sign_in_btn")

# 2FA selectors
TOKEN_FIELD = (By.ID, "token_code")
TOKEN_SUBMIT_BUTTON = (By.CSS_SELECTOR, "button[type='submit']")

# Success indicators
SUCCESS_URL_INDICATORS = [
    "/settings",
    "advantage.mandiant.com"
]

# Login form indicators  
LOGIN_FORM_INDICATORS = [
    EMAIL_FIELD,
    PASSWORD_FIELD
]

# Take Action dropdown selectors
TAKE_ACTION_SELECTORS = [
    (By.XPATH, "//div[@role='button' and contains(text(), 'Take Action')]"),
    (By.XPATH, "//div[contains(text(), 'Take Action')]"),
    (By.CSS_SELECTOR, "div[aria-haspopup='menu']"),
    (By.XPATH, "//div[@aria-haspopup='menu']")
]

# Download Indicators option selectors
DOWNLOAD_INDICATORS_SELECTORS = [
    (By.XPATH, "//div[@role='menuitem' and contains(text(), 'Download Indicators')]"),
    (By.XPATH, "//div[contains(text(), 'Download Indicators')]"),
    (By.XPATH, "//div[@role='menuitem']//text()[contains(., 'Download Indicators')]/parent::*")
]

# URLs
BASE_URL = "https://advantage.mandiant.com"
LOGIN_URL = "https://login.mandiant.com/"