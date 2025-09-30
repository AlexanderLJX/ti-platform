"""CrowdStrike-specific CSS selectors and XPath expressions."""

from selenium.webdriver.common.by import By

# Authentication selectors
EMAIL_FIELD = (By.CSS_SELECTOR, "input[name='email']")
PASSWORD_FIELD = (By.CSS_SELECTOR, "input[name='password']")
CONTINUE_BUTTON = (By.CSS_SELECTOR, "button[data-test-selector='continue']")
LOGIN_BUTTON = (By.CSS_SELECTOR, "button[type='submit']")

# 2FA selectors - CrowdStrike uses separate input fields for each digit
TOKEN_FIELDS = [
    (By.CSS_SELECTOR, f"input[data-segment-index='{i}']") for i in range(6)
]
TOKEN_SUBMIT_BUTTON = (By.CSS_SELECTOR, "button[data-test-selector='mfa-code-submit']")

# Success indicators - URLs that indicate successful login
SUCCESS_URL_INDICATORS = [
    "falcon.crowdstrike.com/dashboard",
    "falcon.crowdstrike.com/intelligence"
]

# Login form indicators
LOGIN_FORM_INDICATORS = [
    EMAIL_FIELD,
    PASSWORD_FIELD
]

# Export button selectors - ordered by specificity
EXPORT_BUTTON_SELECTORS = [
    (By.CSS_SELECTOR, "div[data-test-selector='file-export'] button[data-test-selector='falcon-popover-trigger']"),
    (By.XPATH, "//div[@data-test-selector='file-export']//button[contains(., 'Export')]"),
    (By.XPATH, "//button[contains(., 'Export') and @data-test-selector='falcon-popover-trigger']"),
    (By.CSS_SELECTOR, "button[data-test-selector='falcon-popover-trigger']"),
]

# CSV download button
CSV_BUTTON = (By.CSS_SELECTOR, "button[data-test-selector='csv-button']")

# Download management selectors
DOWNLOAD_BUTTON = (By.CSS_SELECTOR, "button[data-test-selector='download-button']")
DELETE_BUTTON = (By.CSS_SELECTOR, "button[data-test-selector='delete-button']")

# Loading indicators
LOADING_SELECTORS = [
    "div[data-test-selector='loading']",
    ".loading",
    "[data-test-id*='loading']",
    ".spinner",
    "[aria-label*='loading' i]"
]

# URLs
BASE_URL = "https://falcon.crowdstrike.com"
LOGIN_URL = "https://falcon.crowdstrike.com/login"
INTELLIGENCE_URL = "https://falcon.crowdstrike.com/intelligence-v2/actors"

def get_indicators_url(actor_slug: str) -> str:
    """Get the indicators URL for a specific actor.
    
    Args:
        actor_slug: The actor slug/identifier
        
    Returns:
        Full URL for the actor's indicators page
    """
    return f"https://falcon.crowdstrike.com/intelligence-v2/indicators?filter=type_name%3A%27domain%27%2Btype_name%3A%27url%27%2Btype_name%3A%27ip_address%27%2Bactors.slug%3A%27{actor_slug}%27"