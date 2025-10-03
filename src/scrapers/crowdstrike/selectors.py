"""CrowdStrike-specific CSS selectors for Playwright."""

# Authentication selectors (CSS)
EMAIL_FIELD = "input[name='email']"
PASSWORD_FIELD = "input[name='password']"
CONTINUE_BUTTON = "button[data-test-selector='continue']"
LOGIN_BUTTON = "button[type='submit']"

# 2FA selectors - CrowdStrike uses separate input fields for each digit
TOKEN_FIELDS = [f"input[data-segment-index='{i}']" for i in range(6)]
TOKEN_SUBMIT_BUTTON = "button[data-test-selector='mfa-code-submit']"

# Success indicators - URLs that indicate successful login
SUCCESS_URL_INDICATORS = [
    "falcon.crowdstrike.com/dashboard",
    "falcon.crowdstrike.com/intelligence"
]

# Login form indicators
LOGIN_FORM_INDICATORS = [
    "input[name='email']",
    "input[name='password']"
]

# Export button selectors - ordered by specificity
EXPORT_BUTTON_SELECTORS = [
    "div[data-test-selector='file-export'] button[data-test-selector='falcon-popover-trigger']",
    "button[data-test-selector='falcon-popover-trigger']:has-text('Export')",
    "button[data-test-selector='falcon-popover-trigger']"
]

# CSV download button
CSV_BUTTON = "button[data-test-selector='csv-button']"

# Download management selectors
DOWNLOAD_BUTTON = "button[data-test-selector='download-button']"
DELETE_BUTTON = "button[data-test-selector='delete-button']"

# Report content selectors
PDF_BUTTON = "button[data-test-selector='button-pdf'][aria-label='Open pdf']"
REPORT_MAIN_CONTENT = "main.report-details"
REPORT_TITLE = "h2[data-test-selector='report-details-title']"

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

def get_report_url(report_slug: str) -> str:
    """Get the report URL for a specific report.

    Args:
        report_slug: The report slug/identifier

    Returns:
        Full URL for the report page
    """
    return f"https://falcon.crowdstrike.com/intelligence-v2/reports/{report_slug}"