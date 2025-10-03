"""Mandiant-specific CSS selectors for Playwright."""

# Authentication selectors (CSS)
EMAIL_FIELD = "#email"
PASSWORD_FIELD = "#password"
NEXT_BUTTON = "#id_first_next"
SIGN_IN_BUTTON = "#sign_in_btn"

# 2FA selectors (CSS)
TOKEN_FIELD = "#token_code"
TOKEN_SUBMIT_BUTTON = "button[type='submit']"

# Success indicators
SUCCESS_URL_INDICATORS = [
    "/settings",
    "advantage.mandiant.com"
]

# Login form indicators
LOGIN_FORM_INDICATORS = [
    "#email",
    "#password"
]

# Take Action dropdown selectors (CSS/text-based)
TAKE_ACTION_SELECTORS = [
    "text=Take Action",
    "div[aria-haspopup='menu']",
    "div[role='button']:has-text('Take Action')"
]

# Download Indicators option selectors (CSS/text-based)
DOWNLOAD_INDICATORS_SELECTORS = [
    "text=Download Indicators",
    "div[role='menuitem']:has-text('Download Indicators')"
]

# Report PDF selectors (multiple fallbacks)
PDF_DOWNLOAD_BUTTON_SELECTORS = [
    "button.css-1xd8ns1:has-text('Download PDF')",  # Most specific - try first
    "button[type='button']:has-text('Download PDF')",
    "button:has-text('Download PDF')",
    "button:has-text('PDF')",
    "a:has-text('Download PDF')",
    "[aria-label*='Download PDF' i]",
    "div[role='button']:has-text('Download PDF')"
]

# Legacy single selector for compatibility
PDF_DOWNLOAD_BUTTON = "button:has-text('Download PDF')"

# URLs
BASE_URL = "https://advantage.mandiant.com"
LOGIN_URL = "https://login.mandiant.com/"

def get_report_url(report_id: str) -> str:
    """Get the report URL for a specific report.

    Args:
        report_id: The report ID (e.g., '19-00007872')

    Returns:
        Full URL for the report page
    """
    return f"https://advantage.mandiant.com/reports/{report_id}"