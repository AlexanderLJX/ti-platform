"""Mandiant scraper implementation."""

import time
import logging
import csv
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any, Set

from ...core.base_scraper import BaseScraper
from ...core.plugin_system.registry import BasePlugin
from ...core.models import ThreatActor, PluginInfo, IndicatorType
from ...core.config import ConfigManager
from . import selectors

try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False

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
            current_url = self.playwright_helper.get_current_url()

            # If we're still on login domain, navigate to advantage
            if "login.mandiant.com" in current_url:
                self.logger.info("Navigating from login domain to advantage...")
                if not self.playwright_helper.navigate_to("https://advantage.mandiant.com"):
                    return False

            # Verify we're on advantage domain
            final_url = self.playwright_helper.get_current_url()
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
            if not self.playwright_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to actor page for {threat_actor.name}")
                return None

            # Step 1: Find and click "Take Action" button
            take_action_locator = self._find_take_action_button()
            if not take_action_locator:
                self.logger.error(f"Take Action button not found for {threat_actor.name}")
                return None

            # Click Take Action to open dropdown
            if not self.playwright_helper.click_element_safe(take_action_locator):
                self.logger.error(f"Failed to click Take Action button for {threat_actor.name}")
                return None

            time.sleep(2)  # Wait for dropdown to appear
            self.logger.info(f"Opened Take Action dropdown for {threat_actor.name}")

            # Step 2: Find "Download Indicators" option
            download_locator = self._find_download_indicators_option()
            if not download_locator:
                self.logger.error(f"Download Indicators option not found for {threat_actor.name}")
                return None

            # Step 3: Click and wait for download using Playwright's download API
            self.logger.info(f"Waiting for download for {threat_actor.name}...")

            def click_download():
                """Click the download button."""
                if not self.playwright_helper.click_element_safe(download_locator):
                    raise Exception("Failed to click Download Indicators")

            # Create a clean filename based on actor name
            safe_actor_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in threat_actor.name)
            safe_actor_name = safe_actor_name.replace(' ', '_')
            custom_filename = f"{safe_actor_name}_indicators"

            downloaded_file = self.playwright_helper.wait_for_download(
                action_func=click_download,
                timeout=self.config.download_timeout,
                custom_filename=custom_filename
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
            Take Action button Locator or None
        """
        for selector in selectors.TAKE_ACTION_SELECTORS:
            try:
                locator = self.playwright_helper.find_element_safe(selector, timeout=5)
                if locator and locator.is_visible():
                    return locator
            except Exception:
                continue

        return None

    def _find_download_indicators_option(self):
        """Find the Download Indicators option in dropdown.

        Returns:
            Download Indicators option Locator or None
        """
        for selector in selectors.DOWNLOAD_INDICATORS_SELECTORS:
            try:
                locator = self.playwright_helper.find_element_safe(selector, timeout=5)
                if locator and locator.is_visible():
                    return locator
            except Exception:
                continue

        return None

    def _scrape_report_pdf(self, report_id: str, output_dir: Optional[str] = None) -> Optional[str]:
        """Download PDF from a Mandiant report page.

        Args:
            report_id: Report ID (e.g., '19-00007872')
            output_dir: Optional directory to save PDFs (defaults to config download path)

        Returns:
            Path to downloaded PDF, or None if failed
        """
        try:
            # COPIED EXACTLY FROM _scrape_threat_actor_indicators lines 107-121
            # Clean the report ID (remove anything after #)
            clean_report_id = report_id.split('#')[0] if report_id else report_id
            if not clean_report_id:
                self.logger.error(f"No valid report ID for {report_id}")
                return None

            # Construct URL
            url = f"https://advantage.mandiant.com/reports/{clean_report_id}"
            self.logger.info(f"Processing report: {clean_report_id}")
            self.logger.debug(f"URL: {url}")

            # Navigate to report page
            if not self.playwright_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to report page for {clean_report_id}")
                return None

            # Check if we got redirected to upgrade page (no access)
            current_url = self.playwright_helper.get_current_url()
            if "/upgrade" in current_url:
                self.logger.warning(f"No access to report {clean_report_id} - redirected to upgrade page")
                return None
            # END COPIED CODE

            # Find PDF download button (try multiple selectors)
            self.logger.info(f"Looking for PDF download button for report {clean_report_id}...")
            pdf_locator = self._find_pdf_download_button()
            if not pdf_locator:
                self.logger.warning(f"PDF download button not found for report {clean_report_id} - may not have PDF")
                return None

            # Click and wait for download using Playwright's download API
            self.logger.info(f"Downloading PDF for report {clean_report_id}...")

            def click_download():
                """Click the PDF download button."""
                if not self.playwright_helper.click_element_safe(pdf_locator):
                    raise Exception("Failed to click PDF download button")

            # Use report ID as filename
            custom_filename = f"{clean_report_id}"

            downloaded_file = self.playwright_helper.wait_for_download(
                action_func=click_download,
                timeout=self.config.download_timeout,
                custom_filename=custom_filename
            )

            if not downloaded_file:
                self.logger.error(f"PDF download timeout for report {clean_report_id}")
                return None

            self.logger.info(f"PDF downloaded for report {clean_report_id}: {downloaded_file}")

            # Convert PDF to text
            txt_path = self._convert_pdf_to_txt(downloaded_file, clean_report_id, url)
            if txt_path:
                return txt_path

            # If conversion fails, return PDF path
            return downloaded_file

        except Exception as e:
            self.logger.error(f"Failed to download PDF for report {report_id}: {e}")
            return None

    def _find_pdf_download_button(self):
        """Find the PDF download button using multiple selectors.

        Returns:
            PDF download button Locator or None
        """
        for selector in selectors.PDF_DOWNLOAD_BUTTON_SELECTORS:
            try:
                locator = self.playwright_helper.find_element_safe(selector, timeout=2)
                if locator and locator.is_visible():
                    self.logger.info(f"Found PDF button with selector: {selector}")
                    return locator
            except Exception:
                continue

        return None

    def _convert_pdf_to_txt(self, pdf_path: str, report_id: str, report_url: str) -> Optional[str]:
        """Convert PDF to text file.

        Args:
            pdf_path: Path to PDF file
            report_id: Report ID for output filename
            report_url: Report URL for metadata

        Returns:
            Path to text file, or None if failed
        """
        try:
            if not HAS_PYPDF2:
                self.logger.warning("PyPDF2 not installed, cannot convert PDF to text")
                return None

            pdf_file_path = Path(pdf_path)
            txt_path = pdf_file_path.with_suffix('.txt')

            # Extract text from PDF with error handling
            text_content = []
            try:
                with open(pdf_file_path, 'rb') as pdf_file:
                    pdf_reader = PyPDF2.PdfReader(pdf_file, strict=False)

                    for page_num, page in enumerate(pdf_reader.pages):
                        try:
                            page_text = page.extract_text()
                            if page_text:
                                text_content.append(f"\n--- Page {page_num + 1} ---\n")
                                text_content.append(page_text)
                        except Exception as page_error:
                            self.logger.warning(f"Failed to extract page {page_num + 1}: {page_error}")
                            text_content.append(f"\n--- Page {page_num + 1} (extraction failed) ---\n")

            except Exception as pdf_error:
                self.logger.error(f"Failed to read PDF {pdf_path}: {pdf_error}")
                # If PDF is corrupted, keep it but note the error
                text_content.append(f"\n[PDF EXTRACTION ERROR: {pdf_error}]\n")
                text_content.append("PDF file saved but text extraction failed. Please view the PDF directly.\n")

            # Create text file with metadata
            full_text = f"""Mandiant Advantage Threat Report
Report ID: {report_id}
Source: Mandiant Advantage
URL: {report_url}
PDF Source: {pdf_file_path.name}

{'='*80}

{''.join(text_content)}
"""

            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(full_text)

            self.logger.info(f"PDF converted to text: {txt_path}")
            return str(txt_path)

        except Exception as e:
            self.logger.error(f"Failed to convert PDF to text for {report_id}: {e}")
            # Delete corrupted PDF if conversion completely fails
            try:
                if Path(pdf_path).exists():
                    Path(pdf_path).unlink()
                    self.logger.info(f"Deleted corrupted PDF: {pdf_path}")
            except:
                pass
            return None

    def scrape_pdfs_from_csv(self, csv_file_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Process CSV file and download PDFs for all Mandiant reports.

        Args:
            csv_file_path: Path to CSV file containing IOCs with Associated Reports column
            output_dir: Optional directory to save PDFs (defaults to config download path)

        Returns:
            Dictionary with download statistics
        """
        try:
            csv_path = Path(csv_file_path)
            if not csv_path.exists():
                self.logger.error(f"CSV file not found: {csv_file_path}")
                return {"error": "File not found", "downloaded": 0, "failed": 0, "skipped": 0}

            # Collect unique report IDs from CSV (only Mandiant reports)
            report_ids: Set[str] = set()
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Only process Mandiant rows
                    source = row.get('Source', '').strip().lower()
                    if source != 'mandiant':
                        continue

                    reports_str = row.get('Associated Reports', '').strip()
                    if reports_str:
                        # Split by comma and clean up
                        reports = [r.strip() for r in reports_str.split(',') if r.strip()]
                        report_ids.update(reports)

            self.logger.info(f"Found {len(report_ids)} unique Mandiant reports in CSV")

            if not report_ids:
                self.logger.warning("No Mandiant reports found in CSV")
                return {"error": "No reports found", "downloaded": 0, "failed": 0, "skipped": 0}

            # Authenticate once (EXACT same as IOC scraper)
            if not self.authenticate():
                self.logger.error("Authentication failed, cannot proceed with PDF downloads")
                return {"error": "Authentication failed", "downloaded": 0, "failed": 0, "skipped": 0}

            # Navigate to a threat actor page first and wait (EXACTLY like IOC scraper does)
            # This ensures the page is fully loaded before navigating to reports
            actor_url = "https://advantage.mandiant.com/actors/apt1"
            self.logger.info("Navigating to threat actor page first...")
            if not self.playwright_helper.navigate_to(actor_url, wait_time=5):
                self.logger.error("Failed to navigate to threat actor page")
                return {"error": "Navigation failed", "downloaded": 0, "failed": 0, "skipped": 0}
            self.logger.info("Threat actor page loaded successfully")

            # Step 1: Find and click "Take Action" button
            take_action_locator = self._find_take_action_button()
            if not take_action_locator:
                self.logger.error(f"Take Action button not found for")
                return None

            # Download PDFs for each report
            downloaded = 0
            failed = 0
            skipped = 0
            downloaded_files = []

            for i, report_id in enumerate(sorted(report_ids), 1):
                self.logger.info(f"Processing {i}/{len(report_ids)}: {report_id}")

                result = self._scrape_report_pdf(report_id, output_dir)
                if result:
                    downloaded += 1
                    downloaded_files.append(result)
                elif result is None:
                    skipped += 1
                else:
                    failed += 1

                # Add delay between requests (EXACT same as IOC scraper)
                if i < len(report_ids):
                    delay = 2
                    self.logger.info(f"Waiting {delay}s before next request...")
                    time.sleep(delay)

            stats = {
                "total_reports": len(report_ids),
                "downloaded": downloaded,
                "failed": failed,
                "skipped": skipped,
                "files": downloaded_files
            }

            self.logger.info(f"PDF download summary: {downloaded} downloaded, {failed} failed, {skipped} skipped")
            return stats

        except Exception as e:
            self.logger.error(f"Error processing CSV for PDF downloads: {e}")
            return {"error": str(e), "downloaded": 0, "failed": 0, "skipped": 0}

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
            if not self.playwright_helper or not self.playwright_helper.page:
                return False

            current_url = self.playwright_helper.get_current_url()
            return "mandiant.com" in current_url.lower() or current_url == "about:blank"
        except Exception:
            return False