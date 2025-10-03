"""CrowdStrike scraper implementation with Playwright."""

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
            current_url = self.playwright_helper.get_current_url()

            # Navigate to intelligence page if not already there
            if "intelligence-v2/actors" not in current_url:
                self.logger.info("Navigating to intelligence page...")
                # Use 'commit' wait strategy for more reliable navigation on CrowdStrike
                if not self.playwright_helper.navigate_to(selectors.INTELLIGENCE_URL, wait_time=5, wait_until="commit"):
                    # Check if we still reached the destination despite error
                    final_url = self.playwright_helper.get_current_url()
                    if "intelligence-v2" not in final_url:
                        self.logger.error(f"Navigation failed and not at destination: {final_url}")
                        return False
                    self.logger.info("Navigation had errors but reached destination")

            # Verify we're on the correct page
            final_url = self.playwright_helper.get_current_url()
            if "falcon.crowdstrike.com" not in final_url:
                self.logger.error(f"Not on CrowdStrike domain: {final_url}")
                return False

            self.logger.info("Successfully navigated to CrowdStrike Intelligence")
            return True

        except Exception as e:
            self.logger.error(f"Post-login navigation failed: {e}")
            return False

    def _scrape_threat_actor_indicators(self, threat_actor: ThreatActor) -> Optional[str]:
        """Scrape indicators for a CrowdStrike threat actor.

        Args:
            threat_actor: Threat actor to scrape

        Returns:
            Path to downloaded file, or None if failed
        """
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
            if not self.playwright_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to indicators page for {threat_actor.name}")
                return None

            # Wait for export button
            export_selector = selectors.EXPORT_BUTTON_SELECTORS[0]
            self.logger.info(f"Waiting for Export button for {threat_actor.name}...")

            if not self.playwright_helper.wait_for_selector(export_selector, timeout=30, state="visible"):
                self.logger.error(f"Export button not found for {threat_actor.name}")
                return None

            # Click export button
            self.logger.info(f"Clicking Export button for {threat_actor.name}...")
            if not self.playwright_helper.click_by_selector(export_selector, use_js=True):
                self.logger.error(f"Failed to click export button for {threat_actor.name}")
                return None

            time.sleep(2)  # Wait for dropdown

            # Click CSV button
            self.logger.info(f"Waiting for CSV button for {threat_actor.name}...")
            if not self.playwright_helper.wait_for_selector(selectors.CSV_BUTTON, timeout=10, state="visible"):
                self.logger.error(f"CSV button not found for {threat_actor.name}")
                return None

            if not self.playwright_helper.click_by_selector(selectors.CSV_BUTTON, use_js=True):
                self.logger.error(f"Failed to click CSV button for {threat_actor.name}")
                return None

            self.logger.info(f"CSV export initiated for {threat_actor.name}")

            # Wait for download ready
            if not self._wait_for_download_ready(threat_actor.name):
                self.logger.error(f"Download not ready for {threat_actor.name}")
                return None

            # Wait for download button and download file using Playwright's native download handling
            if not self.playwright_helper.wait_for_selector(selectors.DOWNLOAD_BUTTON, timeout=10, state="visible"):
                self.logger.error(f"Download button not found for {threat_actor.name}")
                return None

            # Use Playwright's download handler with normalized filename
            # Create a clean filename based on actor name
            safe_actor_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in threat_actor.name)
            safe_actor_name = safe_actor_name.replace(' ', '_')
            custom_filename = f"{safe_actor_name}_indicators"

            downloaded_file = self.playwright_helper.wait_for_download(
                action_func=lambda: self.playwright_helper.click_by_selector(selectors.DOWNLOAD_BUTTON, use_js=True),
                timeout=self.config.download_timeout,
                custom_filename=custom_filename
            )

            if not downloaded_file:
                self.logger.error(f"Download timeout for {threat_actor.name}")
                return None

            self.logger.info(f"Download started for {threat_actor.name}")

            # Clean up server file
            self._cleanup_server_file(threat_actor.name)

            self.logger.info(f"Download completed for {threat_actor.name}: {downloaded_file}")
            return downloaded_file

        except Exception as e:
            self.logger.error(f"An unexpected error occurred while downloading indicators for {threat_actor.name}: {e}")
            return None

    def _wait_for_download_ready(self, actor_name: str, timeout: int = 90) -> bool:
        """Wait for download to be prepared and ready.

        Args:
            actor_name: Actor name for logging
            timeout: Timeout in seconds

        Returns:
            True if download ready, False if timeout
        """
        self.logger.info(f"Waiting for download to be ready for {actor_name}...")
        return self.playwright_helper.wait_for_selector(
            selectors.DOWNLOAD_BUTTON,
            timeout=timeout,
            state="visible"
        )

    def _cleanup_server_file(self, actor_name: str):
        """Clean up the file on the server after download.

        Args:
            actor_name: Actor name for logging
        """
        try:
            if self.playwright_helper.is_element_present(selectors.DELETE_BUTTON):
                self.playwright_helper.click_by_selector(selectors.DELETE_BUTTON)
                self.logger.info(f"Server file deleted for {actor_name}")
            else:
                self.logger.debug(f"Delete button not found for {actor_name}")
        except Exception as e:
            self.logger.warning(f"Could not delete server file for {actor_name}: {e}")

    def _scrape_report_content(self, report_slug: str, output_dir: Optional[str] = None) -> Optional[str]:
        """Save HTML content from a CrowdStrike report page.

        Args:
            report_slug: Report slug identifier
            output_dir: Optional directory to save HTML files (defaults to config download path)

        Returns:
            Path to saved HTML file, or None if failed
        """
        try:
            # Construct report URL
            url = selectors.get_report_url(report_slug)
            self.logger.info(f"Processing report: {report_slug}")
            self.logger.debug(f"URL: {url}")

            # Navigate to report page
            if not self.playwright_helper.navigate_to(url, wait_time=5):
                self.logger.error(f"Failed to navigate to report page for {report_slug}")
                return None

            # Wait for main report content to load
            self.logger.info(f"Waiting for report content to load for {report_slug}...")
            if not self.playwright_helper.wait_for_selector(selectors.REPORT_MAIN_CONTENT, timeout=15, state="visible"):
                self.logger.error(f"Report content not found for {report_slug}")
                return None

            # Check if PDF button exists
            has_pdf = False
            try:
                has_pdf = self.playwright_helper.wait_for_selector(selectors.PDF_BUTTON, timeout=2, state="visible")
            except:
                pass

            pdf_path = None
            if has_pdf:
                self.logger.info(f"PDF button found for {report_slug}, attempting download...")
                # PDF opens in new tab - we need to handle this differently
                pdf_path = self._download_pdf_from_new_tab(report_slug, output_dir)

            # If PDF download succeeded, convert to text
            if pdf_path and Path(pdf_path).exists():
                self.logger.info(f"PDF downloaded, converting to text: {pdf_path}")
                txt_path = self._convert_pdf_to_txt(pdf_path, report_slug, url)
                if txt_path:
                    return txt_path
                # If conversion fails, fall back to web scraping below
                self.logger.warning(f"PDF conversion failed, falling back to web content")

            # No PDF or PDF conversion failed - scrape web content
            self.logger.info(f"Extracting text from web page for {report_slug}...")

            # Get the report content as text
            report_text = self.playwright_helper.page.locator(selectors.REPORT_MAIN_CONTENT).inner_text()

            # Get report title
            report_title = ""
            try:
                title_element = self.playwright_helper.page.locator(selectors.REPORT_TITLE)
                if title_element.count() > 0:
                    report_title = title_element.inner_text()
            except:
                pass

            # Get report metadata
            report_type = ""
            report_date = ""
            report_serial = ""
            try:
                type_elem = self.playwright_helper.page.locator("span[data-test-selector='report-details-type']")
                if type_elem.count() > 0:
                    report_type = type_elem.inner_text()

                date_elem = self.playwright_helper.page.locator("time[data-test-selector='report-details-date']")
                if date_elem.count() > 0:
                    report_date = date_elem.inner_text()

                serial_elem = self.playwright_helper.page.locator("span[data-test-selector='report-details-serial-number']")
                if serial_elem.count() > 0:
                    report_serial = serial_elem.inner_text()
            except:
                pass

            # Determine output directory
            if not output_dir:
                output_dir = self.config.download_path

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Save as text file
            txt_filename = output_path / f"{report_slug}.txt"

            # Create text document
            text_content = f"""{report_title if report_title else report_slug}

Report ID: {report_serial if report_serial else report_slug}
Type: {report_type}
Date: {report_date}
Source: CrowdStrike Intelligence
URL: {url}

{'='*80}

{report_text}
"""

            with open(txt_filename, 'w', encoding='utf-8') as f:
                f.write(text_content)

            self.logger.info(f"Text content saved for report {report_slug}: {txt_filename}")
            return str(txt_filename)

        except Exception as e:
            self.logger.error(f"Failed to save report content for {report_slug}: {e}")
            return None

    def _download_pdf_from_new_tab(self, report_slug: str, output_dir: Optional[str] = None) -> Optional[str]:
        """Download PDF that opens in a new tab.

        Args:
            report_slug: Report slug identifier
            output_dir: Optional directory to save PDFs

        Returns:
            Path to downloaded PDF, or None if failed
        """
        try:
            # Determine output directory
            if not output_dir:
                output_dir = self.config.download_path

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Listen for new page (tab) opening
            context = self.playwright_helper.page.context
            pdf_filename = output_path / f"{report_slug}.pdf"

            # Wait for new page to open when clicking PDF button
            with context.expect_page() as new_page_info:
                self.playwright_helper.click_by_selector(selectors.PDF_BUTTON, use_js=True)

            new_page = new_page_info.value

            # Wait for navigation to complete
            try:
                new_page.wait_for_load_state("networkidle", timeout=10000)
            except:
                pass

            # Get the actual PDF URL from the embed/iframe
            pdf_url = None
            try:
                # Look for the PDF URL in the embed element
                embed_src = new_page.evaluate("""
                    () => {
                        const embed = document.querySelector('embed[type="application/pdf"]');
                        return embed ? embed.getAttribute('src') : null;
                    }
                """)

                if embed_src and embed_src != 'about:blank':
                    pdf_url = embed_src
                    self.logger.info(f"Found PDF URL from embed: {pdf_url}")
                else:
                    # Try to find PDF URL from page URL or other sources
                    page_url = new_page.url
                    # Check if the page URL itself is a PDF
                    if '.pdf' in page_url or 'application/pdf' in new_page.content():
                        pdf_url = page_url
                        self.logger.info(f"Using page URL as PDF: {pdf_url}")
            except Exception as e:
                self.logger.warning(f"Could not extract PDF URL: {e}")

            if not pdf_url:
                self.logger.error(f"Could not find PDF URL in new tab for {report_slug}")
                new_page.close()
                return None

            # Download the actual PDF content using a new context or API request
            # Use the browser context to fetch the PDF
            try:
                # Make a request to get the PDF content
                response = new_page.request.get(pdf_url)
                if response and response.ok:
                    pdf_content = response.body()

                    # Verify it's actually a PDF (check magic bytes)
                    if pdf_content[:4] == b'%PDF':
                        with open(pdf_filename, 'wb') as f:
                            f.write(pdf_content)

                        new_page.close()
                        self.logger.info(f"PDF saved: {pdf_filename}")
                        return str(pdf_filename)
                    else:
                        self.logger.error(f"Downloaded content is not a PDF for {report_slug}")
            except Exception as e:
                self.logger.error(f"Failed to fetch PDF content: {e}")

            new_page.close()
            return None

        except Exception as e:
            self.logger.error(f"Failed to download PDF from new tab for {report_slug}: {e}")
            return None

    def _convert_pdf_to_txt(self, pdf_path: str, report_slug: str, report_url: str) -> Optional[str]:
        """Convert PDF to text file.

        Args:
            pdf_path: Path to PDF file
            report_slug: Report slug for output filename
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
            full_text = f"""CrowdStrike Intelligence Report
Report ID: {report_slug}
Source: CrowdStrike Intelligence
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
            self.logger.error(f"Failed to convert PDF to text for {report_slug}: {e}")
            # Delete corrupted PDF if conversion completely fails
            try:
                if Path(pdf_path).exists():
                    Path(pdf_path).unlink()
                    self.logger.info(f"Deleted corrupted PDF: {pdf_path}")
            except:
                pass
            return None

    def scrape_pdfs_from_csv(self, csv_file_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Process CSV file and download PDFs for all reports.

        Args:
            csv_file_path: Path to CSV file containing IOCs with Reports column
            output_dir: Optional directory to save PDFs (defaults to config download path)

        Returns:
            Dictionary with download statistics
        """
        try:
            csv_path = Path(csv_file_path)
            if not csv_path.exists():
                self.logger.error(f"CSV file not found: {csv_file_path}")
                return {"error": "File not found", "downloaded": 0, "failed": 0, "skipped": 0}

            # Ensure we're authenticated
            if not self.is_authenticated and not self.authenticate():
                self.logger.error("Authentication required but failed")
                return {"error": "Authentication failed", "downloaded": 0, "failed": 0, "skipped": 0}

            # Collect unique report slugs from CSV (only CrowdStrike reports)
            report_slugs: Set[str] = set()
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Only process CrowdStrike rows
                    source = row.get('Source', '').strip().lower()
                    if source != 'crowdstrike':
                        continue

                    reports_str = row.get('Reports', '').strip()
                    if reports_str:
                        # Split by comma and clean up
                        reports = [r.strip() for r in reports_str.split(',') if r.strip()]
                        report_slugs.update(reports)

            self.logger.info(f"Found {len(report_slugs)} unique CrowdStrike reports in CSV")

            # Download reports for each report slug
            downloaded = 0
            failed = 0
            skipped = 0
            downloaded_files = []

            for report_slug in sorted(report_slugs):
                self.logger.info(f"Processing report {downloaded + failed + skipped + 1}/{len(report_slugs)}: {report_slug}")

                result = self._scrape_report_content(report_slug, output_dir)
                if result:
                    downloaded += 1
                    downloaded_files.append(result)
                else:
                    failed += 1

                # Small delay between downloads
                time.sleep(2)

            stats = {
                "total_reports": len(report_slugs),
                "downloaded": downloaded,
                "failed": failed,
                "skipped": skipped,
                "files": downloaded_files
            }

            self.logger.info(f"PDF download complete: {downloaded} downloaded, {failed} failed, {skipped} skipped")
            return stats

        except Exception as e:
            self.logger.error(f"Error processing CSV for PDF downloads: {e}")
            return {"error": str(e), "downloaded": 0, "failed": 0, "skipped": 0}

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
            if not self.playwright_helper or not self.playwright_helper.page:
                return False

            current_url = self.playwright_helper.get_current_url()
            return "crowdstrike.com" in current_url.lower() or current_url == "about:blank"
        except Exception:
            return False
