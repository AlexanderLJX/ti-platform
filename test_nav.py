import sys
from src.core.config import ConfigManager
from src.scrapers.mandiant.scraper import MandiantScraper

config_manager = ConfigManager()
scraper = MandiantScraper(config_manager)

print("Setting up browser...")
if not scraper.setup():
    print("Setup failed!")
    sys.exit(1)

print("Authenticating...")
if not scraper.authenticate():
    print("Auth failed!")
    sys.exit(1)

print("Testing navigation to main page...")
if scraper.playwright_helper.navigate_to("https://advantage.mandiant.com", wait_time=3):
    print("SUCCESS: Main page loaded")
    print(f"Current URL: {scraper.playwright_helper.get_current_url()}")
else:
    print("FAILED: Could not load main page")

print("\nTesting navigation to specific report...")
if scraper.playwright_helper.navigate_to("https://advantage.mandiant.com/reports/19-00005644", wait_time=3):
    print("SUCCESS: Report page loaded")
    print(f"Current URL: {scraper.playwright_helper.get_current_url()}")
else:
    print("FAILED: Could not load report page")

input("Press Enter to close browser...")
scraper.cleanup()
