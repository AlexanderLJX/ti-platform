from src.core.config import ConfigManager
from src.scrapers.mandiant.scraper import MandiantScraper

config_manager = ConfigManager()
scraper = MandiantScraper(config_manager)

print("1. Setup")
scraper.setup()

print("2. Auth")
scraper.authenticate()

print("3. Navigate to actor URL (like IOC scraper does)")
url1 = "https://advantage.mandiant.com/actors/apt1"
print(f"Navigating to: {url1}")
result1 = scraper.playwright_helper.navigate_to(url1, wait_time=5)
print(f"Result: {result1}, URL: {scraper.playwright_helper.get_current_url()}")

print("\n4. Navigate to report URL (like PDF scraper does)")  
url2 = "https://advantage.mandiant.com/reports/19-00005644"
print(f"Navigating to: {url2}")
result2 = scraper.playwright_helper.navigate_to(url2, wait_time=5)
print(f"Result: {result2}, URL: {scraper.playwright_helper.get_current_url()}")

print("\nDone!")
scraper.cleanup()
