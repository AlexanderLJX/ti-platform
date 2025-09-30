"""CLI main entry point for Threat Intelligence Platform."""

import click
import logging
from rich.console import Console
from .commands import (
    scrape, combine, validate_config, clear_profile,
    process_iocs, enrich_batch, analyze_threats, 
    export_data, list_plugins, plugin_status, split_indicators
)
from ..core.startup import initialize_platform, cleanup_platform

console = Console()
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version="0.2.0", prog_name="ti-platform")
@click.pass_context
def cli(ctx):
    """Threat Intelligence Platform - Advanced multi-source intelligence collection.
    
    A comprehensive platform for collecting, processing, and analyzing threat intelligence
    from multiple sources including Mandiant, CrowdStrike, and 7 additional platforms.
    
    Features:
    - Multi-source threat intelligence scraping
    - IOC enrichment with geolocation, ASN, and reputation data
    - Batch processing for thousands of indicators
    - Export to STIX, MISP, CSV, and JSON formats
    - Plugin architecture for extensibility
    
    Examples:
        ti-platform scrape --source all
        ti-platform process-iocs --file indicators.csv --enrich
        ti-platform export --format stix --input combined.csv
        ti-platform plugins list
    """
    # Initialize platform on first command
    if ctx.invoked_subcommand is not None:
        try:
            if not initialize_platform():
                console.print("[red]Warning: Platform initialization failed. Some features may not work correctly.")
        except Exception as e:
            logger.warning(f"Platform initialization error: {e}")
            console.print(f"[yellow]Warning: {e}")
    
    # Ensure cleanup on exit
    ctx.call_on_close(cleanup_platform)


# Register core commands
cli.add_command(scrape)
cli.add_command(combine)
cli.add_command(validate_config, name="validate-config")
cli.add_command(clear_profile, name="clear-profile")

# Register new enhanced commands
cli.add_command(process_iocs, name="process-iocs")
cli.add_command(enrich_batch, name="enrich-batch")
cli.add_command(analyze_threats, name="analyze-threats")
cli.add_command(export_data, name="export")
cli.add_command(list_plugins, name="plugins")
cli.add_command(plugin_status, name="plugin-status")
cli.add_command(split_indicators, name="split-indicators")


if __name__ == "__main__":
    cli()