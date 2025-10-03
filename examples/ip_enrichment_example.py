"""
IP Enrichment Example Script

This script demonstrates how to use the comprehensive IP enrichment framework
programmatically (without using the CLI).

Make sure to:
1. Install dependencies: uv pip install -e .
2. Configure API keys in .env file
3. Download MaxMind GeoLite2 database (optional but recommended)
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.config import ConfigManager
from src.plugins.enrichers.comprehensive_enricher import ComprehensiveIPEnricher
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


async def enrich_single_ip(enricher: ComprehensiveIPEnricher, ip: str):
    """Enrich a single IP and display results."""
    console.print(f"\n[bold cyan]Enriching IP: {ip}[/bold cyan]")

    # Enrich the IP
    profile = await enricher.enrich_ip(ip)

    # Display results
    console.print(f"\n[bold]Results for {ip}:[/bold]")
    console.print(f"  Risk Score: {profile.get_risk_score()}/100")
    console.print(f"  Classification: {profile.get_classification()}")
    console.print(f"  Is Threat: {profile.is_threat()}")
    console.print(f"  Is Anonymous: {profile.is_anonymous()}")

    if profile.geolocation:
        console.print(f"  Location: {profile.geolocation.city}, {profile.geolocation.country}")

    if profile.network:
        console.print(f"  ASN: AS{profile.network.asn} - {profile.network.asn_org}")

    if profile.cloud and profile.cloud.is_cloud:
        console.print(f"  Cloud: {profile.cloud.cloud_provider} ({profile.cloud.cloud_region})")

    if profile.scanner and profile.scanner.is_scanner:
        console.print(f"  Scanner: {profile.scanner.scanner_name} ({profile.scanner.scanner_type})")

    if profile.threat and profile.threat.is_malicious:
        console.print(f"  [red]⚠ Malicious - Threat Level: {profile.threat.threat_level}[/red]")

    console.print(f"  Sources: {', '.join(profile.enrichment_sources)}")
    console.print(f"  Duration: {profile.enrichment_duration_ms:.2f}ms")

    return profile


async def enrich_batch_example(enricher: ComprehensiveIPEnricher):
    """Example of batch enrichment."""
    console.print("\n[bold cyan]Batch Enrichment Example[/bold cyan]")

    # List of IPs to enrich
    ips = [
        "8.8.8.8",  # Google DNS
        "1.1.1.1",  # Cloudflare DNS
        "185.220.101.1",  # Tor exit node
        "54.239.28.85",  # AWS EC2
    ]

    console.print(f"\nEnriching {len(ips)} IPs in parallel...")

    # Enrich batch
    profiles = await enricher.enrich_batch(ips, parallel=4)

    # Display summary table
    table = Table(title="Enrichment Results", box=box.ROUNDED)
    table.add_column("IP Address", style="cyan")
    table.add_column("Risk", style="yellow")
    table.add_column("Country", style="green")
    table.add_column("ASN", style="blue")
    table.add_column("Cloud", style="magenta")
    table.add_column("Threat", style="red")

    for profile in profiles:
        risk_color = "green"
        risk = profile.get_risk_score()
        if risk >= 75:
            risk_color = "red"
        elif risk >= 50:
            risk_color = "yellow"

        table.add_row(
            profile.ip_address,
            f"[{risk_color}]{risk}/100[/{risk_color}]",
            profile.geolocation.country if profile.geolocation else "N/A",
            f"AS{profile.network.asn}" if profile.network else "N/A",
            profile.cloud.cloud_provider if profile.cloud and profile.cloud.is_cloud else "No",
            "⚠ YES" if profile.is_threat() else "✓ No"
        )

    console.print(table)

    return profiles


async def cache_example(enricher: ComprehensiveIPEnricher):
    """Demonstrate caching functionality."""
    console.print("\n[bold cyan]Caching Example[/bold cyan]")

    ip = "8.8.8.8"

    # First enrichment (cache miss)
    console.print(f"\nFirst enrichment of {ip} (cache miss)...")
    profile1 = await enricher.enrich_ip(ip, use_cache=True)
    console.print(f"  Duration: {profile1.enrichment_duration_ms:.2f}ms")

    # Second enrichment (cache hit)
    console.print(f"\nSecond enrichment of {ip} (cache hit)...")
    profile2 = await enricher.enrich_ip(ip, use_cache=True)
    console.print(f"  Duration: {profile2.enrichment_duration_ms:.2f}ms")
    console.print(f"  Cache hit: {profile2.cache_hit}")

    # Get cache stats
    stats = await enricher.get_cache_stats()
    console.print(f"\nCache stats:")
    console.print(f"  Total entries: {stats.get('total_entries', 0)}")
    console.print(f"  Database size: {stats.get('db_size_mb', 0):.2f} MB")


async def module_selection_example(enricher: ComprehensiveIPEnricher):
    """Demonstrate selective module enrichment."""
    console.print("\n[bold cyan]Selective Module Enrichment Example[/bold cyan]")

    ip = "1.1.1.1"

    # Enrich with only specific modules
    console.print(f"\nEnriching {ip} with only geolocation and network modules...")
    profile = await enricher.enrich_ip(ip, modules=["geolocation", "network"])

    console.print(f"  Modules used: {', '.join(profile.enrichment_sources)}")
    console.print(f"  Has geolocation: {profile.geolocation is not None}")
    console.print(f"  Has network: {profile.network is not None}")
    console.print(f"  Has threat data: {profile.threat is not None}")


async def main():
    """Main example function."""
    console.print("[bold green]IP Enrichment Framework Example[/bold green]")
    console.print("=" * 60)

    try:
        # Load configuration
        console.print("\n[cyan]Loading configuration...[/cyan]")
        config_manager = ConfigManager()
        app_config = config_manager.get_config()

        # Initialize enricher
        console.print("[cyan]Initializing enrichment framework...[/cyan]")
        enricher = ComprehensiveIPEnricher(app_config.enrichment)
        await enricher.initialize()

        console.print("[green]✓ Initialization complete[/green]")

        # Run examples
        console.print("\n" + "=" * 60)

        # Example 1: Single IP enrichment
        await enrich_single_ip(enricher, "8.8.8.8")

        # Example 2: Batch enrichment
        await enrich_batch_example(enricher)

        # Example 3: Caching
        await cache_example(enricher)

        # Example 4: Module selection
        await module_selection_example(enricher)

        # Cleanup
        console.print("\n[cyan]Cleaning up...[/cyan]")
        await enricher.cleanup()

        console.print("\n[bold green]✓ All examples completed successfully![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
