"""CLI commands for IP enrichment."""

import asyncio
import json
import csv
from pathlib import Path
from typing import List, Optional
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import box

from ..core.config import ConfigManager
from ..plugins.enrichers.comprehensive_enricher import ComprehensiveIPEnricher
from ..plugins.enrichers.models import EnrichedIPProfile

console = Console()


@click.command()
@click.option("--ip", "-i", required=True, help="IP address to enrich")
@click.option("--modules", "-m", help="Comma-separated list of modules to use (default: all enabled)")
@click.option("--output", "-o", type=click.Path(), help="Output file (JSON)")
@click.option("--no-cache", is_flag=True, help="Disable caching")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to configuration file")
def enrich_ip(ip: str, modules: Optional[str], output: Optional[str], no_cache: bool, config: Optional[str]):
    """Enrich a single IP address with comprehensive intelligence.

    Examples:
        ti-platform enrich-ip --ip 8.8.8.8
        ti-platform enrich-ip --ip 1.2.3.4 --modules geolocation,threat
        ti-platform enrich-ip --ip 1.2.3.4 --output results.json
    """
    asyncio.run(_enrich_ip_async(ip, modules, output, no_cache, config))


async def _enrich_ip_async(ip: str, modules: Optional[str], output: Optional[str], no_cache: bool, config: Optional[str]):
    """Async implementation of enrich_ip."""
    try:
        # Load configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        enrichment_config = app_config.enrichment

        # Initialize enricher
        console.print(f"\n[cyan]Initializing IP enrichment framework...[/cyan]")
        enricher = ComprehensiveIPEnricher(enrichment_config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Initializing modules...", total=None)
            await enricher.initialize()
            progress.update(task, description="✓ Initialized")

        # Parse modules
        module_list = None
        if modules:
            module_list = [m.strip() for m in modules.split(",")]

        # Enrich IP
        console.print(f"\n[cyan]Enriching IP: {ip}[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enriching...", total=None)
            profile = await enricher.enrich_ip(ip, modules=module_list, use_cache=not no_cache)
            progress.update(task, description="✓ Enrichment complete")

        # Display results
        _display_enrichment_results(profile)

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, 'w') as f:
                json.dump(profile.dict(), f, indent=2, default=str)

            console.print(f"\n[green]✓ Results saved to {output_path}[/green]")

        # Cleanup
        await enricher.cleanup()

    except Exception as e:
        console.print(f"[red]Error enriching IP: {e}[/red]")
        raise click.Abort()


@click.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="File containing IP addresses (one per line)")
@click.option("--modules", "-m", help="Comma-separated list of modules to use")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output file (JSON or CSV)")
@click.option("--parallel", "-p", default=10, help="Number of parallel enrichments (default: 10)")
@click.option("--no-cache", is_flag=True, help="Disable caching")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to configuration file")
def enrich_ips(file: str, modules: Optional[str], output: str, parallel: int, no_cache: bool, config: Optional[str]):
    """Enrich multiple IP addresses from a file.

    Examples:
        ti-platform enrich-ips --file ips.txt --output enriched.json
        ti-platform enrich-ips --file ips.txt --output enriched.csv --parallel 20
        ti-platform enrich-ips --file ips.txt --output results.json --modules geolocation,threat
    """
    asyncio.run(_enrich_ips_async(file, modules, output, parallel, no_cache, config))


async def _enrich_ips_async(file: str, modules: Optional[str], output: str, parallel: int, no_cache: bool, config: Optional[str]):
    """Async implementation of enrich_ips."""
    try:
        # Load IPs from file
        ips = []
        with open(file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    ips.append(ip)

        if not ips:
            console.print("[yellow]No IP addresses found in file[/yellow]")
            return

        console.print(f"\n[cyan]Found {len(ips)} IP addresses to enrich[/cyan]")

        # Load configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        enrichment_config = app_config.enrichment

        # Initialize enricher
        console.print(f"[cyan]Initializing IP enrichment framework...[/cyan]")
        enricher = ComprehensiveIPEnricher(enrichment_config)
        await enricher.initialize()

        # Parse modules
        module_list = None
        if modules:
            module_list = [m.strip() for m in modules.split(",")]

        # Enrich IPs with progress bar
        console.print(f"\n[cyan]Enriching {len(ips)} IPs with {parallel} parallel workers...[/cyan]")

        profiles = []
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            console=console,
        ) as progress:
            task = progress.add_task("Enriching IPs...", total=len(ips))

            # Process in batches
            batch_size = parallel * 2
            for i in range(0, len(ips), batch_size):
                batch = ips[i:i + batch_size]
                batch_profiles = await enricher.enrich_batch(
                    batch,
                    modules=module_list,
                    parallel=parallel,
                    use_cache=not no_cache
                )
                profiles.extend(batch_profiles)
                progress.update(task, advance=len(batch))

        # Display summary
        _display_batch_summary(profiles)

        # Save results
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_path.suffix == '.json':
            with open(output_path, 'w') as f:
                json.dump([p.dict() for p in profiles], f, indent=2, default=str)
        elif output_path.suffix == '.csv':
            _save_profiles_to_csv(profiles, output_path)
        else:
            console.print("[yellow]Unknown output format, saving as JSON[/yellow]")
            with open(output_path, 'w') as f:
                json.dump([p.dict() for p in profiles], f, indent=2, default=str)

        console.print(f"\n[green]✓ Results saved to {output_path}[/green]")

        # Cleanup
        await enricher.cleanup()

    except Exception as e:
        console.print(f"[red]Error enriching IPs: {e}[/red]")
        raise click.Abort()


@click.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to configuration file")
def enrichment_status(config: Optional[str]):
    """Show status of enrichment modules and cache.

    Examples:
        ti-platform enrichment-status
    """
    asyncio.run(_enrichment_status_async(config))


async def _enrichment_status_async(config: Optional[str]):
    """Async implementation of enrichment_status."""
    try:
        # Load configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        enrichment_config = app_config.enrichment

        # Initialize enricher
        enricher = ComprehensiveIPEnricher(enrichment_config)
        await enricher.initialize()

        # Get module statuses
        console.print("\n[bold cyan]Enrichment Module Status[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Module", style="cyan")
        table.add_column("Enabled", style="green")
        table.add_column("Initialized", style="yellow")
        table.add_column("Health", style="blue")

        for name, module in enricher.modules.items():
            enabled = "✓" if module.is_enabled() else "✗"
            initialized = "✓" if module.is_initialized() else "✗"
            health = "✓" if await module.health_check() else "✗"
            table.add_row(name, enabled, initialized, health)

        console.print(table)

        # Get cache stats
        cache_stats = await enricher.get_cache_stats()

        console.print("\n[bold cyan]Cache Statistics[/bold cyan]\n")

        cache_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        cache_table.add_column("Metric", style="cyan")
        cache_table.add_column("Value", style="yellow")

        if cache_stats.get("enabled"):
            cache_table.add_row("Status", "Enabled ✓")
            cache_table.add_row("Total Entries", str(cache_stats.get("total_entries", 0)))
            cache_table.add_row("Database Size", f"{cache_stats.get('db_size_mb', 0):.2f} MB")
            cache_table.add_row("Database Path", cache_stats.get("db_path", "N/A"))

            # Entries by module
            by_module = cache_stats.get("by_module", {})
            for module, count in by_module.items():
                cache_table.add_row(f"  {module}", str(count))
        else:
            cache_table.add_row("Status", "Disabled ✗")

        console.print(cache_table)

        # Get rate limiter status
        console.print("\n[bold cyan]Rate Limiter Status[/bold cyan]\n")

        rl_table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        rl_table.add_column("Service", style="cyan")
        rl_table.add_column("Limit", style="yellow")
        rl_table.add_column("Period", style="blue")
        rl_table.add_column("Used", style="green")
        rl_table.add_column("Available", style="magenta")

        services = ["virustotal", "shodan", "greynoise", "bgpview", "abuseipdb", "alienvault_otx"]
        for service in services:
            status = enricher.rate_limiter.get_status(service)
            if status.get("configured"):
                rl_table.add_row(
                    service,
                    str(status.get("limit", "N/A")),
                    f"{status.get('period', 0)}s",
                    str(status.get("used", 0)),
                    str(status.get("available", 0)),
                )

        console.print(rl_table)

        # Cleanup
        await enricher.cleanup()

    except Exception as e:
        console.print(f"[red]Error getting enrichment status: {e}[/red]")
        raise click.Abort()


def _display_enrichment_results(profile: EnrichedIPProfile):
    """Display enrichment results in a formatted table."""
    console.print(f"\n[bold cyan]Enrichment Results for {profile.ip_address}[/bold cyan]\n")

    # Summary panel
    risk_score = profile.get_risk_score()
    classification = profile.get_classification()

    # Color based on risk
    risk_color = "green"
    if risk_score >= 75:
        risk_color = "red"
    elif risk_score >= 50:
        risk_color = "yellow"
    elif risk_score >= 25:
        risk_color = "blue"

    summary = f"""
[bold]Risk Score:[/bold] [{risk_color}]{risk_score}/100[/{risk_color}]
[bold]Classification:[/bold] [{risk_color}]{classification.upper()}[/{risk_color}]
[bold]Is Threat:[/bold] {"⚠️  YES" if profile.is_threat() else "✓ NO"}
[bold]Is Anonymous:[/bold] {"🔒 YES" if profile.is_anonymous() else "✗ NO"}
[bold]Enrichment Duration:[/bold] {profile.enrichment_duration_ms:.2f}ms
[bold]Sources Used:[/bold] {', '.join(profile.enrichment_sources)}
"""

    console.print(Panel(summary, title="Summary", border_style=risk_color))

    # Geolocation
    if profile.geolocation:
        geo = profile.geolocation
        geo_info = f"""
[bold]Country:[/bold] {geo.country} ({geo.country_code})
[bold]City:[/bold] {geo.city or 'N/A'}
[bold]Region:[/bold] {geo.region or 'N/A'}
[bold]Coordinates:[/bold] {geo.latitude}, {geo.longitude}
[bold]Timezone:[/bold] {geo.timezone or 'N/A'}
"""
        console.print(Panel(geo_info, title="🌍 Geolocation", border_style="cyan"))

    # Network
    if profile.network:
        net = profile.network
        net_info = f"""
[bold]ASN:[/bold] AS{net.asn}
[bold]Organization:[/bold] {net.asn_org or net.asn_name or 'N/A'}
[bold]ISP:[/bold] {net.isp or 'N/A'}
[bold]CIDR:[/bold] {net.cidr or 'N/A'}
"""
        console.print(Panel(net_info, title="🌐 Network", border_style="blue"))

    # Cloud
    if profile.cloud and profile.cloud.is_cloud:
        cloud = profile.cloud
        cloud_info = f"""
[bold]Provider:[/bold] {cloud.cloud_provider.upper()}
[bold]Region:[/bold] {cloud.cloud_region or 'N/A'}
[bold]Service:[/bold] {cloud.cloud_service or 'N/A'}
"""
        console.print(Panel(cloud_info, title="☁️  Cloud Infrastructure", border_style="magenta"))

    # Scanner
    if profile.scanner and profile.scanner.is_scanner:
        scanner = profile.scanner
        scanner_type_emoji = "🔍" if scanner.scanner_type == "benign" else "⚠️"
        scanner_info = f"""
[bold]Scanner:[/bold] {scanner_type_emoji} {scanner.scanner_name or 'Unknown'}
[bold]Type:[/bold] {scanner.scanner_type or 'N/A'}
[bold]Tags:[/bold] {', '.join(scanner.scanner_tags) if scanner.scanner_tags else 'N/A'}
"""
        console.print(Panel(scanner_info, title="🔍 Scanner Detection", border_style="yellow"))

    # Threat
    if profile.threat:
        threat = profile.threat
        threat_emoji = "🚨" if threat.is_malicious else "✓"
        threat_info = f"""
[bold]Malicious:[/bold] {threat_emoji} {"YES" if threat.is_malicious else "NO"}
[bold]Reputation Score:[/bold] {threat.reputation_score or 'N/A'}/100
[bold]Threat Level:[/bold] {threat.threat_level or 'N/A'}
[bold]Abuse Reports:[/bold] {threat.abuse_report_count}
[bold]Attack Types:[/bold] {', '.join(threat.attack_types[:5]) if threat.attack_types else 'N/A'}
"""
        threat_color = "red" if threat.is_malicious else "green"
        console.print(Panel(threat_info, title="🛡️  Threat Intelligence", border_style=threat_color))


def _display_batch_summary(profiles: List[EnrichedIPProfile]):
    """Display summary of batch enrichment."""
    console.print(f"\n[bold cyan]Enrichment Summary[/bold cyan]\n")

    total = len(profiles)
    malicious = sum(1 for p in profiles if p.is_threat())
    anonymous = sum(1 for p in profiles if p.is_anonymous())
    scanners = sum(1 for p in profiles if p.scanner and p.scanner.is_scanner)
    cloud = sum(1 for p in profiles if p.cloud and p.cloud.is_cloud)

    # Risk distribution
    critical = sum(1 for p in profiles if p.get_classification() == "critical")
    high = sum(1 for p in profiles if p.get_classification() == "high")
    medium = sum(1 for p in profiles if p.get_classification() == "medium")
    low = sum(1 for p in profiles if p.get_classification() == "low")

    summary = f"""
[bold]Total IPs:[/bold] {total}
[bold]Malicious:[/bold] [red]{malicious}[/red] ({malicious/total*100:.1f}%)
[bold]Anonymous:[/bold] {anonymous} ({anonymous/total*100:.1f}%)
[bold]Scanners:[/bold] {scanners} ({scanners/total*100:.1f}%)
[bold]Cloud Hosted:[/bold] {cloud} ({cloud/total*100:.1f}%)

[bold]Risk Distribution:[/bold]
  Critical: [red]{critical}[/red]
  High: [yellow]{high}[/yellow]
  Medium: [blue]{medium}[/blue]
  Low: [green]{low}[/green]
"""

    console.print(Panel(summary, title="Summary", border_style="cyan"))


def _save_profiles_to_csv(profiles: List[EnrichedIPProfile], output_path: Path):
    """Save enrichment profiles to CSV."""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
            "ip_address", "risk_score", "classification", "is_threat", "is_anonymous",
            "country", "city", "asn", "asn_org", "cloud_provider", "cloud_region",
            "is_scanner", "scanner_name", "reputation_score", "threat_level",
            "abuse_reports", "sources", "timestamp"
        ])

        # Data
        for p in profiles:
            writer.writerow([
                p.ip_address,
                p.get_risk_score(),
                p.get_classification(),
                p.is_threat(),
                p.is_anonymous(),
                p.geolocation.country if p.geolocation else "",
                p.geolocation.city if p.geolocation else "",
                p.network.asn if p.network else "",
                p.network.asn_org if p.network else "",
                p.cloud.cloud_provider if p.cloud else "",
                p.cloud.cloud_region if p.cloud else "",
                p.scanner.is_scanner if p.scanner else False,
                p.scanner.scanner_name if p.scanner else "",
                p.threat.reputation_score if p.threat else "",
                p.threat.threat_level if p.threat else "",
                p.threat.abuse_report_count if p.threat else 0,
                ', '.join(p.enrichment_sources),
                p.timestamp.isoformat(),
            ])
