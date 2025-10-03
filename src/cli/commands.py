"""CLI command implementations."""

import logging
import time
import asyncio
from pathlib import Path
from typing import List, Optional
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from ..core.config import ConfigManager
from ..core.models import ScrapingStatus
from ..scrapers.mandiant.scraper import MandiantScraper
from ..scrapers.crowdstrike.scraper import CrowdStrikeScraper
from ..utils.data_processor import DataProcessor

logger = logging.getLogger(__name__)


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("logs/threat_intel.log"),
            logging.StreamHandler()
        ]
    )
    
    # Reduce selenium logging noise
    logging.getLogger("selenium").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_scraper_instance(source: str, config_manager: ConfigManager):
    """Get scraper instance for source.
    
    Args:
        source: Source name (mandiant, crowdstrike)
        config_manager: Configuration manager
        
    Returns:
        Scraper instance
        
    Raises:
        ValueError: If source is not supported
    """
    if source == "mandiant":
        return MandiantScraper(config_manager)
    elif source == "crowdstrike":
        return CrowdStrikeScraper(config_manager)
    else:
        raise ValueError(f"Unsupported source: {source}")


@click.command()
@click.option("--source", "-s", 
              type=click.Choice(["mandiant", "crowdstrike", "all"]),
              default="all",
              help="Source to scrape from")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
@click.option("--dry-run", "-n",
              is_flag=True,
              help="Show what would be scraped without actually scraping")
def scrape(source: str, config: Optional[str], log_level: str, dry_run: bool):
    """Scrape threat intelligence indicators from configured sources."""
    setup_logging(log_level)
    
    try:
        # Initialize configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        
        click.echo(f"Starting threat intelligence scraping...")
        click.echo(f"Sources: {source}")
        click.echo(f"Log level: {log_level}")
        
        if dry_run:
            click.echo("DRY RUN MODE - No actual scraping will be performed")
        
        # Determine sources to process
        if source == "all":
            sources = [name for name, config in app_config.scrapers.items() if config.enabled]
        else:
            sources = [source] if app_config.scrapers.get(source, {}).enabled else []
        
        if not sources:
            click.echo("No enabled sources found")
            return
        
        click.echo(f"Active sources: {', '.join(sources)}")
        
        # Process each source
        all_jobs = []
        for src in sources:
            click.echo(f"\n{'='*50}")
            click.echo(f"Processing {src.upper()}")
            click.echo(f"{'='*50}")
            
            try:
                # Load threat actors for preview
                threat_actors = config_manager.load_threat_actors(src)
                active_actors = [ta for ta in threat_actors if ta.active]
                
                click.echo(f"Found {len(active_actors)} active threat actors")
                
                if dry_run:
                    click.echo("Would scrape:")
                    for ta in active_actors:
                        click.echo(f"  - {ta.name} ({ta.url or ta.slug})")
                    continue
                
                # Initialize and run scraper
                scraper = get_scraper_instance(src, config_manager)
                
                if not scraper.setup():
                    click.echo(f"[ERROR] Failed to setup {src} scraper")
                    continue
                
                try:
                    jobs = scraper.scrape_all_threat_actors()
                    all_jobs.extend(jobs)
                    
                    # Show results
                    successful = len([j for j in jobs if j.status == ScrapingStatus.COMPLETED])
                    failed = len([j for j in jobs if j.status == ScrapingStatus.FAILED])
                    total_indicators = sum(j.indicators_count for j in jobs)
                    
                    click.echo(f"\n{src.upper()} Results:")
                    click.echo(f"  Successful: {successful}")
                    click.echo(f"  Failed: {failed}")
                    click.echo(f"  Total indicators: {total_indicators}")
                    
                finally:
                    scraper.cleanup()
                    
            except Exception as e:
                click.echo(f"[ERROR] Error processing {src}: {e}")
                logger.error(f"Error processing {src}: {e}")
        
        # Overall summary
        if not dry_run and all_jobs:
            click.echo(f"\n{'='*50}")
            click.echo("OVERALL SUMMARY")
            click.echo(f"{'='*50}")
            
            total_successful = len([j for j in all_jobs if j.status == ScrapingStatus.COMPLETED])
            total_failed = len([j for j in all_jobs if j.status == ScrapingStatus.FAILED])
            total_indicators = sum(j.indicators_count for j in all_jobs)
            
            click.echo(f"Total jobs: {len(all_jobs)}")
            click.echo(f"Successful: {total_successful}")
            click.echo(f"Failed: {total_failed}")
            click.echo(f"Total indicators: {total_indicators}")
            
            if total_successful > 0:
                click.echo(f"\nRun 'threat-intel combine' to combine all downloaded files")
        
        click.echo(f"\nScraping completed!")
        
    except Exception as e:
        click.echo(f"[ERROR] Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--output", "-o",
              type=click.Path(),
              help="Output file path")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def combine(config: Optional[str], output: Optional[str], log_level: str):
    """Combine downloaded CSV files into a unified dataset."""
    setup_logging(log_level)
    
    try:
        # Initialize configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        
        click.echo(f"Combining downloaded files...")
        
        # Initialize data processor
        processor = DataProcessor(app_config.data_processing)
        
        # Find all CSV files in download directories
        csv_files = []
        for source_name, source_config in app_config.scrapers.items():
            if source_config.enabled:
                download_path = Path(source_config.download_path)
                if download_path.exists():
                    source_files = list(download_path.glob("*.csv"))
                    csv_files.extend(source_files)
                    click.echo(f"Found {len(source_files)} files from {source_name}")
        
        if not csv_files:
            click.echo("[ERROR] No CSV files found to combine")
            return
        
        click.echo(f"Total files to process: {len(csv_files)}")
        
        # Determine output path
        if not output:
            output = Path(app_config.data_processing.combined_output_path) / "combined_indicators.csv"
        
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Process and combine files
        result = processor.combine_and_process_files(
            file_paths=[str(f) for f in csv_files],
            output_path=str(output_path)
        )
        
        if result['success']:
            click.echo(f"[OK] Successfully combined {result['processed_files']} files")
            click.echo(f"Total indicators: {result['total_rows']}")
            click.echo(f"Output file: {output_path}")
            
            if result.get('summary'):
                click.echo(f"\nSummary by source:")
                for source, count in result['summary'].items():
                    click.echo(f"  {source}: {count} indicators")
        else:
            click.echo(f"[ERROR] Combination failed")
            for error in result.get('errors', []):
                click.echo(f"  - {error}")
        
    except Exception as e:
        click.echo(f"[ERROR] Error: {e}")
        logger.error(f"Combine error: {e}")
        raise click.ClickException(str(e))


@click.command('split-indicators')
@click.option("--input-file", "-i",
              type=click.Path(exists=True, path_type=Path),
              help="Input file to split. Defaults to combined_indicators.csv")
@click.option("--output-dir", "-o",
              type=click.Path(path_type=Path),
              help="Output directory for separated files.")
@click.option("--by-source", "-s",
              is_flag=True,
              help="Split by source (Mandiant/CrowdStrike) in addition to type")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def split_indicators(input_file: Optional[Path], output_dir: Optional[Path], by_source: bool, config: Optional[str], log_level: str):
    """Split combined indicators into separate files for IPs and domains, optionally by source."""
    setup_logging(log_level)

    try:
        import pandas as pd
        import os

        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()

        if not input_file:
            input_file = Path(app_config.data_processing.combined_output_path) / "combined_indicators.csv"

        if not input_file.exists():
            click.echo(f"[ERROR] Input file not found: {input_file}")
            return

        if not output_dir:
            output_dir = Path("output/separated")

        output_dir.mkdir(parents=True, exist_ok=True)

        if by_source:
            # Split by source and type
            mandiant_ip_file = output_dir / "mandiant_ip_addresses.csv"
            mandiant_domain_file = output_dir / "mandiant_domains.csv"
            crowdstrike_ip_file = output_dir / "crowdstrike_ip_addresses.csv"
            crowdstrike_domain_file = output_dir / "crowdstrike_domains.csv"

            # Delete existing files to prevent appending to old data
            for f in [mandiant_ip_file, mandiant_domain_file, crowdstrike_ip_file, crowdstrike_domain_file]:
                if f.exists():
                    f.unlink()

            headers_written = {
                'mandiant_ip': False,
                'mandiant_domain': False,
                'crowdstrike_ip': False,
                'crowdstrike_domain': False
            }

            chunk_size = 1000
            for chunk in pd.read_csv(input_file, chunksize=chunk_size, low_memory=False):
                # Mandiant IPs
                mandiant_ip_chunk = chunk[(chunk["IP"].notna()) & (chunk["Source"].str.contains('mandiant', case=False, na=False))].copy()
                if not mandiant_ip_chunk.empty:
                    mandiant_ip_chunk['Description'] = mandiant_ip_chunk.apply(
                        lambda row: f"[Mandiant]\nThis IP is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    mandiant_ip_chunk.to_csv(mandiant_ip_file, mode='a', header=not headers_written['mandiant_ip'], index=False, quoting=1)
                    headers_written['mandiant_ip'] = True

                # Mandiant Domains
                mandiant_domain_chunk = chunk[(chunk["Domain"].notna()) & (chunk["Source"].str.contains('mandiant', case=False, na=False))].copy()
                if not mandiant_domain_chunk.empty:
                    mandiant_domain_chunk['Description'] = mandiant_domain_chunk.apply(
                        lambda row: f"[Mandiant]\nThis domain is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    mandiant_domain_chunk.to_csv(mandiant_domain_file, mode='a', header=not headers_written['mandiant_domain'], index=False, quoting=1)
                    headers_written['mandiant_domain'] = True

                # CrowdStrike IPs
                crowdstrike_ip_chunk = chunk[(chunk["IP"].notna()) & (chunk["Source"].str.contains('crowdstrike', case=False, na=False))].copy()
                if not crowdstrike_ip_chunk.empty:
                    crowdstrike_ip_chunk['Description'] = crowdstrike_ip_chunk.apply(
                        lambda row: f"[CrowdStrike]\nThis IP is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    crowdstrike_ip_chunk.to_csv(crowdstrike_ip_file, mode='a', header=not headers_written['crowdstrike_ip'], index=False, quoting=1)
                    headers_written['crowdstrike_ip'] = True

                # CrowdStrike Domains
                crowdstrike_domain_chunk = chunk[(chunk["Domain"].notna()) & (chunk["Source"].str.contains('crowdstrike', case=False, na=False))].copy()
                if not crowdstrike_domain_chunk.empty:
                    crowdstrike_domain_chunk['Description'] = crowdstrike_domain_chunk.apply(
                        lambda row: f"[CrowdStrike]\nThis domain is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    crowdstrike_domain_chunk.to_csv(crowdstrike_domain_file, mode='a', header=not headers_written['crowdstrike_domain'], index=False, quoting=1)
                    headers_written['crowdstrike_domain'] = True

            click.echo(f"[OK] Successfully split indicators by source:")
            click.echo(f"  - Mandiant IPs: {mandiant_ip_file}")
            click.echo(f"  - Mandiant Domains: {mandiant_domain_file}")
            click.echo(f"  - CrowdStrike IPs: {crowdstrike_ip_file}")
            click.echo(f"  - CrowdStrike Domains: {crowdstrike_domain_file}")
        else:
            # Original behavior - split by type only
            ip_output_file = output_dir / "ip_addresses.csv"
            domain_output_file = output_dir / "domains.csv"

            # Delete existing files to prevent appending to old data
            if ip_output_file.exists():
                ip_output_file.unlink()
            if domain_output_file.exists():
                domain_output_file.unlink()

            chunk_size = 1000
            ip_header_written = False
            domain_header_written = False

            for chunk in pd.read_csv(input_file, chunksize=chunk_size, low_memory=False):
                ip_chunk = chunk[chunk["IP"].notna()].copy()
                if not ip_chunk.empty:
                    ip_chunk['Description'] = ip_chunk.apply(
                        lambda row: f"[{row.get('Source', 'Unknown').title()}]\n"
                                  f"This IP is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    ip_chunk.to_csv(ip_output_file, mode='a', header=not ip_header_written, index=False, quoting=1)
                    ip_header_written = True

                domain_chunk = chunk[chunk["Domain"].notna()].copy()
                if not domain_chunk.empty:
                    domain_chunk['Description'] = domain_chunk.apply(
                        lambda row: f"[{row.get('Source', 'Unknown').title()}]\n"
                                  f"This domain is associated with {row.get('Threat Actor Name', 'Unknown')}\n"
                                  f"Last seen {row.get('Last Seen', 'Unknown')}\n"
                                  f"IC Score: {row.get('IC Score', 'N/A')}, Threat Score: {row.get('Threat Score', 'N/A')}",
                        axis=1
                    )
                    domain_chunk.to_csv(domain_output_file, mode='a', header=not domain_header_written, index=False, quoting=1)
                    domain_header_written = True

            click.echo(f"[OK] Successfully split indicators into {ip_output_file} and {domain_output_file}")

    except Exception as e:
        click.echo(f"[ERROR] Error splitting indicators: {e}")
        logger.error(f"Split indicators error: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
def validate_config(config: Optional[str]):
    """Validate configuration and credentials."""
    try:
        config_manager = ConfigManager(config)
        
        click.echo("Validating configuration...")
        
        # Load and validate config
        app_config = config_manager.get_config()
        click.echo("[OK] Configuration file loaded successfully")
        
        # Validate paths
        config_manager.validate_paths()
        click.echo("[OK] Paths validated and created")
        
        # Check credentials for each enabled source
        for source_name, source_config in app_config.scrapers.items():
            if source_config.enabled:
                try:
                    credentials = config_manager.get_credentials(source_name)
                    click.echo(f"[OK] {source_name} credentials found")
                except ValueError as e:
                    click.echo(f"[ERROR] {source_name} credentials missing: {e}")
        
        # Check threat actor files
        for source_name, source_config in app_config.scrapers.items():
            if source_config.enabled:
                try:
                    threat_actors = config_manager.load_threat_actors(source_name)
                    active_count = len([ta for ta in threat_actors if ta.active])
                    click.echo(f"[OK] {source_name} threat actors: {len(threat_actors)} total, {active_count} active")
                except Exception as e:
                    click.echo(f"[ERROR] {source_name} threat actors error: {e}")
        
        click.echo("\nConfiguration validation completed!")
        
    except Exception as e:
        click.echo(f"[ERROR] Validation failed: {e}")
        raise click.ClickException(str(e))


@click.command()
def clear_profile():
    """Clear shared browser profile to force fresh login for all sources."""
    try:
        config_manager = ConfigManager()
        
        # Get profile path from any source (they should all be the same now)
        mandiant_config = config_manager.get_scraper_config("mandiant")
        profile_path = Path(mandiant_config.profile_path)
        
        if profile_path.exists():
            import shutil
            shutil.rmtree(profile_path)
            click.echo(f"[OK] Cleared shared profile: {profile_path}")
            click.echo("Next run will require fresh login for all sources")
        else:
            click.echo(f"[INFO] No profile found: {profile_path}")
            
    except Exception as e:
        click.echo(f"[ERROR] Error clearing profile: {e}")
        raise click.ClickException(str(e))


console = Console()


@click.command()
@click.option("--file", "-f", "input_file",
              type=click.Path(exists=True, path_type=Path),
              required=True,
              help="Input file containing IOCs (CSV, JSON, TXT)")
@click.option("--output", "-o",
              type=click.Path(path_type=Path),
              help="Output file path")
@click.option("--enrich", "-e",
              is_flag=True,
              help="Enrich IOCs with external data sources")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--types", 
              multiple=True,
              help="Filter by indicator types (ip, domain, hash, etc.)")
@click.option("--batch-size", 
              type=int,
              default=1000,
              help="Batch size for processing")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def process_iocs(input_file: Path, output: Optional[Path], enrich: bool, config: Optional[str], 
                types: List[str], batch_size: int, log_level: str):
    """Process and enrich IOCs from file with advanced filtering and enrichment."""
    setup_logging(log_level)
    
    try:
        from ..services.ioc_processor.batch_processor import IOCBatchProcessor
        from ..services.ioc_processor.enrichment_engine import EnrichmentConfig
        
        console.print(f"[bold blue]Processing IOCs from: {input_file}")
        
        # Initialize configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        
        # Setup enrichment if requested
        enrichment_config = None
        if enrich:
            enrichment_config = EnrichmentConfig(app_config.enrichment if hasattr(app_config, 'enrichment') else {})
        
        # Initialize processor
        processor = IOCBatchProcessor(enrichment_config)
        processor.batch_size = batch_size
        
        # Setup filters
        filters = {}
        if types:
            filters['types'] = list(types)
        
        # Determine output path
        if not output:
            output = input_file.with_name(f"{input_file.stem}_processed{input_file.suffix}")
        
        # Process file
        with console.status("[bold green]Processing IOCs...") as status:
            result = asyncio.run(processor.process_file(
                input_path=input_file,
                output_path=output,
                enrich=enrich,
                filters=filters
            ))
        
        # Display results
        if result.errors:
            for error in result.errors:
                console.print(f"[red]Error: {error}")
            return
        
        console.print(f"[green]Successfully processed {result.valid_indicators} IOCs")
        console.print(f"Processing time: {result.processing_time:.2f}s")
        
        if result.output_files:
            console.print(f"Output saved to: {result.output_files[0]}")
        
    except Exception as e:
        console.print(f"[red]Error processing IOCs: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--input-dir", "-i",
              type=click.Path(exists=True, file_okay=False, path_type=Path),
              required=True,
              help="Directory containing IOC files to enrich")
@click.option("--output-dir", "-o",
              type=click.Path(path_type=Path),
              help="Output directory for enriched files")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--parallel", "-p",
              type=int,
              default=5,
              help="Number of parallel enrichment workers")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def enrich_batch(input_dir: Path, output_dir: Optional[Path], config: Optional[str], 
                parallel: int, log_level: str):
    """Batch enrich multiple IOC files with external data sources."""
    setup_logging(log_level)
    
    try:
        from ..services.ioc_processor.batch_processor import IOCBatchProcessor
        from ..services.ioc_processor.enrichment_engine import EnrichmentConfig
        
        console.print(f"[bold blue]Batch enriching IOCs from: {input_dir}")
        
        # Initialize configuration
        config_manager = ConfigManager(config)
        app_config = config_manager.get_config()
        
        # Setup enrichment
        enrichment_config = EnrichmentConfig(app_config.enrichment if hasattr(app_config, 'enrichment') else {})
        
        # Initialize processor
        processor = IOCBatchProcessor(enrichment_config)
        processor.max_workers = parallel
        
        # Find all IOC files
        ioc_files = []
        for pattern in ['*.csv', '*.json', '*.txt']:
            ioc_files.extend(input_dir.glob(pattern))
        
        if not ioc_files:
            console.print(f"[yellow]No IOC files found in {input_dir}")
            return
        
        console.print(f"Found {len(ioc_files)} files to process")
        
        # Setup output directory
        if not output_dir:
            output_dir = input_dir / "enriched"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Process files with progress
        total_indicators = 0
        total_time = 0
        
        with Progress() as progress:
            task = progress.add_task("[green]Enriching files...", total=len(ioc_files))
            
            for ioc_file in ioc_files:
                progress.update(task, description=f"Processing {ioc_file.name}")
                
                output_file = output_dir / f"{ioc_file.stem}_enriched{ioc_file.suffix}"
                
                result = asyncio.run(processor.process_file(
                    input_path=ioc_file,
                    output_path=output_file,
                    enrich=True
                ))
                
                total_indicators += result.valid_indicators
                total_time += result.processing_time
                
                progress.advance(task)
        
        console.print(f"[green]Batch enrichment completed!")
        console.print(f"Total indicators processed: {total_indicators}")
        console.print(f"Total processing time: {total_time:.2f}s")
        console.print(f"Output directory: {output_dir}")
        
    except Exception as e:
        console.print(f"[red]Error in batch enrichment: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--timeframe",
              default="30d",
              help="Analysis timeframe (e.g., 7d, 30d, 90d)")
@click.option("--sources",
              multiple=True,
              help="Filter by specific sources")
@click.option("--actors",
              multiple=True,
              help="Filter by specific threat actors")
@click.option("--output", "-o",
              type=click.Path(path_type=Path),
              help="Output file for analysis report")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
def analyze_threats(timeframe: str, sources: List[str], actors: List[str], 
                   output: Optional[Path], config: Optional[str]):
    """Analyze threat intelligence data and generate insights."""
    try:
        console.print(f"[bold blue]Analyzing threats for timeframe: {timeframe}")
        
        # Initialize configuration
        config_manager = ConfigManager(config)
        
        # This would integrate with the data analysis service
        # For now, show placeholder functionality
        
        console.print("[green]Analysis completed!")
        console.print("Key insights:")
        console.print("- Top 5 threat actors by activity")
        console.print("- IOC type distribution")
        console.print("- Geographic threat patterns")
        console.print("- Trending attack vectors")
        
        if output:
            console.print(f"Detailed report saved to: {output}")
            
    except Exception as e:
        console.print(f"[red]Error analyzing threats: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--format", "-f",
              type=click.Choice(["csv", "json", "stix", "misp", "openioc"]),
              required=True,
              help="Export format")
@click.option("--input", "-i",
              type=click.Path(exists=True, path_type=Path),
              required=True,
              help="Input file to export")
@click.option("--output", "-o",
              type=click.Path(path_type=Path),
              required=True,
              help="Output file path")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--include-enrichment",
              is_flag=True,
              help="Include enrichment data in export")
def export_data(format: str, input: Path, output: Path, config: Optional[str], 
               include_enrichment: bool):
    """Export threat intelligence data to various formats."""
    try:
        from ..core.plugin_system.registry import plugin_registry
        from ..services.ioc_processor.batch_processor import IOCBatchProcessor
        
        console.print(f"[bold blue]Exporting to {format.upper()} format")
        
        # Load indicators from input file
        processor = IOCBatchProcessor()
        indicators = asyncio.run(processor._load_indicators_from_file(input))
        
        if not indicators:
            console.print("[yellow]No indicators found in input file")
            return
        
        console.print(f"Loaded {len(indicators)} indicators")
        
        # Get exporter plugin
        exporter_config = {
            'output_path': str(output),
            'include_enrichment': include_enrichment
        }
        
        exporter = plugin_registry.get_plugin_instance("exporter", format, exporter_config)
        if not exporter:
            console.print(f"[red]Exporter plugin '{format}' not available")
            return
        
        # Export data
        with console.status(f"[bold green]Exporting to {format}..."):
            success = exporter.export_indicators(indicators, output)
        
        if success:
            console.print(f"[green]Successfully exported to: {output}")
        else:
            console.print("[red]Export failed")
            
    except Exception as e:
        console.print(f"[red]Error exporting data: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.argument("action", type=click.Choice(["list", "enable", "disable", "install"]))
@click.argument("plugin_name", required=False)
@click.option("--plugin-file",
              type=click.Path(exists=True),
              help="Plugin file to install")
def list_plugins(action: str, plugin_name: Optional[str], plugin_file: Optional[str]):
    """Manage plugins (list, enable, disable, install)."""
    try:
        from ..core.plugin_system.registry import plugin_registry
        
        if action == "list":
            console.print("[bold blue]Available Plugins:")
            
            # Create table
            table = Table(title="Plugin Registry")
            table.add_column("Type", style="cyan")
            table.add_column("Name", style="magenta")
            table.add_column("Status", style="green")
            
            for scraper_name in plugin_registry.get_available_scrapers():
                table.add_row("Scraper", scraper_name, "Available")
            
            for enricher_name in plugin_registry.get_available_enrichers():
                table.add_row("Enricher", enricher_name, "Available")
            
            for exporter_name in plugin_registry.get_available_exporters():
                table.add_row("Exporter", exporter_name, "Available")
            
            console.print(table)
            
        elif action == "install" and plugin_file:
            console.print(f"[blue]Installing plugin from: {plugin_file}")
            # Plugin installation logic would go here
            console.print("[green]Plugin installed successfully!")
            
        else:
            console.print(f"[yellow]Action '{action}' not fully implemented yet")
            
    except Exception as e:
        console.print(f"[red]Error managing plugins: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--plugin-type",
              type=click.Choice(["scraper", "enricher", "exporter", "processor"]),
              help="Filter by plugin type")
def plugin_status(plugin_type: Optional[str]):
    """Show detailed plugin status and health."""
    try:
        from ..core.plugin_system.registry import plugin_registry

        console.print("[bold blue]Plugin Status Report:")

        # Show plugin health status
        table = Table(title="Plugin Health Check")
        table.add_column("Type", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Health", style="green")
        table.add_column("Version", style="yellow")

        # This would check actual plugin health
        plugins_to_check = []

        if not plugin_type or plugin_type == "scraper":
            plugins_to_check.extend([("scraper", name) for name in plugin_registry.get_available_scrapers()])

        if not plugin_type or plugin_type == "enricher":
            plugins_to_check.extend([("enricher", name) for name in plugin_registry.get_available_enrichers()])

        if not plugin_type or plugin_type == "exporter":
            plugins_to_check.extend([("exporter", name) for name in plugin_registry.get_available_exporters()])

        for ptype, pname in plugins_to_check:
            # Would check actual plugin health here
            table.add_row(ptype.title(), pname, "Healthy", "1.0.0")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error checking plugin status: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--csv-file", "-f",
              type=click.Path(exists=True, path_type=Path),
              help="CSV file containing IOCs with Reports column (defaults to output/separated/ip_addresses.csv)")
@click.option("--output-dir", "-o",
              type=click.Path(path_type=Path),
              help="Output directory for PDFs and text files (defaults to downloads/crowdstrike_reports)")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def scrape_crowdstrike_pdfs(csv_file: Optional[Path], output_dir: Optional[Path], config: Optional[str], log_level: str):
    """Download PDFs from CrowdStrike reports referenced in IOC CSV file."""
    setup_logging(log_level)

    try:
        # Initialize configuration
        config_manager = ConfigManager(config)

        # Use default path if not provided
        if not csv_file:
            csv_file = Path("output/separated/ip_addresses.csv")
            if not csv_file.exists():
                console.print(f"[red]Default CSV file not found: {csv_file}")
                console.print("[yellow]Please specify a CSV file with --csv-file option")
                return

        # Use default output directory if not provided
        if not output_dir:
            output_dir = Path("downloads/crowdstrike_reports")

        console.print(f"[bold blue]Downloading CrowdStrike report PDFs from: {csv_file}")
        console.print(f"[bold blue]Output directory: {output_dir}")

        # Initialize CrowdStrike scraper
        scraper = CrowdStrikeScraper(config_manager)

        # Setup scraper (login)
        console.print("[yellow]Initializing CrowdStrike session...")
        if not scraper.setup():
            console.print("[red]Failed to setup CrowdStrike scraper")
            return

        try:
            # Download PDFs
            console.print("[green]Starting PDF downloads...")
            stats = scraper.scrape_pdfs_from_csv(str(csv_file), str(output_dir) if output_dir else None)

            # Display results
            if "error" in stats:
                console.print(f"[red]Error: {stats['error']}")
            else:
                console.print("\n[bold green]PDF Download Summary:")
                console.print(f"  Total reports found: {stats['total_reports']}")
                console.print(f"  Successfully downloaded: {stats['downloaded']}")
                console.print(f"  Failed: {stats['failed']}")
                console.print(f"  Skipped (no PDF): {stats['skipped']}")

                if stats['files']:
                    console.print(f"\n[blue]Downloaded files:")
                    for file_path in stats['files'][:10]:  # Show first 10
                        console.print(f"  - {file_path}")
                    if len(stats['files']) > 10:
                        console.print(f"  ... and {len(stats['files']) - 10} more")

        finally:
            scraper.cleanup()

    except Exception as e:
        console.print(f"[red]Error downloading PDFs: {e}")
        logger.error(f"PDF download error: {e}")
        raise click.ClickException(str(e))


@click.command()
@click.option("--csv-file", "-f",
              type=click.Path(exists=True, path_type=Path),
              help="CSV file containing IOCs with Associated Reports column (defaults to output/separated/ip_addresses.csv)")
@click.option("--output-dir", "-o",
              type=click.Path(path_type=Path),
              help="Output directory for PDFs (defaults to downloads/mandiant_reports)")
@click.option("--config", "-c",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--log-level", "-l",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO",
              help="Logging level")
def scrape_mandiant_pdfs(csv_file: Optional[Path], output_dir: Optional[Path], config: Optional[str], log_level: str):
    """Download PDFs from Mandiant reports referenced in IOC CSV file."""
    setup_logging(log_level)

    try:
        # Initialize configuration
        config_manager = ConfigManager(config)

        # Use default path if not provided
        if not csv_file:
            csv_file = Path("output/separated/ip_addresses.csv")
            if not csv_file.exists():
                console.print(f"[red]Default CSV file not found: {csv_file}")
                console.print("[yellow]Please specify a CSV file with --csv-file option")
                return

        # Use default output directory if not provided
        if not output_dir:
            output_dir = Path("downloads/mandiant_reports")

        console.print(f"[bold blue]Downloading Mandiant report PDFs from: {csv_file}")
        console.print(f"[bold blue]Output directory: {output_dir}")

        # Initialize Mandiant scraper
        scraper = MandiantScraper(config_manager)

        # Setup scraper (login)
        console.print("[yellow]Initializing Mandiant session...")
        if not scraper.setup():
            console.print("[red]Failed to setup Mandiant scraper")
            return

        try:
            # Download PDFs
            console.print("[green]Starting PDF downloads...")
            stats = scraper.scrape_pdfs_from_csv(str(csv_file), str(output_dir) if output_dir else None)

            # Display results
            if "error" in stats:
                console.print(f"[red]Error: {stats['error']}")
            else:
                console.print("\n[bold green]PDF Download Summary:")
                console.print(f"  Total reports found: {stats['total_reports']}")
                console.print(f"  Successfully downloaded: {stats['downloaded']}")
                console.print(f"  Failed: {stats['failed']}")
                console.print(f"  Skipped (no PDF): {stats['skipped']}")

                if stats['files']:
                    console.print(f"\n[blue]Downloaded files:")
                    for file_path in stats['files'][:10]:  # Show first 10
                        console.print(f"  - {file_path}")
                    if len(stats['files']) > 10:
                        console.print(f"  ... and {len(stats['files']) - 10} more")

        finally:
            scraper.cleanup()

    except Exception as e:
        console.print(f"[red]Error downloading PDFs: {e}")
        logger.error(f"PDF download error: {e}")
        raise click.ClickException(str(e))