# CLAUDE.md - Threat Intelligence Platform

## Project Overview

This is an advanced threat intelligence collection and analysis platform designed for cybersecurity professionals. The platform automates the collection of threat intelligence from multiple sources, enriches IOCs with external data sources, and provides comprehensive analysis capabilities.

## Architecture

### Core Components
- **Plugin System**: Modular architecture supporting scrapers, enrichers, exporters, and processors
- **IOC Processing Pipeline**: High-performance batch processing with enrichment capabilities
- **Multi-Source Scraping**: Support for 9+ threat intelligence platforms
- **Export Engine**: Support for STIX, MISP, CSV, JSON, and OpenIOC formats
- **VS Code Extension**: Professional IDE integration for threat analysis workflows

### Technology Stack
- **Python 3.8+**: Core runtime
- **Selenium**: Web automation and scraping
- **Pydantic**: Type-safe data models and validation
- **Click**: Professional CLI framework
- **aiohttp**: Async HTTP for enrichment APIs
- **Rich**: Enhanced CLI output and progress indicators
- **TypeScript**: VS Code extension development

## Key Features

### 1. Multi-Source Intelligence Collection
```bash
# Scrape from all configured sources
ti-platform scrape --source all

# Scrape specific platforms
ti-platform scrape --source mandiant,crowdstrike,flashpoint
```

**Supported Platforms:**
- Mandiant Advantage
- CrowdStrike Falcon Intelligence  
- Flashpoint (planned)
- BAE Systems Threat Intelligence (planned)
- Kaspersky Threat Intelligence Portal (planned)
- Recorded Future (planned)
- Dragos Platform (planned)
- Cyware (planned)
- Feedly (planned)

### 2. Advanced IOC Processing
```bash
# Process and enrich thousands of IOCs
ti-platform process-iocs --file indicators.csv --enrich --types ip,domain,hash

# Batch enrichment of multiple files
ti-platform enrich-batch --input-dir ./raw_data/ --parallel 5
```

**Enrichment Sources:**
- **Geolocation**: MaxMind GeoIP2, IPinfo.io
- **Network Intelligence**: ASN data, hosting providers
- **Reputation Scoring**: VirusTotal, URLVoid, IPVoid
- **DNS Analysis**: Resolution data and historical records

### 3. Professional Export Capabilities
```bash
# Export to STIX 2.1 format
ti-platform export --format stix --input combined.csv --output threat-feed.json

# Export to MISP format
ti-platform export --format misp --input indicators.csv --output misp-event.json

# Export with enrichment data
ti-platform export --format csv --input data.csv --include-enrichment
```

### 4. Plugin Architecture
```bash
# List available plugins
ti-platform plugins list

# Check plugin health
ti-platform plugin-status --plugin-type scraper

# Install custom plugins
ti-platform plugins install --plugin-file custom-source.py
```

### 5. Threat Analysis
```bash
# Analyze threat patterns
ti-platform analyze-threats --timeframe 30d --sources mandiant,crowdstrike

# Generate executive reports
ti-platform analyze-threats --timeframe 90d --output executive-report.md
```

## Configuration

### Main Configuration (`config.yml`)
```yaml
scrapers:
  mandiant:
    enabled: true
    base_url: "https://advantage.mandiant.com"
    download_timeout: 30
    retry_attempts: 3
  
  crowdstrike:
    enabled: true
    base_url: "https://falcon.crowdstrike.com"
    download_timeout: 90

enrichment:
  maxmind_db_path: "data/GeoLite2-City.mmdb"
  virustotal_api_key: "${VIRUSTOTAL_API_KEY}"
  ipinfo_api_key: "${IPINFO_API_KEY}"
  rate_limit_per_minute: 60

data_processing:
  date_filter_days: 135
  confidence_mapping:
    ic_score_thresholds: [25, 75]
  output_formats: ["csv", "json", "stix"]
```

### Environment Variables (`.env`)
```bash
# Platform Credentials
MANDIANT_EMAIL=your_email@example.com
MANDIANT_PASSWORD=your_password
CROWDSTRIKE_EMAIL=your_email@example.com
CROWDSTRIKE_PASSWORD=your_password

# Enrichment API Keys
VIRUSTOTAL_API_KEY=your_vt_key
IPINFO_API_KEY=your_ipinfo_key
URLVOID_API_KEY=your_urlvoid_key
```

## VS Code Extension

The platform includes a professional VS Code extension providing:

### Features
- **Command Palette Integration**: Access all TI functions via Ctrl+Shift+P
- **IOC Detection**: Automatic highlighting and validation of indicators in documents
- **Enrichment Hover Cards**: Real-time threat intelligence on mouseover
- **Sidebar Panels**: Live source status, active jobs, and recent indicators
- **Export Integration**: One-click report generation in multiple formats

### Installation
1. Open VS Code
2. Navigate to Extensions
3. Install "Threat Intelligence Platform" extension
4. Configure CLI path in settings

## Development Guidelines

### Adding New Sources
1. Create scraper plugin inheriting from `BasePlugin`
2. Implement required methods: `initialize()`, `cleanup()`, `health_check()`
3. Register plugin in `src/plugins/scrapers/__init__.py`
4. Add configuration to `config.yml`

### Adding Enrichment Sources
1. Create enricher plugin in `src/plugins/enrichers/`
2. Implement enrichment logic with proper rate limiting
3. Add API configuration to enrichment config
4. Register plugin in plugin system

### Testing
```bash
# Validate configuration
ti-platform validate-config

# Test scraping (dry run)
ti-platform scrape --source mandiant --dry-run

# Test enrichment
ti-platform process-iocs --file test_iocs.csv --enrich

# Test exports
ti-platform export --format stix --input test_data.csv --output test.json
```

## Performance Characteristics

### Scalability
- **IOC Processing**: 10,000+ indicators per batch
- **Concurrent Enrichment**: 5-10 parallel API calls
- **Memory Efficient**: Streaming processing for large datasets
- **Rate Limiting**: Configurable limits for external APIs

### Reliability
- **Retry Logic**: Automatic retry with exponential backoff
- **Session Persistence**: Browser profiles for stable authentication
- **Error Handling**: Comprehensive logging and graceful degradation
- **Health Monitoring**: Plugin health checks and status reporting

## Security Considerations

### Authentication
- **2FA Support**: Compatible with TOTP and SMS-based 2FA
- **Session Management**: Secure browser profile storage
- **Credential Protection**: Environment-based credential management

### Data Privacy
- **Local Processing**: All enrichment data processed locally
- **API Rate Limiting**: Respectful API usage patterns
- **Data Retention**: Configurable cleanup policies

## Troubleshooting

### Common Issues
1. **Authentication Failures**: Check credentials and 2FA setup
2. **Download Timeouts**: Increase timeout values in config
3. **Enrichment Errors**: Verify API keys and rate limits
4. **Plugin Issues**: Check plugin status and dependencies

### Debugging
```bash
# Enable debug logging
ti-platform scrape --source mandiant --log-level DEBUG

# Check plugin health
ti-platform plugin-status

# Validate configuration
ti-platform validate-config
```

## Roadmap

### Phase 1 (Current)
- ✅ Core platform with 2 sources (Mandiant, CrowdStrike)
- ✅ IOC enrichment pipeline
- ✅ Export to STIX, MISP, CSV, JSON
- ✅ VS Code extension foundation

### Phase 2 (Next)
- 🔄 Additional 7 threat intelligence sources
- 🔄 Advanced threat analysis and correlation
- 🔄 Automated report generation
- 🔄 API integration for threat feeds

### Phase 3 (Future)
- 📋 Machine learning-based threat classification
- 📋 Real-time threat monitoring dashboards
- 📋 Integration with SIEM platforms
- 📋 Collaborative threat hunting features

## License

MIT License - See LICENSE file for details.

## Support

For issues, feature requests, or contributions, please use the GitHub repository issue tracker.