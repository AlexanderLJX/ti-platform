# Threat Intelligence Platform

Advanced threat intelligence collection, enrichment, and analysis platform for cybersecurity professionals.

## 🚀 Features

- **🌐 Multi-Source Intelligence**: Automated collection from 9+ threat intelligence platforms
- **⚡ IOC Enrichment**: Real-time enrichment with geolocation, ASN, and reputation data
- **📊 Batch Processing**: Handle thousands of indicators with high-performance processing
- **🔄 Export Formats**: STIX 2.1, MISP, CSV, JSON, and OpenIOC support
- **🧩 Plugin Architecture**: Modular design for easy extensibility
- **🎯 VS Code Integration**: Professional IDE extension for threat analysis workflows
- **🔐 Enterprise Security**: 2FA support, session persistence, and secure credential management

## 📋 Supported Platforms

### Currently Implemented
- ✅ **Mandiant Advantage** - Comprehensive threat intelligence and indicators
- ✅ **CrowdStrike Falcon Intelligence** - Real-time threat data and IOCs

### Planned Integration
- 🔄 **Flashpoint** - Deep & dark web intelligence
- 🔄 **BAE Systems** - Government-grade threat intelligence
- 🔄 **Kaspersky TIP** - Global threat landscape data
- 🔄 **Recorded Future** - Predictive threat intelligence
- 🔄 **Dragos Platform** - Industrial cybersecurity intelligence
- 🔄 **Cyware** - Collaborative threat intelligence
- 🔄 **Feedly** - Open source intelligence feeds

## 🏁 Quick Start

### 1. Install Dependencies
```bash
# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### 2. Configure Credentials
Create `.env` file:
```bash
# Platform Credentials
MANDIANT_EMAIL=your_email@example.com
MANDIANT_PASSWORD=your_secure_password
MANDIANT_TOTP_SECRET=your_base32_totp_secret  # Optional: Enables automatic 2FA

CROWDSTRIKE_EMAIL=your_email@example.com
CROWDSTRIKE_PASSWORD=your_secure_password
CROWDSTRIKE_TOTP_SECRET=your_base32_totp_secret  # Optional: Enables automatic 2FA

# Enrichment API Keys (Optional)
VIRUSTOTAL_API_KEY=your_vt_api_key
IPINFO_API_KEY=your_ipinfo_key
```

**Setting up Automatic 2FA (Optional but Recommended):**
1. When configuring 2FA in Mandiant/CrowdStrike, look for "Manual entry" or "Can't scan?" option
2. Copy the base32 secret key (e.g., `JBSWY3DPEHPK3PXP`)
3. Add it to your `.env` file as the `*_TOTP_SECRET` value
4. The platform will automatically generate and enter 2FA tokens

### 3. Validate Configuration
```bash
ti-platform validate-config
```

### 4. Start Collecting Intelligence
```bash
# Scrape from all sources
ti-platform scrape --source all

# Process and enrich IOCs
ti-platform process-iocs --file indicators.csv --enrich

# Export to STIX format
ti-platform export --format stix --input combined.csv --output threat-feed.json
```

## 📖 Core Commands

### Intelligence Collection
```bash
# Scrape from specific sources
ti-platform scrape --source mandiant,crowdstrike

# Preview before scraping
ti-platform scrape --source all --dry-run

# Combine downloaded files
ti-platform combine
```

### IOC Processing & Enrichment
```bash
# Process IOCs with enrichment
ti-platform process-iocs --file indicators.csv --enrich --types ip,domain,hash

# Batch enrich multiple files
ti-platform enrich-batch --input-dir ./raw_iocs/ --output-dir ./enriched/

# Filter by indicator types
ti-platform process-iocs --file mixed_iocs.csv --types ip,domain --batch-size 500
```

### Export & Analysis
```bash
# Export to multiple formats
ti-platform export --format stix --input data.csv --output threat-feed.json
ti-platform export --format misp --input data.csv --output misp-event.json
ti-platform export --format csv --input data.csv --include-enrichment

# Analyze threat patterns
ti-platform analyze-threats --timeframe 30d --sources mandiant,crowdstrike
```

### Plugin Management
```bash
# List available plugins
ti-platform plugins list

# Check plugin health
ti-platform plugin-status

# Install custom plugins
ti-platform plugins install --plugin-file custom-source.py
```

## 🎯 VS Code Extension

Install the "Threat Intelligence Platform" extension for:

- **Command Palette Integration**: Access all functions via `Ctrl+Shift+P`
- **IOC Detection**: Automatic highlighting of indicators in documents
- **Enrichment Hover Cards**: Real-time threat intelligence on mouseover
- **Live Monitoring**: Source status, active jobs, and recent indicators
- **One-Click Exports**: Generate reports directly from the IDE

## ⚙️ Configuration

### Main Configuration (`config.yml`)
```yaml
scrapers:
  mandiant:
    enabled: true
    base_url: "https://advantage.mandiant.com"
    download_timeout: 30
    retry_attempts: 3
    profile_path: "profiles/chrome_shared"
  
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

### Enrichment Services
The platform integrates with multiple external services:

- **Geolocation**: MaxMind GeoIP2, IPinfo.io
- **Network Intelligence**: ASN data, hosting providers  
- **Reputation**: VirusTotal, URLVoid, IPVoid
- **DNS Analysis**: Resolution and historical data

## 📁 Project Structure

```
threat-intelligence-platform/
├── src/
│   ├── core/                    # Core framework
│   │   ├── plugin_system/       # Plugin registry and management
│   │   ├── models/              # Pydantic data models
│   │   └── config/              # Configuration management
│   ├── plugins/                 # Plugin implementations
│   │   ├── scrapers/            # Source scraper plugins
│   │   ├── enrichers/           # IOC enrichment plugins
│   │   └── exporters/           # Export format plugins
│   ├── services/                # Core services
│   │   ├── ioc_processor/       # IOC processing engine
│   │   └── data_manager/        # Data storage and retrieval
│   ├── cli/                     # Command-line interface
│   └── vscode_extension/        # VS Code extension
├── data/
│   ├── sources/                 # Source configurations
│   ├── enrichment/              # Enrichment databases
│   └── exports/                 # Output files
└── tests/                       # Test suites
```

## 📊 Performance & Scale

- **IOC Processing**: 10,000+ indicators per batch
- **Concurrent Enrichment**: 5-10 parallel API calls with rate limiting
- **Memory Efficient**: Streaming processing for large datasets
- **Reliability**: Automatic retry with exponential backoff
- **Session Management**: Persistent browser profiles for stable authentication

## 🛡️ Security Features

- **Automatic 2FA**: TOTP-based automatic authentication with Google Authenticator compatibility
- **Manual 2FA Fallback**: SMS and app-based 2FA support when TOTP secrets aren't configured
- **Credential Protection**: Environment-based secret management with no hardcoded credentials
- **Session Persistence**: Secure browser profile storage to minimize re-authentication
- **API Rate Limiting**: Respectful usage of external services with configurable limits
- **Local Processing**: All enrichment performed locally for data privacy

## 🔧 Development

### Adding New Sources
1. Create scraper plugin inheriting from `BasePlugin`
2. Implement authentication and data extraction logic
3. Register plugin in `src/plugins/scrapers/__init__.py`
4. Add configuration to `config.yml`

### Testing
```bash
# Validate setup
ti-platform validate-config

# Test scraping (dry run)
ti-platform scrape --source mandiant --dry-run

# Debug mode
ti-platform scrape --source all --log-level DEBUG
```

## 📈 Roadmap

### Current Version (v0.2.0)
- ✅ Core platform with plugin architecture
- ✅ Mandiant and CrowdStrike integration
- ✅ IOC enrichment pipeline
- ✅ STIX, MISP, CSV, JSON export formats
- ✅ VS Code extension foundation

### Next Release (v0.3.0)
- 🔄 Additional 7 threat intelligence sources
- 🔄 Advanced threat correlation and analysis
- 🔄 Automated reporting and dashboards
- 🔄 Enhanced VS Code extension features

### Future Releases
- 📋 Machine learning-based threat classification
- 📋 Real-time threat monitoring
- 📋 SIEM platform integrations
- 📋 Collaborative threat hunting tools

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/threat-intelligence-platform/issues)
- **Documentation**: See [CLAUDE.md](CLAUDE.md) for detailed documentation
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/threat-intelligence-platform/discussions)

---

**Built with ❤️ for the cybersecurity community**