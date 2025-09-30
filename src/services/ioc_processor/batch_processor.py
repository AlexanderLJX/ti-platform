"""Batch processing engine for large IOC datasets."""

import asyncio
import logging
import time
from typing import List, Optional, Dict, Any, Callable
from pathlib import Path
import pandas as pd

from ...core.models import Indicator, ProcessingResult, IndicatorType
from .enrichment_engine import IOCEnrichmentEngine, EnrichmentConfig

logger = logging.getLogger(__name__)


class IOCBatchProcessor:
    """High-performance batch processor for IOC datasets."""
    
    def __init__(self, enrichment_config: Optional[EnrichmentConfig] = None):
        self.enrichment_config = enrichment_config
        self.batch_size = 1000
        self.max_workers = 10
        
    async def process_file(
        self, 
        input_path: Path, 
        output_path: Optional[Path] = None,
        enrich: bool = False,
        filters: Optional[Dict[str, Any]] = None
    ) -> ProcessingResult:
        """Process IOCs from a file with optional enrichment."""
        start_time = time.time()
        logger.info(f"Starting batch processing of {input_path}")
        
        try:
            # Load indicators from file
            indicators = await self._load_indicators_from_file(input_path)
            logger.info(f"Loaded {len(indicators)} indicators from file")
            
            # Apply filters if provided
            if filters:
                indicators = self._apply_filters(indicators, filters)
                logger.info(f"Filtered to {len(indicators)} indicators")
            
            # Process indicators
            processed_indicators = await self._process_indicators(indicators, enrich)
            
            # Save results if output path provided
            output_files = []
            if output_path:
                output_files = await self._save_results(processed_indicators, output_path)
            
            processing_time = time.time() - start_time
            
            return ProcessingResult(
                total_indicators=len(indicators),
                valid_indicators=len(processed_indicators),
                filtered_indicators=len(indicators) - len(processed_indicators),
                processing_time=processing_time,
                output_files=output_files
            )
            
        except Exception as e:
            error_msg = f"Batch processing failed: {str(e)}"
            logger.error(error_msg)
            
            return ProcessingResult(
                errors=[error_msg],
                processing_time=time.time() - start_time
            )
    
    async def process_indicators(
        self,
        indicators: List[Indicator],
        enrich: bool = False,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Indicator]:
        """Process a list of indicators."""
        logger.info(f"Processing {len(indicators)} indicators")
        
        # Apply filters
        if filters:
            indicators = self._apply_filters(indicators, filters)
        
        # Process indicators
        return await self._process_indicators(indicators, enrich)
    
    async def _load_indicators_from_file(self, file_path: Path) -> List[Indicator]:
        """Load indicators from various file formats."""
        indicators = []
        
        try:
            if file_path.suffix.lower() == '.csv':
                df = pd.read_csv(file_path)
                indicators = self._dataframe_to_indicators(df)
            elif file_path.suffix.lower() == '.json':
                df = pd.read_json(file_path)
                indicators = self._dataframe_to_indicators(df)
            elif file_path.suffix.lower() in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
                indicators = self._dataframe_to_indicators(df)
            else:
                # Try to read as plain text (one IOC per line)
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f if line.strip()]
                
                indicators = []
                for line in lines:
                    ioc_type = self._detect_indicator_type(line)
                    if ioc_type:
                        indicators.append(Indicator(
                            value=line,
                            type=ioc_type,
                            threat_actor_name="Unknown",
                            source="file_import"
                        ))
            
            logger.info(f"Successfully loaded {len(indicators)} indicators from {file_path}")
            return indicators
            
        except Exception as e:
            logger.error(f"Error loading indicators from {file_path}: {e}")
            return []
    
    def _dataframe_to_indicators(self, df: pd.DataFrame) -> List[Indicator]:
        """Convert pandas DataFrame to list of Indicator objects."""
        indicators = []
        
        # Try to map common column names
        column_mapping = {
            'indicator': 'value',
            'ioc': 'value',
            'value': 'value',
            'type': 'type',
            'indicator_type': 'type',
            'threat_actor': 'threat_actor_name',
            'actor': 'threat_actor_name',
            'source': 'source',
            'confidence': 'confidence'
        }
        
        # Rename columns based on mapping
        df_mapped = df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns})
        
        # Ensure required columns exist
        if 'value' not in df_mapped.columns:
            # Try to find the most likely IOC column
            for col in df.columns:
                if any(keyword in col.lower() for keyword in ['indicator', 'ioc', 'value', 'ip', 'domain', 'hash']):
                    df_mapped['value'] = df[col]
                    break
        
        if 'value' not in df_mapped.columns:
            logger.error("Could not identify IOC value column in DataFrame")
            return indicators
        
        # Set defaults for missing columns
        if 'type' not in df_mapped.columns:
            df_mapped['type'] = df_mapped['value'].apply(self._detect_indicator_type)
        
        if 'threat_actor_name' not in df_mapped.columns:
            df_mapped['threat_actor_name'] = 'Unknown'
        
        if 'source' not in df_mapped.columns:
            df_mapped['source'] = 'file_import'
        
        # Convert to indicators
        for _, row in df_mapped.iterrows():
            try:
                # Skip rows with invalid values
                if pd.isna(row['value']) or not str(row['value']).strip():
                    continue
                
                indicator = Indicator(
                    value=str(row['value']).strip(),
                    type=row['type'] or IndicatorType.OTHER,
                    threat_actor_name=str(row['threat_actor_name']),
                    source=str(row['source'])
                )
                
                # Add optional fields if present
                if 'confidence' in row and not pd.isna(row['confidence']):
                    indicator.confidence = row['confidence']
                
                indicators.append(indicator)
                
            except Exception as e:
                logger.warning(f"Error converting row to indicator: {e}")
                continue
        
        return indicators
    
    def _detect_indicator_type(self, value: str) -> Optional[IndicatorType]:
        """Automatically detect indicator type from value."""
        if not value or not isinstance(value, str):
            return None
        
        value = str(value).strip()
        
        try:
            # IP address
            import ipaddress
            ipaddress.ip_address(value)
            return IndicatorType.IP
        except ValueError:
            pass
        
        # Hash patterns
        if len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IndicatorType.HASH_MD5
        elif len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IndicatorType.HASH_SHA1
        elif len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value):
            return IndicatorType.HASH_SHA256
        
        # URL
        if value.startswith(('http://', 'https://')):
            return IndicatorType.URL
        
        # Email
        if '@' in value and '.' in value.split('@')[-1]:
            return IndicatorType.EMAIL
        
        # Domain/FQDN
        if '.' in value and not value.startswith('.') and not value.endswith('.'):
            return IndicatorType.DOMAIN
        
        return IndicatorType.OTHER
    
    def _apply_filters(self, indicators: List[Indicator], filters: Dict[str, Any]) -> List[Indicator]:
        """Apply filters to indicator list."""
        filtered = indicators.copy()
        
        # Filter by indicator type
        if 'types' in filters:
            allowed_types = filters['types']
            if isinstance(allowed_types, str):
                allowed_types = [allowed_types]
            filtered = [i for i in filtered if i.type in allowed_types]
        
        # Filter by confidence
        if 'min_confidence' in filters:
            min_conf = filters['min_confidence']
            filtered = [i for i in filtered if i.confidence and i.confidence.value >= min_conf]
        
        # Filter by source
        if 'sources' in filters:
            allowed_sources = filters['sources']
            if isinstance(allowed_sources, str):
                allowed_sources = [allowed_sources]
            filtered = [i for i in filtered if i.source in allowed_sources]
        
        # Filter by date range
        if 'date_from' in filters:
            date_from = filters['date_from']
            filtered = [i for i in filtered if i.created_at >= date_from]
        
        if 'date_to' in filters:
            date_to = filters['date_to']
            filtered = [i for i in filtered if i.created_at <= date_to]
        
        # Custom filter function
        if 'custom_filter' in filters and callable(filters['custom_filter']):
            filtered = [i for i in filtered if filters['custom_filter'](i)]
        
        return filtered
    
    async def _process_indicators(self, indicators: List[Indicator], enrich: bool) -> List[Indicator]:
        """Process indicators with optional enrichment."""
        if not indicators:
            return []
        
        # Deduplicate indicators
        unique_indicators = self._deduplicate_indicators(indicators)
        logger.info(f"Deduplicated to {len(unique_indicators)} unique indicators")
        
        # Validate indicators
        valid_indicators = [i for i in unique_indicators if self._validate_indicator(i)]
        logger.info(f"Validated {len(valid_indicators)} indicators")
        
        # Enrich if requested
        if enrich and self.enrichment_config:
            valid_indicators = await self._enrich_indicators(valid_indicators)
        
        return valid_indicators
    
    def _deduplicate_indicators(self, indicators: List[Indicator]) -> List[Indicator]:
        """Remove duplicate indicators based on value and type."""
        seen = set()
        unique = []
        
        for indicator in indicators:
            key = (indicator.value.lower(), indicator.type)
            if key not in seen:
                seen.add(key)
                unique.append(indicator)
        
        return unique
    
    def _validate_indicator(self, indicator: Indicator) -> bool:
        """Validate indicator format and content."""
        try:
            # Basic validation
            if not indicator.value or not indicator.value.strip():
                return False
            
            # Type-specific validation
            if indicator.type == IndicatorType.IP:
                import ipaddress
                ipaddress.ip_address(indicator.value)
            elif indicator.type == IndicatorType.EMAIL:
                import re
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, indicator.value):
                    return False
            elif indicator.type == IndicatorType.URL:
                import validators
                if not validators.url(indicator.value):
                    return False
            elif indicator.type == IndicatorType.DOMAIN:
                import validators
                if not validators.domain(indicator.value):
                    return False
            
            return True
            
        except Exception as e:
            logger.debug(f"Validation failed for {indicator.value}: {e}")
            return False
    
    async def _enrich_indicators(self, indicators: List[Indicator]) -> List[Indicator]:
        """Enrich indicators using the enrichment engine."""
        if not self.enrichment_config:
            logger.warning("Enrichment requested but no config provided")
            return indicators
        
        try:
            async with IOCEnrichmentEngine(self.enrichment_config) as enricher:
                return await enricher.enrich_indicators(indicators)
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            return indicators
    
    async def _save_results(self, indicators: List[Indicator], output_path: Path) -> List[str]:
        """Save processed indicators to file."""
        output_files = []
        
        try:
            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert indicators to DataFrame
            df = self._indicators_to_dataframe(indicators)
            
            # Save in multiple formats
            if output_path.suffix.lower() == '.csv':
                df.to_csv(output_path, index=False)
                output_files.append(str(output_path))
            elif output_path.suffix.lower() == '.json':
                df.to_json(output_path, orient='records', indent=2)
                output_files.append(str(output_path))
            elif output_path.suffix.lower() in ['.xlsx', '.xls']:
                df.to_excel(output_path, index=False)
                output_files.append(str(output_path))
            else:
                # Default to CSV
                csv_path = output_path.with_suffix('.csv')
                df.to_csv(csv_path, index=False)
                output_files.append(str(csv_path))
            
            logger.info(f"Saved {len(indicators)} indicators to {output_files}")
            return output_files
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            return []
    
    def _indicators_to_dataframe(self, indicators: List[Indicator]) -> pd.DataFrame:
        """Convert indicators to pandas DataFrame."""
        records = []
        
        for indicator in indicators:
            record = {
                'value': indicator.value,
                'type': indicator.type,
                'confidence': indicator.confidence,
                'threat_actor_name': indicator.threat_actor_name,
                'source': indicator.source,
                'created_at': indicator.created_at,
                'is_enriched': indicator.is_enriched
            }
            
            # Add enrichment data if present
            if indicator.enrichment:
                if indicator.enrichment.geolocation:
                    record.update({
                        'country': indicator.enrichment.geolocation.country,
                        'country_code': indicator.enrichment.geolocation.country_code,
                        'city': indicator.enrichment.geolocation.city,
                        'latitude': indicator.enrichment.geolocation.latitude,
                        'longitude': indicator.enrichment.geolocation.longitude
                    })
                
                if indicator.enrichment.asn:
                    record.update({
                        'asn': indicator.enrichment.asn.asn,
                        'organization': indicator.enrichment.asn.organization
                    })
                
                if indicator.enrichment.reputation:
                    record.update({
                        'malicious_count': indicator.enrichment.reputation.malicious_count,
                        'suspicious_count': indicator.enrichment.reputation.suspicious_count,
                        'clean_count': indicator.enrichment.reputation.clean_count,
                        'reputation_score': indicator.enrichment.reputation.reputation_score
                    })
            
            records.append(record)
        
        return pd.DataFrame(records)