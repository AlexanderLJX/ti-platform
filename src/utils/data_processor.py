"""Data processing utilities for threat intelligence indicators."""

import re
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
import ipaddress

from ..core.models import ConfidenceLevel
from ..core.config import DataProcessingConfig

logger = logging.getLogger(__name__)


class DataProcessor:
    """Processes and standardizes threat intelligence data."""
    
    def __init__(self, config: DataProcessingConfig):
        """Initialize data processor.
        
        Args:
            config: Data processing configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def is_ip_address(self, value: str) -> bool:
        """Check if a value is an IP address.
        
        Args:
            value: Value to check
            
        Returns:
            True if IP address, False otherwise
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def clean_domain(self, value: str, indicator_type: str = None) -> Optional[str]:
        """Clean domain/URL by removing protocol and adding wildcards.
        
        Args:
            value: Value to clean
            indicator_type: Type of indicator
            
        Returns:
            Cleaned domain with wildcards, or None if invalid
        """
        if pd.isna(value) or not value:
            return None
        
        value = str(value).strip()
        
        # Remove http/https prefixes
        value = re.sub(r'^https?://', '', value, flags=re.IGNORECASE)
        
        # Add wildcards
        value = f'*{value}*'
        
        return value
    
    def convert_ic_score_to_confidence(self, ic_score: Any) -> Optional[ConfidenceLevel]:
        """Convert IC Score (0-100) to confidence level.
        
        Args:
            ic_score: IC score value
            
        Returns:
            ConfidenceLevel enum value or None
        """
        if pd.isna(ic_score):
            return None
        
        try:
            score = float(ic_score)
            low_threshold, high_threshold = self.config.ic_score_thresholds
            
            if 0 <= score < low_threshold:
                return ConfidenceLevel.LOW
            elif low_threshold <= score < high_threshold:
                return ConfidenceLevel.MEDIUM
            elif high_threshold <= score <= 100:
                return ConfidenceLevel.HIGH
            else:
                return None
        except (ValueError, TypeError):
            return None
    
    def parse_date(self, date_str: Any) -> Optional[datetime]:
        """Parse date string into datetime object.

        Args:
            date_str: Date string to parse

        Returns:
            Datetime object or None if parsing fails
        """
        if pd.isna(date_str):
            return None

        date_str = str(date_str).strip()

        # Common date formats
        formats = [
            '%Y-%m-%d',               # 2023-10-10
            '%Y-%m-%dT%H:%M:%SZ',     # 2025-07-03T18:16:20Z
            '%Y-%m-%dT%H:%M:%S',      # Without Z
            '%m/%d/%Y',               # 01/15/2023
            '%d/%m/%Y',               # 15/01/2023
            '%Y-%m-%d %H:%M:%S',      # 2023-10-10 15:30:00
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue

        self.logger.warning(f"Could not parse date: {date_str}")
        return None

    def generate_description(self, row_data: Dict[str, Any]) -> str:
        """Generate a detailed description for an IOC with source-separated information.

        Args:
            row_data: Dictionary containing IOC data

        Returns:
            Formatted description string with clear source attribution
        """
        parts = []

        # Basic info
        source = row_data.get('Source', 'unknown source')
        indicator_type = row_data.get('Original Type', 'indicator')
        indicator_value = row_data.get('IP') or row_data.get('Domain', 'Unknown')
        parts.append(f"This {indicator_type} ({indicator_value}) is associated with {row_data.get('Threat Actor Name', 'unknown threat actor')}.")

        # Dates
        first_seen = row_data.get('First Seen')
        last_seen = row_data.get('Last Seen')
        if first_seen or last_seen:
            date_parts = []
            if first_seen:
                date_parts.append(f"first observed {first_seen}")
            if last_seen:
                date_parts.append(f"last seen {last_seen}")
            parts.append(f"Activity timeline: {', '.join(date_parts)}.")

        # Separate Mandiant and CrowdStrike information
        mandiant_parts = []
        crowdstrike_parts = []

        # Check if we have Mandiant data
        has_mandiant = (
            not pd.isna(row_data.get('IC Score')) or
            not pd.isna(row_data.get('Associated Malware')) or
            not pd.isna(row_data.get('Associated Tools')) or
            not pd.isna(row_data.get('Associated Campaigns')) or
            not pd.isna(row_data.get('Associated Reports')) or
            'mandiant' in str(source).lower()
        )

        # Check if we have CrowdStrike data
        has_crowdstrike = (
            not pd.isna(row_data.get('Malware Families')) or
            not pd.isna(row_data.get('Kill Chains')) or
            not pd.isna(row_data.get('Labels')) or
            not pd.isna(row_data.get('Reports')) or
            'crowdstrike' in str(source).lower()
        )

        # MANDIANT INTELLIGENCE
        if has_mandiant:
            # Scores (IC Score and Threat Score only, no confidence level)
            ic_score = row_data.get('IC Score')
            threat_score = row_data.get('Threat Score')
            if ic_score or threat_score:
                score_parts = []
                if ic_score:
                    score_parts.append(f"IC Score: {ic_score}")
                if threat_score:
                    score_parts.append(f"Threat Score: {threat_score}")
                mandiant_parts.append(f"Scores: {', '.join(score_parts)}")

            # Malware
            if not pd.isna(row_data.get('Associated Malware')):
                mandiant_parts.append(f"Associated malware: {row_data.get('Associated Malware')}")

            # Tools
            if not pd.isna(row_data.get('Associated Tools')):
                mandiant_parts.append(f"Tools: {row_data.get('Associated Tools')}")

            # Campaigns
            if not pd.isna(row_data.get('Associated Campaigns')):
                mandiant_parts.append(f"Campaigns: {row_data.get('Associated Campaigns')}")

            # Reports
            if not pd.isna(row_data.get('Associated Reports')):
                mandiant_parts.append(f"Reports: {row_data.get('Associated Reports')}")

            # Hashes
            hashes = []
            if not pd.isna(row_data.get('SHA256')):
                hashes.append(f"SHA256: {row_data.get('SHA256')}")
            if not pd.isna(row_data.get('SHA1')):
                hashes.append(f"SHA1: {row_data.get('SHA1')}")
            if hashes:
                mandiant_parts.append(f"Hashes: {', '.join(hashes)}")

            # Exclusive
            if row_data.get('Exclusive') == True or row_data.get('Exclusive') == 'True':
                mandiant_parts.append("Exclusive intelligence")

        # CROWDSTRIKE INTELLIGENCE
        if has_crowdstrike:
            # Malware Families
            if not pd.isna(row_data.get('Malware Families')):
                crowdstrike_parts.append(f"Malware families: {row_data.get('Malware Families')}")

            # Kill Chains
            if not pd.isna(row_data.get('Kill Chains')):
                crowdstrike_parts.append(f"Kill chain stages: {row_data.get('Kill Chains')}")

            # Reports (only if not already added by Mandiant)
            if not pd.isna(row_data.get('Reports')) and pd.isna(row_data.get('Associated Reports')):
                crowdstrike_parts.append(f"Reports: {row_data.get('Reports')}")

            # Labels/Tags
            if not pd.isna(row_data.get('Labels')):
                crowdstrike_parts.append(f"Tags: {row_data.get('Labels')}")

        # Combine source-specific information
        if mandiant_parts:
            parts.append(f"[MANDIANT] {'; '.join(mandiant_parts)}.")
        if crowdstrike_parts:
            parts.append(f"[CROWDSTRIKE] {'; '.join(crowdstrike_parts)}.")

        return ' '.join(parts)
    
    def is_within_date_filter(self, date_str: Any) -> bool:
        """Check if date is within the configured filter window.
        
        Args:
            date_str: Date string to check
            
        Returns:
            True if within filter window, False otherwise
        """
        parsed_date = self.parse_date(date_str)
        if parsed_date is None:
            return False
        
        cutoff_date = datetime.now() - timedelta(days=self.config.date_filter_days)
        return parsed_date >= cutoff_date
    
    def process_mandiant_indicators(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process Mandiant indicators DataFrame.
        
        Args:
            df: Raw Mandiant indicators DataFrame
            
        Returns:
            Processed DataFrame
        """
        processed_rows = []
        
        for _, row in df.iterrows():
            # Skip if not within date filter
            if not self.is_within_date_filter(row.get('Last Seen')):
                continue
            
            indicator_value = row.get('Indicator Value')
            indicator_type = row.get('Indicator Type', '').lower()
            threat_actor_name = row.get('threat_actor_name')
            ic_score = row.get('IC Score')
            
            if pd.isna(indicator_value) or not threat_actor_name:
                continue
            
            # Determine if it's an IP or domain
            if self.is_ip_address(indicator_value):
                ip = indicator_value
                domain = None
            else:
                ip = None
                domain = self.clean_domain(indicator_value, indicator_type)
            
            # Convert confidence
            confidence = self.convert_ic_score_to_confidence(ic_score)

            row_dict = {
                'Threat Actor Name': threat_actor_name,
                'IP': ip,
                'Domain': domain,
                'Confidence': confidence.value if confidence else None,
                'Source': 'mandiant',
                'Last Seen': self.parse_date(row.get('Last Seen')),
                'First Seen': self.parse_date(row.get('First Seen')),
                'IC Score': ic_score,
                'Threat Score': row.get('Threat Score'),
                'Original Type': indicator_type,
                'Associated Actors': row.get('Associated Actors'),
                'Associated Malware': row.get('Associated Malware'),
                'Associated Tools': row.get('Associated Tools'),
                'Associated Campaigns': row.get('Associated Campaigns'),
                'Associated Reports': row.get('Associated Reports'),
                'Exclusive': row.get('Exclusive'),
                'SHA1': row.get('SHA1'),
                'SHA256': row.get('SHA256'),
                'Malware Families': None,
                'Actors': None,
                'Reports': None,
                'Kill Chains': None,
                'Labels': None,
                'Metadata': {
                    'original_indicator': indicator_value,
                    'threat_actor_id': row.get('threat_actor_id')
                }
            }

            # Generate description
            row_dict['Description'] = self.generate_description(row_dict)

            processed_rows.append(row_dict)
        
        return pd.DataFrame(processed_rows)
    
    def process_crowdstrike_indicators(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process CrowdStrike indicators DataFrame.
        
        Args:
            df: Raw CrowdStrike indicators DataFrame
            
        Returns:
            Processed DataFrame
        """
        processed_rows = []
        
        for _, row in df.iterrows():
            # Skip if not within date filter
            if not self.is_within_date_filter(row.get('last_updated')):
                continue
            
            indicator = row.get('indicator')
            indicator_type = row.get('type', '').lower()
            threat_actor_name = row.get('threat_actor_name')
            malicious_confidence = row.get('malicious_confidence')
            
            if pd.isna(indicator) or not threat_actor_name:
                continue
            
            # Determine if it's an IP or domain
            if self.is_ip_address(indicator):
                ip = indicator
                domain = None
            else:
                ip = None
                domain = self.clean_domain(indicator, indicator_type)
            
            # Standardize confidence
            confidence = None
            if not pd.isna(malicious_confidence):
                conf_str = str(malicious_confidence).lower()
                if conf_str in ['low', 'medium', 'high']:
                    confidence = conf_str.title()

            row_dict = {
                'Threat Actor Name': threat_actor_name,
                'IP': ip,
                'Domain': domain,
                'Confidence': confidence,
                'Source': 'crowdstrike',
                'Last Seen': self.parse_date(row.get('last_updated')),
                'First Seen': self.parse_date(row.get('published_date')),
                'IC Score': None,
                'Threat Score': None,
                'Original Type': indicator_type,
                'Malware Families': row.get('malware_families'),
                'Actors': row.get('actors'),
                'Reports': row.get('reports'),
                'Kill Chains': row.get('kill_chains'),
                'Labels': row.get('labels'),
                'Associated Actors': None,
                'Associated Malware': None,
                'Associated Tools': None,
                'Associated Campaigns': None,
                'Associated Reports': None,
                'Exclusive': None,
                'SHA1': None,
                'SHA256': None,
                'Metadata': {
                    'original_indicator': indicator,
                    'threat_actor_slug': row.get('threat_actor_slug'),
                    'malicious_confidence': malicious_confidence
                }
            }

            # Generate description
            row_dict['Description'] = self.generate_description(row_dict)

            processed_rows.append(row_dict)
        
        return pd.DataFrame(processed_rows)
    
    def combine_and_process_files(self, file_paths: List[str], output_path: str) -> Dict[str, Any]:
        """Combine and process multiple CSV files.
        
        Args:
            file_paths: List of CSV file paths
            output_path: Output file path
            
        Returns:
            Dictionary with processing results
        """
        result = {
            'success': False,
            'total_files': len(file_paths),
            'processed_files': 0,
            'total_rows': 0,
            'filtered_rows': 0,
            'output_file': output_path,
            'errors': [],
            'summary': {}
        }
        
        try:
            all_processed_data = []
            
            for file_path in file_paths:
                try:
                    file_path_obj = Path(file_path)
                    self.logger.info(f"Processing: {file_path_obj.name}")
                    
                    # Read CSV
                    df = pd.read_csv(file_path)
                    original_count = len(df)
                    
                    # Determine source and process accordingly
                    if 'source' in df.columns:
                        source = df['source'].iloc[0] if len(df) > 0 else 'unknown'
                    elif 'threat_actor_slug' in df.columns:
                        source = 'crowdstrike'
                    elif 'IC Score' in df.columns:
                        source = 'mandiant'
                    else:
                        source = 'unknown'
                    
                    # Process based on source
                    if source == 'mandiant':
                        processed_df = self.process_mandiant_indicators(df)
                    elif source == 'crowdstrike':
                        processed_df = self.process_crowdstrike_indicators(df)
                    else:
                        # Generic processing
                        processed_df = df
                        processed_df = processed_df.dropna(subset=['threat_actor_name'], how='all')
                    
                    if len(processed_df) > 0:
                        # Add source file info
                        processed_df['source_file'] = file_path_obj.name
                        all_processed_data.append(processed_df)
                        
                        # Update summary
                        source_key = f"{source}"
                        if source_key not in result['summary']:
                            result['summary'][source_key] = 0
                        result['summary'][source_key] += len(processed_df)
                    
                    result['processed_files'] += 1
                    result['filtered_rows'] += (original_count - len(processed_df))
                    
                    self.logger.info(f"Processed {file_path_obj.name}: {original_count} -> {len(processed_df)} rows")
                    
                except Exception as e:
                    error_msg = f"Error processing {Path(file_path).name}: {e}"
                    result['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            if not all_processed_data:
                result['errors'].append("No valid data to combine")
                return result
            
            # Combine all processed data
            final_df = pd.concat(all_processed_data, ignore_index=True)
            
            # Deduplicate indicators
            final_df['indicator_value'] = final_df['IP'].fillna(final_df['Domain'])
            final_df = final_df.sort_values('Last Seen', ascending=False)

            # Map confidence to numerical values for aggregation
            confidence_mapping = {'Low': 1, 'Medium': 2, 'High': 3}
            final_df['Confidence_numeric'] = final_df['Confidence'].map(confidence_mapping)

            # Helper function to combine non-null values
            def combine_values(series):
                unique_values = series.dropna().astype(str).unique()
                return ', '.join(unique_values) if len(unique_values) > 0 else None

            aggregation_functions = {
                'Threat Actor Name': 'first',
                'IP': 'first',
                'Domain': 'first',
                'Confidence_numeric': 'max',
                'Source': lambda x: ', '.join(x.unique()),
                'Last Seen': 'first',
                'First Seen': 'first',
                'IC Score': 'max',
                'Threat Score': 'max',
                'Original Type': 'first',
                'Associated Actors': combine_values,
                'Associated Malware': combine_values,
                'Associated Tools': combine_values,
                'Associated Campaigns': combine_values,
                'Associated Reports': combine_values,
                'Exclusive': 'first',
                'SHA1': 'first',
                'SHA256': 'first',
                'Malware Families': combine_values,
                'Actors': combine_values,
                'Reports': combine_values,
                'Kill Chains': combine_values,
                'Labels': combine_values,
                'Description': 'first',
                'Metadata': lambda x: {k: v for d in x for k, v in d.items()},
                'source_file': lambda x: ', '.join(x.unique())
            }

            final_df = final_df.groupby('indicator_value').agg(aggregation_functions).reset_index()

            # Map confidence back to string values
            reverse_confidence_mapping = {v: k for k, v in confidence_mapping.items()}
            final_df['Confidence'] = final_df['Confidence_numeric'].map(reverse_confidence_mapping)
            final_df = final_df.drop(columns=['indicator_value', 'Confidence_numeric'])

            # Regenerate descriptions after aggregation to include data from both sources
            self.logger.info("Regenerating descriptions with merged source data...")
            new_descriptions = []
            for _, row in final_df.iterrows():
                new_descriptions.append(self.generate_description(row.to_dict()))
            final_df['Description'] = new_descriptions

            # Remove rows where both IP and Domain are None
            final_df = final_df.dropna(subset=['IP', 'Domain'], how='all')
            
            # Create output directory
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Save combined file
            final_df.to_csv(output_path, index=False)
            
            result['success'] = True
            result['total_rows'] = len(final_df)
            
            self.logger.info(f"Combined {result['processed_files']} files into {output_path}")
            self.logger.info(f"Total rows: {result['total_rows']}, Filtered: {result['filtered_rows']}")
            
            # Generate additional output formats if configured
            if 'json' in self.config.output_formats:
                json_path = output_path_obj.with_suffix('.json')
                final_df.to_json(json_path, orient='records', indent=2)
                self.logger.info(f"JSON output saved: {json_path}")
            
        except Exception as e:
            error_msg = f"Error combining files: {e}"
            result['errors'].append(error_msg)
            self.logger.error(error_msg)
        
        return result