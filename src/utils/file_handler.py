"""File handling utilities for downloads and CSV processing."""

import os
import glob
import time
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
import pandas as pd

logger = logging.getLogger(__name__)


class FileHandler:
    """Handles file operations for downloads and data processing."""
    
    def __init__(self, download_path: str):
        """Initialize file handler.
        
        Args:
            download_path: Path to download directory
        """
        self.download_path = Path(download_path)
        self.download_path.mkdir(parents=True, exist_ok=True)
    
    def wait_for_download(
        self, 
        timeout: int = 30,
        file_pattern: str = "*.csv",
        initial_files: Optional[List[str]] = None
    ) -> Optional[str]:
        """Wait for a new file to be downloaded.
        
        Args:
            timeout: Timeout in seconds
            file_pattern: Glob pattern for files to monitor
            initial_files: List of files present before download started
            
        Returns:
            Path to new downloaded file, or None if timeout
        """
        if initial_files is None:
            initial_files = glob.glob(str(self.download_path / file_pattern))
        
        logger.info(f"Waiting for download in {self.download_path} (timeout: {timeout}s)")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            current_files = glob.glob(str(self.download_path / file_pattern))
            
            # Check for new files
            new_files = [f for f in current_files if f not in initial_files]
            
            # Filter out partial downloads (files ending with .tmp, .part, .crdownload)
            complete_files = []
            for file_path in new_files:
                if not any(file_path.endswith(ext) for ext in ['.tmp', '.part', '.crdownload']):
                    # Check if file is stable (size not changing)
                    try:
                        size1 = os.path.getsize(file_path)
                        time.sleep(0.5)
                        size2 = os.path.getsize(file_path)
                        if size1 == size2 and size1 > 0:
                            complete_files.append(file_path)
                    except (OSError, FileNotFoundError):
                        continue
            
            if complete_files:
                # Return the most recent file
                newest_file = max(complete_files, key=os.path.getctime)
                logger.info(f"Download completed: {os.path.basename(newest_file)}")
                return newest_file
            
            time.sleep(1)
        
        logger.warning(f"Download timeout after {timeout} seconds")
        return None
    
    def get_files_before_download(self, file_pattern: str = "*.csv") -> List[str]:
        """Get list of files before starting download.
        
        Args:
            file_pattern: Glob pattern for files
            
        Returns:
            List of file paths
        """
        return glob.glob(str(self.download_path / file_pattern))
    
    def add_metadata_to_csv(
        self, 
        csv_file_path: str, 
        metadata: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> bool:
        """Add metadata columns to a CSV file.
        
        Args:
            csv_file_path: Path to CSV file
            metadata: Dictionary of column_name -> value mappings
            output_path: Optional output path (overwrites original if None)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            df = pd.read_csv(csv_file_path)
            
            # Add metadata columns at the beginning
            for i, (column, value) in enumerate(metadata.items()):
                df.insert(i, column, value)
            
            # Save to output path or overwrite original
            output_file = output_path or csv_file_path
            df.to_csv(output_file, index=False)
            
            logger.info(f"Added metadata to {os.path.basename(output_file)}: {list(metadata.keys())}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add metadata to CSV {csv_file_path}: {e}")
            return False
    
    def validate_csv_file(self, csv_file_path: str) -> Dict[str, Any]:
        """Validate and analyze a CSV file.
        
        Args:
            csv_file_path: Path to CSV file
            
        Returns:
            Dictionary with validation results
        """
        result = {
            'valid': False,
            'row_count': 0,
            'column_count': 0,
            'columns': [],
            'errors': []
        }
        
        try:
            if not os.path.exists(csv_file_path):
                result['errors'].append(f"File does not exist: {csv_file_path}")
                return result
            
            if os.path.getsize(csv_file_path) == 0:
                result['errors'].append("File is empty")
                return result
            
            # Read CSV
            df = pd.read_csv(csv_file_path)
            
            result['valid'] = True
            result['row_count'] = len(df)
            result['column_count'] = len(df.columns)
            result['columns'] = df.columns.tolist()
            
            # Check for common issues
            if result['row_count'] == 0:
                result['errors'].append("No data rows found")
            
            # Check for empty columns
            empty_columns = df.columns[df.isnull().all()].tolist()
            if empty_columns:
                result['errors'].append(f"Empty columns found: {empty_columns}")
            
            logger.info(f"CSV validation completed: {os.path.basename(csv_file_path)} "
                       f"({result['row_count']} rows, {result['column_count']} columns)")
            
        except pd.errors.EmptyDataError:
            result['errors'].append("CSV file is empty or has no data")
        except pd.errors.ParserError as e:
            result['errors'].append(f"CSV parsing error: {e}")
        except Exception as e:
            result['errors'].append(f"Unexpected error: {e}")
        
        return result
    
    def combine_csv_files(
        self, 
        file_paths: List[str], 
        output_path: str,
        add_source_column: bool = True
    ) -> Dict[str, Any]:
        """Combine multiple CSV files into one.
        
        Args:
            file_paths: List of CSV file paths to combine
            output_path: Path for combined output file
            add_source_column: Whether to add source_file column
            
        Returns:
            Dictionary with combination results
        """
        result = {
            'success': False,
            'total_files': len(file_paths),
            'processed_files': 0,
            'total_rows': 0,
            'output_file': output_path,
            'errors': []
        }
        
        try:
            combined_data = []
            
            for file_path in file_paths:
                try:
                    # Validate file first
                    validation = self.validate_csv_file(file_path)
                    if not validation['valid']:
                        result['errors'].extend([f"{os.path.basename(file_path)}: {err}" for err in validation['errors']])
                        continue
                    
                    # Read CSV
                    df = pd.read_csv(file_path)
                    
                    # Add source file column if requested
                    if add_source_column:
                        df['source_file'] = os.path.basename(file_path)
                    
                    combined_data.append(df)
                    result['processed_files'] += 1
                    
                    logger.info(f"Added {len(df)} rows from {os.path.basename(file_path)}")
                    
                except Exception as e:
                    error_msg = f"Error processing {os.path.basename(file_path)}: {e}"
                    result['errors'].append(error_msg)
                    logger.error(error_msg)
            
            if not combined_data:
                result['errors'].append("No valid CSV files to combine")
                return result
            
            # Combine all data
            final_df = pd.concat(combined_data, ignore_index=True)
            
            # Create output directory if needed
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Save combined file
            final_df.to_csv(output_path, index=False)
            
            result['success'] = True
            result['total_rows'] = len(final_df)
            
            logger.info(f"Combined {result['processed_files']} files into {output_path} "
                       f"({result['total_rows']} total rows)")
            
        except Exception as e:
            error_msg = f"Error combining CSV files: {e}"
            result['errors'].append(error_msg)
            logger.error(error_msg)
        
        return result
    
    def cleanup_temp_files(self, file_pattern: str = "*.tmp"):
        """Clean up temporary files in download directory.
        
        Args:
            file_pattern: Glob pattern for files to clean up
        """
        try:
            temp_files = glob.glob(str(self.download_path / file_pattern))
            
            for file_path in temp_files:
                try:
                    os.remove(file_path)
                    logger.debug(f"Removed temp file: {os.path.basename(file_path)}")
                except OSError as e:
                    logger.warning(f"Failed to remove temp file {file_path}: {e}")
            
            if temp_files:
                logger.info(f"Cleaned up {len(temp_files)} temporary files")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def move_file(self, source_path: str, destination_path: str) -> bool:
        """Move file from source to destination.
        
        Args:
            source_path: Source file path
            destination_path: Destination file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            source_path_obj = Path(source_path)
            dest_path_obj = Path(destination_path)
            
            # Create destination directory if needed
            dest_path_obj.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file
            source_path_obj.rename(dest_path_obj)
            
            logger.info(f"Moved file: {source_path_obj.name} -> {dest_path_obj}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to move file {source_path} -> {destination_path}: {e}")
            return False