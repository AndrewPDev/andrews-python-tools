"""
CSV/Excel Analyzer and Cleaner

Author:
Andrew Piggot

Purpose: 
Analyze and clean CSV/Excel files with data insights and cleaning operations

Usage: 
Data analysis, file cleaning, educational purposes
"""

import csv
import os
import sys
from typing import List, Dict, Any, Optional
import json
from datetime import datetime

# Main class for CSV/Excel analysis and cleaning
class CSVTool:
    # Initialize the analyzer
    def __init__( self ):
        self.data = []
        self.headers = []
        self.filename = ""
        self.stats = {}
    
    # Load CSV file for analysis
    def Load( self, filename: str ) -> bool:
        try:
            self.filename = filename
            self.data = []
            self.headers = []
            
            with open( filename, 'r', encoding='utf-8', newline='' ) as file:
                # Try to detect delimiter
                sample = file.read( 1024 )
                file.seek( 0 )
                
                sniffer = csv.Sniffer()
                delimiter = sniffer.sniff( sample ).delimiter
                
                reader = csv.reader( file, delimiter=delimiter )
                self.headers = next( reader )
                
                for row in reader:
                    self.data.append( row )
            
            print( f"Successfully loaded {len( self.data )} rows from {filename}" )
            return True
            
        except FileNotFoundError:
            print( f"Error: File '{filename}' not found." )
            return False
        except Exception as e:
            print( f"Error loading file: {e}" )
            return False
    
    # Analyze the loaded data
    def Analyze( self ):
        if not self.data:
            print( "No data loaded. Please load a file first." )
            return
        
        print( f"\n{'='*60}" )
        print( f"Data Analysis for: {self.filename}" )
        print( f"{'='*60}" )
        
        # Basic statistics
        print( f"\nBasic Information:" )
        print( f"   Rows: {len( self.data )}" )
        print( f"   Columns: {len( self.headers )}" )
        print( f"   File size: {self._GetSize()}" )
        
        # Column analysis
        print( f"\nColumn Analysis:" )
        for i, header in enumerate( self.headers ):
            column_data = [row[i] if i < len( row ) else '' for row in self.data]
            self._AnalyzeCol( header, column_data, i )
        
        # Data quality issues
        self._CheckQuality()
    
    # Analyze individual column
    def _AnalyzeCol( self, header: str, data: List[str], index: int ):
        print( f"\n   Column {index + 1}: '{header}'" )
        
        # Count non-empty values
        non_empty = [val for val in data if val.strip()]
        empty_count = len( data ) - len( non_empty )
        
        print( f"      Non-empty values: {len( non_empty )}" )
        if empty_count > 0:
            print( f"      Empty/blank values: {empty_count}" )
        
        # Try to determine data type
        data_type = self._GuessType( non_empty )
        print( f"      Likely data type: {data_type}" )
        
        # Unique values
        unique_vals = set( non_empty )
        print( f"      Unique values: {len( unique_vals )}" )
        
        # Show sample values
        if non_empty:
            sample_size = min( 3, len( unique_vals ) )
            samples = list( unique_vals )[:sample_size]
            print( f"      Sample values: {samples}" )
    
    # Guess the data type of a column
    def _GuessType( self, data: List[str] ) -> str:
        if not data:
            return "Empty"
        
        # Check if all values are numeric
        num_count = 0
        date_count = 0
        
        for value in data[:min( 100, len( data ) )]:  # Sample first 100 values
            # Check for numbers
            try:
                float( value.replace( ',', '' ) )
                num_count += 1
                continue
            except ValueError:
                pass
            
            # Check for dates
            if self._IsDate( value ):
                date_count += 1
        
        total_sample = min( 100, len( data ) )
        
        if num_count > total_sample * 0.8:
            return "Numeric"
        elif date_count > total_sample * 0.5:
            return "Date/Time"
        else:
            return "Text"
    
    # Check if a value looks like a date
    def _IsDate( self, value: str ) -> bool:
        date_patterns = [
            '%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%Y/%m/%d',
            '%d-%m-%Y', '%m-%d-%Y', '%Y%m%d'
        ]
        
        for pattern in date_patterns:
            try:
                datetime.strptime( value, pattern )
                return True
            except ValueError:
                continue
        return False
    
    # Check for data quality issues
    def _CheckQuality( self ):
        print( f"\nData Quality Check:" )
        issues = []
        
        # Check for inconsistent row lengths
        expected_cols = len( self.headers )
        bad_rows = 0
        
        for i, row in enumerate( self.data ):
            if len( row ) != expected_cols:
                bad_rows += 1
        
        if bad_rows > 0:
            issues.append( f"Inconsistent row lengths: {bad_rows} rows" )
        
        # Check for completely empty rows
        empty_rows = 0
        for row in self.data:
            if all( cell.strip() == '' for cell in row ):
                empty_rows += 1
        
        if empty_rows > 0:
            issues.append( f"Completely empty rows: {empty_rows}" )
        
        # Check for duplicate rows
        row_strings = [','.join( row ) for row in self.data]
        unique_rows = set( row_strings )
        duplicates = len( row_strings ) - len( unique_rows )
        
        if duplicates > 0:
            issues.append( f"Duplicate rows: {duplicates}" )
        
        if issues:
            print( "   Issues found:" )
            for issue in issues:
                print( f"      - {issue}" )
        else:
            print( "   No major data quality issues detected!" )
    
    # Clean the data based on user preferences
    def Clean( self, options: Dict[str, bool] ) -> bool:
        if not self.data:
            print( "No data loaded. Please load a file first." )
            return False
        
        orig_rows = len( self.data )
        clean_data = []
        
        print( f"\nCleaning data with options: {options}" )
        
        for row in self.data:
            # Skip empty rows if requested
            if options.get( 'remove_empty_rows', False ):
                if all( cell.strip() == '' for cell in row ):
                    continue
            
            # Clean individual cells
            clean_row = []
            for cell in row:
                clean_cell = cell
                
                # Remove extra whitespace
                if options.get( 'trim_whitespace', False ):
                    clean_cell = clean_cell.strip()
                
                # Remove special characters if requested
                if options.get( 'remove_special_chars', False ):
                    clean_cell = ''.join( char for char in clean_cell 
                                         if char.isalnum() or char.isspace() or char in '.,;:-' )
                
                clean_row.append( clean_cell )
            
            clean_data.append( clean_row )
        
        # Remove duplicates if requested
        if options.get( 'remove_duplicates', False ):
            seen = set()
            unique_data = []
            for row in clean_data:
                row_str = ','.join( row )
                if row_str not in seen:
                    seen.add( row_str )
                    unique_data.append( row )
            clean_data = unique_data
        
        self.data = clean_data
        rows_removed = orig_rows - len( self.data )
        
        print( f"Cleaning complete: {rows_removed} rows removed, {len( self.data )} rows remaining" )
        return True
    
    # Export cleaned data to a new file
    def Export( self, out_file: str ) -> bool:
        try:
            with open( out_file, 'w', encoding='utf-8', newline='' ) as file:
                writer = csv.writer( file )
                writer.writerow( self.headers )
                writer.writerows( self.data )
            
            print( f"Data exported successfully to: {out_file}" )
            return True
            
        except Exception as e:
            print( f"Error exporting data: {e}" )
            return False
    
    # Get file size in human readable format
    def _GetSize( self ) -> str:
        try:
            size = os.path.getsize( self.filename )
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        except:
            return "Unknown"
    
    # Generate a summary report
    def GenReport( self ) -> str:
        if not self.data:
            return "No data available for report"
        
        report = f"""
CSV Analysis Report
Generated: {datetime.now().strftime( '%Y-%m-%d %H:%M:%S' )}
File: {self.filename}

Summary:
- Total rows: {len( self.data )}
- Total columns: {len( self.headers )}
- File size: {self._GetSize()}

Columns:
"""
        for i, header in enumerate( self.headers ):
            col_data = [row[i] if i < len( row ) else '' for row in self.data]
            non_empty = [val for val in col_data if val.strip()]
            data_type = self._GuessType( non_empty )
            report += f"  {i+1}. {header} ({data_type}) - {len( non_empty )} values\n"
        
        return report

# Print application banner
def ShowBanner():
    banner = """
    ==============================================================
                       CSV/Excel Analyzer                       
                      Author: Andrew Piggot                
    ==============================================================
    """
    print(banner)

# Print help information
def ShowHelp():
    help_text = """
    Commands:
    1. load <filename>          - Load a CSV file for analysis
    2. analyze                  - Analyze the loaded data
    3. clean                    - Clean data with interactive options
    4. export <filename>        - Export cleaned data to new file
    5. report                   - Generate analysis report
    6. help                     - Show this help information
    7. quit/exit                - Exit the program
    
    Supported formats:
    - CSV files with various delimiters (comma, semicolon, tab)
    - Files with headers in the first row
    
    Cleaning options include:
    - Remove empty rows
    - Trim whitespace
    - Remove special characters
    - Remove duplicate rows
    
    Examples:
    load data.csv
    analyze
    clean
    export cleaned_data.csv
    """
    print(help_text)

# Interactive cleaning options
def GetOptions() -> Dict[str, bool]:
    print( "\nSelect cleaning options (y/n):" )
    
    options = {}
    
    options['remove_empty_rows'] = input( "Remove completely empty rows? (y/n): " ).lower().startswith( 'y' )
    options['trim_whitespace'] = input( "Trim whitespace from cells? (y/n): " ).lower().startswith( 'y' )
    options['remove_special_chars'] = input( "Remove special characters? (y/n): " ).lower().startswith( 'y' )
    options['remove_duplicates'] = input( "Remove duplicate rows? (y/n): " ).lower().startswith( 'y' )
    
    return options

# Main application function
def main():
    ShowBanner()
    analyzer = CSVTool()
    
    print( "Welcome to the CSV/Excel Analyzer!" )
    print( "Type 'help' for usage information or 'quit' to exit.\n" )
    
    while True:
        try:
            user_input = input( "csv-analyzer> " ).strip()
            
            if not user_input:
                continue
            
            parts = user_input.split( ' ', 1 )
            command = parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                print( "Goodbye!" )
                break
                
            elif command == 'help':
                ShowHelp()
                
            elif command == 'load':
                if len( parts ) < 2:
                    print( "Usage: load <filename>" )
                    continue
                filename = parts[1]
                analyzer.Load( filename )
                
            elif command == 'analyze':
                analyzer.Analyze()
                
            elif command == 'clean':
                options = GetOptions()
                analyzer.Clean( options )
                
            elif command == 'export':
                if len( parts ) < 2:
                    print( "Usage: export <filename>" )
                    continue
                filename = parts[1]
                analyzer.Export( filename )
                
            elif command == 'report':
                report = analyzer.GenReport()
                print( report )
                
                # Ask if user wants to save report
                save = input( "Save report to file? (y/n): " ).lower().startswith( 'y' )
                if save:
                    report_file = f"report_{datetime.now().strftime( '%Y%m%d_%H%M%S' )}.txt"
                    with open( report_file, 'w' ) as f:
                        f.write( report )
                    print( f"Report saved to: {report_file}" )
                
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
            
        except KeyboardInterrupt:
            print( "\n\nGoodbye!" )
            break
        except Exception as e:
            print( f"Error: {e}" )

if __name__ == "__main__":
    main()
