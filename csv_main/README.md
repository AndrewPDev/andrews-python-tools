## 📊 CSV/Excel Analyzer and Cleaner

**File:** `csv_main/csv_analyzer.py`

A comprehensive data analysis and cleaning tool for CSV files that provides insights into your data and helps clean it up for better analysis.

### Features
- Load and analyze CSV files with automatic delimiter detection
- Column-wise data analysis with type detection
- Data quality assessment (duplicates, empty rows, inconsistencies)
- Interactive data cleaning options
- Export cleaned data to new files
- Generate detailed analysis reports
- Support for various CSV formats

### Analysis Capabilities
- **Basic Statistics:** Row/column counts, file size, data types
- **Column Analysis:** Empty values, unique values, sample data
- **Data Quality:** Duplicate detection, empty row identification, inconsistent formatting
- **Type Detection:** Automatic detection of numeric, date, and text columns

### Cleaning Options
- Remove completely empty rows
- Trim whitespace from all cells
- Remove special characters
- Remove duplicate rows
- Export cleaned data

### Installation & Usage
```bash
# Clone repository (if not already done)
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools

# Run the CSV analyzer
python csv_main/csv_analyzer.py
```

### Usage Examples
#### Basic Workflow
```
csv-analyzer> load csv_main/sample_data.csv
csv-analyzer> analyze
csv-analyzer> clean
csv-analyzer> export cleaned_data.csv
```

#### Sample CSV Data
A sample CSV file (`csv_main/sample_data.csv`) is included for testing the analyzer.

### Commands
| Command | Description |
|---------|-------------|
| `load <filename>` | Load a CSV file for analysis |
| `analyze` | Analyze the loaded data |
| `clean` | Clean data with interactive options |
| `export <filename>` | Export cleaned data to new file |
| `report` | Generate analysis report |
| `help` | Display usage information |
| `quit`, `exit` | Exit the program |