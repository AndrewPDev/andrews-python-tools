# Financial Tools

This directory contains tools for financial data analysis and investment portfolio optimization.

## Files

### Scripts
- `financial_analyzer.py` - Main financial analysis tool

### Sample Data Files
- `sample_portfolio.json` - Sample portfolio data in JSON format
- `sample_portfolio.csv` - Sample portfolio data in CSV format  
- `sample_stock.json` - Sample individual stock data
- `sample_crypto.json` - Sample cryptocurrency data

## Usage

Run the financial analyzer:
```bash
python financial_analyzer.py
```

Test with sample data:
```bash
# Analyze portfolio from JSON
python financial_analyzer.py
> portfolio sample_portfolio.json

# Analyze portfolio from CSV
python financial_analyzer.py
> portfolio sample_portfolio.csv

# Analyze individual stock
python financial_analyzer.py
> stock sample_stock.json

# Analyze cryptocurrency
python financial_analyzer.py
> crypto sample_crypto.json

# Generate sample data
python financial_analyzer.py
> generate portfolio
> generate stock
> generate crypto
```

## Analysis Types

### Portfolio Analysis
- Asset allocation analysis
- Diversification scoring
- Risk assessment
- Performance metrics
- Rebalancing recommendations

### Stock Analysis
- Valuation metrics (P/E, PEG ratios)
- Growth analysis
- Risk assessment
- Buy/sell recommendations

### Cryptocurrency Analysis
- Volatility analysis
- Market sentiment
- Liquidity assessment
- Risk warnings

## Data Formats

### Portfolio Data (JSON)
```json
{
  "holdings": [
    {
      "symbol": "AAPL",
      "value": 25000,
      "type": "stocks",
      "annual_return": 12.5,
      "volatility": 18.2
    }
  ]
}
```

### Portfolio Data (CSV)
```csv
symbol,name,type,value,annual_return,volatility,sector
AAPL,Apple Inc.,stocks,26370,12.8,18.5,Technology
```

### Stock Data (JSON)
```json
{
  "symbol": "AAPL",
  "current_price": 175.50,
  "pe_ratio": 28.5,
  "peg_ratio": 1.2,
  "dividend_yield": 0.52,
  "market_cap": 2800000000000,
  "beta": 1.15,
  "eps_growth": 8.5
}
```

### Cryptocurrency Data (JSON)
```json
{
  "symbol": "BTC",
  "current_price": 42500.00,
  "market_cap": 835000000000,
  "volume_24h": 25000000000,
  "price_change_24h": 2.5,
  "price_change_7d": -1.8,
  "volatility_30d": 65.2
}
```

## Requirements

No external dependencies required - uses Python standard library only.

## Scoring System

All analyses use a 0-10 scoring system:
- 8-10: Excellent
- 6-7: Good  
- 4-5: Fair
- 0-3: Poor

## Features

- Comprehensive financial analysis
- Risk assessment and scoring
- Performance metrics calculation
- Investment recommendations
- JSON export functionality
- Interactive command-line interface
- Multiple data format support
