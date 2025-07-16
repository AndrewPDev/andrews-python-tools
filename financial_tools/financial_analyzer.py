"""
Financial Data Analyzer

Author:
Andrew Piggot

Purpose: 
Analyze financial data, calculate investment metrics, and provide portfolio optimization recommendations

Usage: 
Investment analysis, portfolio management, financial planning, risk assessment
"""

import os
import sys
import json
import csv
import statistics
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from pathlib import Path
import re

# Main class for financial data analysis and portfolio optimization
class FinTool:
    
    def __init__( self ):
        self.portfolio_data = {}
        self.analysis_results = {}
        self.financial_score = 0
        self.risk_assessment = {}
        self.recommendations = []
        self.supported_formats = ['.csv', '.json', '.txt']
        self.analysis_types = ['portfolio', 'stock', 'crypto', 'bonds', 'mutual_funds']
        self.script_dir = Path( __file__ ).parent.absolute()
    
    # Analyze financial data from file or manual input
    def Analyze( self, source_type: str, source_path: str = None, data_type: str = 'portfolio' ) -> Dict:
        print( f"\nStarting financial analysis..." )
        print( "=" * 60 )
        
        try:
            if source_type.lower() == 'file':
                if not source_path:
                    return {'error': 'File path required for file analysis'}
                return self._AnalyzeFile( source_path, data_type )
            elif source_type.lower() == 'manual':
                return self._AnalyzeManual( data_type )
            elif source_type.lower() == 'generate':
                return self._GenSample( data_type )
            else:
                return {'error': f'Unsupported source type: {source_type}'}
                
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}'}
    
    # Analyze financial data from file
    def _AnalyzeFile( self, file_path: str, data_type: str ) -> Dict:
        # Convert relative paths to absolute paths relative to script directory
        if not os.path.isabs( file_path ):
            file_path = os.path.join( self.script_dir, file_path )
        
        if not os.path.exists( file_path ):
            return {'error': f'File not found: {file_path}'}
        
        file_extension = Path( file_path ).suffix.lower()
        if file_extension not in self.supported_formats:
            return {'error': f'Unsupported file format: {file_extension}'}
        
        print( f"Loading financial data from: {file_path}" )
        
        try:
            if file_extension == '.json':
                data = self._LoadJson( file_path )
            elif file_extension == '.csv':
                data = self._LoadCsv( file_path )
            else:
                data = self._LoadText( file_path )
            
            return self._ProcessData( data, data_type )
            
        except Exception as e:
            return {'error': f'Failed to load file: {str(e)}'}
    
    # Load JSON financial data
    def _LoadJson( self, file_path: str ) -> Dict:
        with open( file_path, 'r', encoding='utf-8' ) as file:
            return json.load( file )
    
    # Load CSV financial data
    def _LoadCsv( self, file_path: str ) -> List[Dict]:
        data = []
        with open( file_path, 'r', encoding='utf-8' ) as file:
            csv_reader = csv.DictReader( file )
            for row in csv_reader:
                data.append( row )
        return data
    
    # Load text financial data
    def _LoadText( self, file_path: str ) -> List[str]:
        with open( file_path, 'r', encoding='utf-8' ) as file:
            return file.readlines()
    
    # Process and analyze financial data
    def _ProcessData( self, data: Any, data_type: str ) -> Dict:
        print( f"Processing {data_type} data..." )
        
        if data_type == 'portfolio':
            return self._AnalyzePortfolio( data )
        elif data_type == 'stock':
            return self._AnalyzeStock( data )
        elif data_type == 'crypto':
            return self._AnalyzeCrypto( data )
        elif data_type == 'bonds':
            return self._AnalyzeBonds( data )
        elif data_type == 'mutual_funds':
            return self._AnalyzeFunds( data )
        else:
            return {'error': f'Unsupported data type: {data_type}'}
    
    # Analyze portfolio data
    def _AnalyzePortfolio( self, data: Any ) -> Dict:
        results = {
            'analysis_type': 'Portfolio Analysis',
            'timestamp': datetime.now().isoformat(),
            'portfolio_metrics': {},
            'asset_allocation': {},
            'risk_metrics': {},
            'performance_metrics': {},
            'diversification_score': 0,
            'risk_score': 0,
            'overall_score': 0,
            'recommendations': []
        }
        
        if isinstance( data, dict ) and 'holdings' in data:
            holdings = data['holdings']
        elif isinstance( data, list ):
            holdings = data
        else:
            return {'error': 'Invalid portfolio data format'}
        
        total_value = 0
        asset_types = {}
        returns = []
        volatilities = []
        
        for holding in holdings:
            if isinstance( holding, dict ):
                symbol = holding.get( 'symbol', 'Unknown' )
                value = float( holding.get( 'value', 0 ) )
                asset_type = holding.get( 'type', 'Unknown' )
                annual_return = float( holding.get( 'annual_return', 0 ) )
                volatility = float( holding.get( 'volatility', 0 ) )
                
                total_value += value
                
                if asset_type not in asset_types:
                    asset_types[asset_type] = 0
                asset_types[asset_type] += value
                
                returns.append( annual_return )
                volatilities.append( volatility )
        
        # Calculate asset allocation percentages
        for asset_type in asset_types:
            asset_types[asset_type] = round( (asset_types[asset_type] / total_value) * 100, 2 )
        
        # Calculate portfolio metrics
        avg_return = statistics.mean( returns ) if returns else 0
        portfolio_volatility = statistics.mean( volatilities ) if volatilities else 0
        sharpe_ratio = (avg_return - 2.0) / portfolio_volatility if portfolio_volatility > 0 else 0
        
        # Calculate diversification score
        diversification_score = self._CalcDiversification( asset_types )
        
        # Calculate risk score
        risk_score = self._CalcRisk( portfolio_volatility, asset_types )
        
        # Calculate overall score
        overall_score = self._CalcOverallScore( avg_return, diversification_score, risk_score, sharpe_ratio )
        
        results['portfolio_metrics'] = {
            'total_value': f"${total_value:,.2f}",
            'number_of_holdings': len( holdings ),
            'average_annual_return': f"{avg_return:.2f}%",
            'portfolio_volatility': f"{portfolio_volatility:.2f}%",
            'sharpe_ratio': f"{sharpe_ratio:.2f}"
        }
        
        results['asset_allocation'] = asset_types
        results['diversification_score'] = diversification_score
        results['risk_score'] = risk_score
        results['overall_score'] = overall_score
        
        # Generate recommendations
        results['recommendations'] = self._GenPortfolioRecs( asset_types, diversification_score, risk_score, avg_return )
        
        return results
    
    # Analyze individual stock data
    def _AnalyzeStock( self, data: Any ) -> Dict:
        results = {
            'analysis_type': 'Stock Analysis',
            'timestamp': datetime.now().isoformat(),
            'stock_metrics': {},
            'valuation_metrics': {},
            'risk_assessment': {},
            'price_analysis': {},
            'overall_score': 0,
            'recommendations': []
        }
        
        if isinstance( data, dict ):
            stock_data = data
        else:
            return {'error': 'Invalid stock data format'}
        
        symbol = stock_data.get( 'symbol', 'Unknown' )
        current_price = float( stock_data.get( 'current_price', 0 ) )
        pe_ratio = float( stock_data.get( 'pe_ratio', 0 ) )
        peg_ratio = float( stock_data.get( 'peg_ratio', 0 ) )
        dividend_yield = float( stock_data.get( 'dividend_yield', 0 ) )
        market_cap = float( stock_data.get( 'market_cap', 0 ) )
        beta = float( stock_data.get( 'beta', 1.0 ) )
        eps_growth = float( stock_data.get( 'eps_growth', 0 ) )
        
        # Calculate valuation score
        valuation_score = self._CalcValuation( pe_ratio, peg_ratio, dividend_yield )
        
        # Calculate risk score
        risk_score = self._CalcStockRisk( beta, market_cap )
        
        # Calculate growth score
        growth_score = self._CalcGrowth( eps_growth, peg_ratio )
        
        # Calculate overall score
        overall_score = round( (valuation_score + (10 - risk_score) + growth_score) / 3, 1 )
        
        results['stock_metrics'] = {
            'symbol': symbol,
            'current_price': f"${current_price:.2f}",
            'market_cap': f"${market_cap:,.0f}",
            'pe_ratio': f"{pe_ratio:.2f}",
            'peg_ratio': f"{peg_ratio:.2f}",
            'dividend_yield': f"{dividend_yield:.2f}%",
            'beta': f"{beta:.2f}",
            'eps_growth': f"{eps_growth:.2f}%"
        }
        
        results['valuation_metrics'] = {
            'valuation_score': valuation_score,
            'risk_score': risk_score,
            'growth_score': growth_score
        }
        
        results['overall_score'] = overall_score
        
        # Generate recommendations
        results['recommendations'] = self._GenStockRecs( valuation_score, risk_score, growth_score )
        
        return results
    
    # Analyze cryptocurrency data
    def _AnalyzeCrypto( self, data: Any ) -> Dict:
        results = {
            'analysis_type': 'Cryptocurrency Analysis',
            'timestamp': datetime.now().isoformat(),
            'crypto_metrics': {},
            'volatility_analysis': {},
            'market_metrics': {},
            'risk_assessment': {},
            'overall_score': 0,
            'recommendations': []
        }
        
        if isinstance( data, dict ):
            crypto_data = data
        else:
            return {'error': 'Invalid cryptocurrency data format'}
        
        symbol = crypto_data.get( 'symbol', 'Unknown' )
        current_price = float( crypto_data.get( 'current_price', 0 ) )
        market_cap = float( crypto_data.get( 'market_cap', 0 ) )
        volume_24h = float( crypto_data.get( 'volume_24h', 0 ) )
        price_change_24h = float( crypto_data.get( 'price_change_24h', 0 ) )
        price_change_7d = float( crypto_data.get( 'price_change_7d', 0 ) )
        volatility_30d = float( crypto_data.get( 'volatility_30d', 0 ) )
        
        # Calculate stability score
        stability_score = self._CalcStability( volatility_30d, price_change_7d )
        
        # Calculate liquidity score
        liquidity_score = self._CalcLiquidity( volume_24h, market_cap )
        
        # Calculate trend score
        trend_score = self._CalcTrend( price_change_24h, price_change_7d )
        
        # Calculate overall score
        overall_score = round( (stability_score + liquidity_score + trend_score) / 3, 1 )
        
        results['crypto_metrics'] = {
            'symbol': symbol,
            'current_price': f"${current_price:.4f}",
            'market_cap': f"${market_cap:,.0f}",
            'volume_24h': f"${volume_24h:,.0f}",
            'price_change_24h': f"{price_change_24h:.2f}%",
            'price_change_7d': f"{price_change_7d:.2f}%",
            'volatility_30d': f"{volatility_30d:.2f}%"
        }
        
        results['volatility_analysis'] = {
            'stability_score': stability_score,
            'liquidity_score': liquidity_score,
            'trend_score': trend_score
        }
        
        results['overall_score'] = overall_score
        
        # Generate recommendations
        results['recommendations'] = self._GenCryptoRecs( stability_score, liquidity_score, trend_score )
        
        return results
    
    # Analyze bonds data
    def _AnalyzeBonds( self, data: Any ) -> Dict:
        results = {
            'analysis_type': 'Bonds Analysis',
            'timestamp': datetime.now().isoformat(),
            'bond_metrics': {},
            'yield_analysis': {},
            'credit_assessment': {},
            'duration_risk': {},
            'overall_score': 0,
            'recommendations': []
        }
        
        # Implementation for bonds analysis
        results['recommendations'] = ['Bond analysis feature under development']
        results['overall_score'] = 5.0
        
        return results
    
    # Analyze mutual funds data
    def _AnalyzeFunds( self, data: Any ) -> Dict:
        results = {
            'analysis_type': 'Mutual Funds Analysis',
            'timestamp': datetime.now().isoformat(),
            'fund_metrics': {},
            'performance_analysis': {},
            'expense_analysis': {},
            'risk_metrics': {},
            'overall_score': 0,
            'recommendations': []
        }
        
        # Implementation for mutual funds analysis
        results['recommendations'] = ['Mutual funds analysis feature under development']
        results['overall_score'] = 5.0
        
        return results
    
    # Calculate diversification score based on asset allocation
    def _CalcDiversification( self, asset_types: Dict ) -> float:
        if not asset_types:
            return 0
        
        # Ideal allocation weights
        ideal_allocation = {
            'stocks': 60,
            'bonds': 30,
            'cash': 5,
            'commodities': 3,
            'real_estate': 2
        }
        
        score = 10
        for asset_type, percentage in asset_types.items():
            if asset_type.lower() in ideal_allocation:
                ideal = ideal_allocation[asset_type.lower()]
                deviation = abs( percentage - ideal )
                score -= (deviation / 10)
        
        return max( 0, min( 10, score ) )
    
    # Calculate risk score based on volatility and allocation
    def _CalcRisk( self, volatility: float, asset_types: Dict ) -> float:
        base_risk = min( volatility / 2, 10 )
        
        # Adjust based on asset allocation
        high_risk_assets = asset_types.get( 'crypto', 0 ) + asset_types.get( 'growth_stocks', 0 )
        if high_risk_assets > 30:
            base_risk += 2
        
        return min( 10, base_risk )
    
    # Calculate overall portfolio score
    def _CalcOverallScore( self, avg_return: float, diversification_score: float, risk_score: float, sharpe_ratio: float ) -> float:
        return_score = min( avg_return / 2, 10 )
        risk_adjusted_score = max( 0, 10 - risk_score )
        sharpe_score = min( sharpe_ratio * 2, 10 )
        
        overall = (return_score + diversification_score + risk_adjusted_score + sharpe_score) / 4
        return round( overall, 1 )
    
    # Calculate stock valuation score
    def _CalcValuation( self, pe_ratio: float, peg_ratio: float, dividend_yield: float ) -> float:
        score = 5
        
        # PE ratio scoring
        if pe_ratio < 15:
            score += 2
        elif pe_ratio < 25:
            score += 1
        elif pe_ratio > 40:
            score -= 2
        
        # PEG ratio scoring
        if peg_ratio < 1:
            score += 2
        elif peg_ratio < 1.5:
            score += 1
        elif peg_ratio > 2:
            score -= 1
        
        # Dividend yield scoring
        if dividend_yield > 3:
            score += 1
        
        return max( 0, min( 10, score ) )
    
    # Calculate stock risk score
    def _CalcStockRisk( self, beta: float, market_cap: float ) -> float:
        risk_score = 5
        
        # Beta risk
        if beta > 1.5:
            risk_score += 3
        elif beta > 1.2:
            risk_score += 1
        elif beta < 0.8:
            risk_score -= 1
        
        # Market cap risk
        if market_cap < 1000000000:  # Small cap
            risk_score += 2
        elif market_cap > 50000000000:  # Large cap
            risk_score -= 1
        
        return max( 0, min( 10, risk_score ) )
    
    # Calculate growth score
    def _CalcGrowth( self, eps_growth: float, peg_ratio: float ) -> float:
        score = 5
        
        if eps_growth > 20:
            score += 3
        elif eps_growth > 10:
            score += 2
        elif eps_growth > 5:
            score += 1
        elif eps_growth < 0:
            score -= 2
        
        if peg_ratio < 1:
            score += 1
        
        return max( 0, min( 10, score ) )
    
    # Calculate cryptocurrency stability score
    def _CalcStability( self, volatility_30d: float, price_change_7d: float ) -> float:
        stability = 10 - min( volatility_30d / 10, 8 )
        if abs( price_change_7d ) > 20:
            stability -= 2
        return max( 0, stability )
    
    # Calculate liquidity score
    def _CalcLiquidity( self, volume_24h: float, market_cap: float ) -> float:
        if market_cap == 0:
            return 0
        volume_ratio = volume_24h / market_cap
        return min( volume_ratio * 100, 10 )
    
    # Calculate trend score
    def _CalcTrend( self, price_change_24h: float, price_change_7d: float ) -> float:
        score = 5
        if price_change_24h > 0 and price_change_7d > 0:
            score += 3
        elif price_change_24h > 0 or price_change_7d > 0:
            score += 1
        elif price_change_24h < -5 and price_change_7d < -10:
            score -= 3
        return max( 0, min( 10, score ) )
    
    # Generate portfolio recommendations
    def _GenPortfolioRecs( self, asset_types: Dict, diversification_score: float, risk_score: float, avg_return: float ) -> List[str]:
        recommendations = []
        
        if diversification_score < 6:
            recommendations.append( "Consider diversifying across more asset classes for better risk management" )
        
        if risk_score > 7:
            recommendations.append( "Portfolio has high risk - consider adding more stable assets like bonds" )
        
        if avg_return < 5:
            recommendations.append( "Portfolio returns are below market average - review underperforming assets" )
        
        stocks_allocation = asset_types.get( 'stocks', 0 )
        if stocks_allocation < 40:
            recommendations.append( "Consider increasing stock allocation for better long-term growth" )
        elif stocks_allocation > 80:
            recommendations.append( "Stock allocation is high - consider adding bonds for stability" )
        
        if not recommendations:
            recommendations.append( "Portfolio is well-balanced - continue regular monitoring and rebalancing" )
        
        return recommendations
    
    # Generate stock recommendations
    def _GenStockRecs( self, valuation_score: float, risk_score: float, growth_score: float ) -> List[str]:
        recommendations = []
        
        if valuation_score > 7:
            recommendations.append( "Stock appears undervalued - good buying opportunity" )
        elif valuation_score < 4:
            recommendations.append( "Stock may be overvalued - consider waiting for better entry point" )
        
        if risk_score > 7:
            recommendations.append( "High-risk stock - suitable only for aggressive investors" )
        elif risk_score < 4:
            recommendations.append( "Low-risk stock - good for conservative portfolios" )
        
        if growth_score > 7:
            recommendations.append( "Strong growth potential - good for growth-oriented portfolios" )
        elif growth_score < 4:
            recommendations.append( "Limited growth prospects - focus on dividend income if available" )
        
        return recommendations
    
    # Generate cryptocurrency recommendations
    def _GenCryptoRecs( self, stability_score: float, liquidity_score: float, trend_score: float ) -> List[str]:
        recommendations = []
        
        if stability_score < 4:
            recommendations.append( "High volatility - only invest what you can afford to lose" )
        
        if liquidity_score < 4:
            recommendations.append( "Low liquidity - may be difficult to sell quickly" )
        
        if trend_score > 7:
            recommendations.append( "Positive price momentum - monitor for continuation" )
        elif trend_score < 4:
            recommendations.append( "Negative price trend - consider waiting for reversal" )
        
        recommendations.append( "Cryptocurrency investments are highly speculative - limit to 5-10% of portfolio" )
        
        return recommendations
    
    # Manual input for analysis
    def _AnalyzeManual( self, data_type: str ) -> Dict:
        print( f"\nManual {data_type} data input mode" )
        print( "Enter financial data (type 'done' when finished):" )
        
        # Implementation for manual input would go here
        return {'error': 'Manual input mode not yet implemented'}
    
    # Generate sample financial data for testing
    def _GenSample( self, data_type: str ) -> Dict:
        print( f"Generating sample {data_type} data..." )
        
        if data_type == 'portfolio':
            sample_data = {
                'holdings': [
                    {'symbol': 'AAPL', 'value': 25000, 'type': 'stocks', 'annual_return': 12.5, 'volatility': 18.2},
                    {'symbol': 'MSFT', 'value': 20000, 'type': 'stocks', 'annual_return': 15.2, 'volatility': 16.8},
                    {'symbol': 'BND', 'value': 15000, 'type': 'bonds', 'annual_return': 3.8, 'volatility': 4.2},
                    {'symbol': 'VTI', 'value': 18000, 'type': 'stocks', 'annual_return': 10.8, 'volatility': 15.5},
                    {'symbol': 'CASH', 'value': 5000, 'type': 'cash', 'annual_return': 1.5, 'volatility': 0.1}
                ]
            }
        elif data_type == 'stock':
            sample_data = {
                'symbol': 'AAPL',
                'current_price': 175.50,
                'pe_ratio': 28.5,
                'peg_ratio': 1.2,
                'dividend_yield': 0.52,
                'market_cap': 2800000000000,
                'beta': 1.15,
                'eps_growth': 8.5
            }
        elif data_type == 'crypto':
            sample_data = {
                'symbol': 'BTC',
                'current_price': 42500.00,
                'market_cap': 835000000000,
                'volume_24h': 25000000000,
                'price_change_24h': 2.5,
                'price_change_7d': -1.8,
                'volatility_30d': 65.2
            }
        else:
            return {'error': f'Sample data not available for {data_type}'}
        
        return self._ProcessData( sample_data, data_type )
    
    # Display analysis results in a formatted way
    def ShowResults( self, results: Dict ):
        if 'error' in results:
            print( f"\nError: {results['error']}" )
            return
        
        print( f"\n{'='*60}" )
        print( f"FINANCIAL ANALYSIS REPORT" )
        print( f"{'='*60}" )
        print( f"Analysis Type: {results.get('analysis_type', 'Unknown')}" )
        print( f"Overall Score: {results.get('overall_score', 0)}/10 {self._GetRating(results.get('overall_score', 0))}" )
        print( f"{'='*60}" )
        
        analysis_type = results.get( 'analysis_type', '' )
        
        if 'Portfolio' in analysis_type:
            self._ShowPortfolio( results )
        elif 'Stock' in analysis_type:
            self._ShowStock( results )
        elif 'Cryptocurrency' in analysis_type:
            self._ShowCrypto( results )
        
        # Display recommendations
        recommendations = results.get( 'recommendations', [] )
        if recommendations:
            print( f"\nRECOMMENDATIONS" )
            for i, rec in enumerate( recommendations, 1 ):
                print( f"   {i}. {rec}" )
        
        print( f"\n{'='*60}" )
    
    # Display portfolio analysis results
    def _ShowPortfolio( self, results: Dict ):
        metrics = results.get( 'portfolio_metrics', {} )
        allocation = results.get( 'asset_allocation', {} )
        
        print( f"\nPORTFOLIO METRICS" )
        print( f"Total Value: {metrics.get('total_value', 'N/A')}" )
        print( f"Number of Holdings: {metrics.get('number_of_holdings', 'N/A')}" )
        print( f"Average Annual Return: {metrics.get('average_annual_return', 'N/A')}" )
        print( f"Portfolio Volatility: {metrics.get('portfolio_volatility', 'N/A')}" )
        print( f"Sharpe Ratio: {metrics.get('sharpe_ratio', 'N/A')}" )
        
        print( f"\nASSET ALLOCATION" )
        for asset_type, percentage in allocation.items():
            print( f"{asset_type.title()}: {percentage}%" )
        
        print( f"\nSCORES" )
        print( f"Diversification Score: {results.get('diversification_score', 0):.1f}/10" )
        print( f"Risk Score: {results.get('risk_score', 0):.1f}/10" )
    
    # Display stock analysis results
    def _ShowStock( self, results: Dict ):
        metrics = results.get( 'stock_metrics', {} )
        valuation = results.get( 'valuation_metrics', {} )
        
        print( f"\nSTOCK METRICS" )
        print( f"Symbol: {metrics.get('symbol', 'N/A')}" )
        print( f"Current Price: {metrics.get('current_price', 'N/A')}" )
        print( f"Market Cap: {metrics.get('market_cap', 'N/A')}" )
        print( f"P/E Ratio: {metrics.get('pe_ratio', 'N/A')}" )
        print( f"PEG Ratio: {metrics.get('peg_ratio', 'N/A')}" )
        print( f"Dividend Yield: {metrics.get('dividend_yield', 'N/A')}" )
        print( f"Beta: {metrics.get('beta', 'N/A')}" )
        print( f"EPS Growth: {metrics.get('eps_growth', 'N/A')}" )
        
        print( f"\nVALUATION SCORES" )
        print( f"Valuation Score: {valuation.get('valuation_score', 0):.1f}/10" )
        print( f"Risk Score: {valuation.get('risk_score', 0):.1f}/10" )
        print( f"Growth Score: {valuation.get('growth_score', 0):.1f}/10" )
    
    # Display cryptocurrency analysis results
    def _ShowCrypto( self, results: Dict ):
        metrics = results.get( 'crypto_metrics', {} )
        volatility = results.get( 'volatility_analysis', {} )
        
        print( f"\nCRYPTOCURRENCY METRICS" )
        print( f"Symbol: {metrics.get('symbol', 'N/A')}" )
        print( f"Current Price: {metrics.get('current_price', 'N/A')}" )
        print( f"Market Cap: {metrics.get('market_cap', 'N/A')}" )
        print( f"24h Volume: {metrics.get('volume_24h', 'N/A')}" )
        print( f"24h Change: {metrics.get('price_change_24h', 'N/A')}" )
        print( f"7d Change: {metrics.get('price_change_7d', 'N/A')}" )
        print( f"30d Volatility: {metrics.get('volatility_30d', 'N/A')}" )
        
        print( f"\nANALYSIS SCORES" )
        print( f"Stability Score: {volatility.get('stability_score', 0):.1f}/10" )
        print( f"Liquidity Score: {volatility.get('liquidity_score', 0):.1f}/10" )
        print( f"Trend Score: {volatility.get('trend_score', 0):.1f}/10" )
    
    # Get rating description for score
    def _GetRating( self, score: float ) -> str:
        if score >= 8:
            return "(Excellent)"
        elif score >= 6:
            return "(Good)"
        elif score >= 4:
            return "(Fair)"
        else:
            return "(Poor)"
    
    # Export results to JSON file
    def Export( self, results: Dict, filename: str ):
        try:
            # Convert relative paths to absolute paths relative to current working directory
            if not os.path.isabs( filename ):
                filename = os.path.abspath( filename )
            
            with open( filename, 'w', encoding='utf-8' ) as file:
                json.dump( results, file, indent=2, ensure_ascii=False )
            print( f"\nResults exported to: {filename}" )
        except Exception as e:
            print( f"\nError exporting results: {str(e)}" )
    
    # Display help information
    def ShowHelp( self ):
        print( f"\n{'='*60}" )
        print( f"FINANCIAL DATA ANALYZER - HELP" )
        print( f"{'='*60}" )
        print( f"Commands:" )
        print( f"  portfolio <file>     - Analyze portfolio from file" )
        print( f"  stock <file>         - Analyze individual stock" )
        print( f"  crypto <file>        - Analyze cryptocurrency" )
        print( f"  generate portfolio   - Generate sample portfolio data" )
        print( f"  generate stock       - Generate sample stock data" )
        print( f"  generate crypto      - Generate sample crypto data" )
        print( f"  export <filename>    - Export last analysis to JSON" )
        print( f"  help                 - Show this help message" )
        print( f"  quit, exit           - Exit the program" )
        print( f"\nSupported file formats: .json, .csv, .txt" )
        print( f"Analysis types: portfolio, stock, crypto, bonds, mutual_funds" )
        print( f"\nExample usage:" )
        print( f"  portfolio sample_portfolio.json" )
        print( f"  stock sample_stock.json" )
        print( f"  crypto sample_crypto.json" )
        print( f"  generate portfolio" )
        print( f"\nNote: Sample files are included with the script." )
        print( f"You can also use absolute or relative paths to your own data files." )
        print( f"{'='*60}" )

# Main function to run the financial analyzer
def Main():
    analyzer = FinTool()
    last_results = None
    
    print( "Financial Data Analyzer - Investment Analysis Tool" )
    print( "Type 'help' for commands or 'quit' to exit" )
    
    while True:
        try:
            user_input = input( "\nfinancial-analyzer> " ).strip()
            
            if not user_input:
                continue
            
            command_parts = user_input.split()
            command = command_parts[0].lower()
            
            if command in ['quit', 'exit', 'q']:
                print( "Thank you for using Financial Data Analyzer!" )
                break
            
            elif command == 'help':
                analyzer.ShowHelp()
            
            elif command in ['portfolio', 'stock', 'crypto', 'bonds', 'mutual_funds']:
                if len( command_parts ) > 1:
                    file_path = command_parts[1]
                    results = analyzer.Analyze( 'file', file_path, command )
                else:
                    print( f"Usage: {command} <file_path>" )
                    continue
                
                analyzer.ShowResults( results )
                last_results = results
            
            elif command == 'generate':
                if len( command_parts ) > 1:
                    data_type = command_parts[1]
                    results = analyzer.Analyze( 'generate', None, data_type )
                    analyzer.ShowResults( results )
                    last_results = results
                else:
                    print( "Usage: generate <portfolio|stock|crypto>" )
            
            elif command == 'export':
                if last_results and len( command_parts ) > 1:
                    filename = command_parts[1]
                    analyzer.Export( last_results, filename )
                else:
                    print( "Usage: export <filename.json> (analyze something first)" )
            
            else:
                print( f"Unknown command: {command}" )
                print( "Type 'help' for available commands" )
        
        except KeyboardInterrupt:
            print( "\n\nExiting Financial Data Analyzer..." )
            break
        except Exception as e:
            print( f"\nError: {str(e)}" )

if __name__ == "__main__":
    Main()
