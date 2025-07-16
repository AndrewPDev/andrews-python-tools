"""
SEO Website Analyzer Tool

Author:
Andrew Piggot

Purpose: 
Analyze websites for SEO optimization opportunities and issues

Usage: 
Website optimization, SEO auditing, content analysis
"""

import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser
from typing import List, Dict, Tuple, Optional
import json

# Custom HTML parser to extract SEO-relevant data from web pages
class SEOParser( HTMLParser ):
    
    def __init__( self ):
        super().__init__()
        self.title = ""
        self.meta_description = ""
        self.meta_keywords = ""
        self.headings = {'h1': [], 'h2': [], 'h3': [], 'h4': [], 'h5': [], 'h6': []}
        self.images = []
        self.links = {'internal': [], 'external': []}
        self.current_tag = None
        self.base_url = ""
        self.meta_tags = {}
        
    # Handle start tags and extract relevant attributes
    def handle_starttag( self, tag, attrs ):
        self.current_tag = tag
        attrs_dict = dict( attrs )
        
        if tag == 'title':
            pass
            
        elif tag == 'meta':
            name = attrs_dict.get( 'name', '' ).lower()
            content = attrs_dict.get( 'content', '' )
            
            if name == 'description':
                self.meta_description = content
            elif name == 'keywords':
                self.meta_keywords = content
            elif name:
                self.meta_tags[name] = content
                
        elif tag in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            pass
            
        elif tag == 'img':
            alt_text = attrs_dict.get( 'alt', '' )
            src = attrs_dict.get( 'src', '' )
            self.images.append( {
                'src': src,
                'alt': alt_text,
                'has_alt': bool( alt_text.strip() )
            } )
            
        elif tag == 'a':
            href = attrs_dict.get( 'href', '' )
            if href:
                if href.startswith( 'http' ):
                    if self.base_url and self.base_url in href:
                        self.links['internal'].append( href )
                    else:
                        self.links['external'].append( href )
                elif href.startswith( '/' ) or not href.startswith( '#' ):
                    self.links['internal'].append( href )
    
    # Handle text data within tags
    def handle_data( self, data ):
        if self.current_tag == 'title':
            self.title += data.strip()
        elif self.current_tag in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            if data.strip():
                self.headings[self.current_tag].append( data.strip() )
    
    # Handle end tags
    def handle_endtag( self, tag ):
        self.current_tag = None

# Main SEO analysis class for website optimization auditing
class SEOTool:
    
    def __init__( self ):
        self.results = {}
        self.recommendations = []
        self.score = 0
        
    # Analyze a website for SEO issues and opportunities
    def Analyze( self, url: str ) -> Dict:
        print( f"\nStarting SEO analysis for: {url}" )
        print( "=" * 60 )
        
        try:
            html_content, status_code = self._Fetch( url )
            if not html_content:
                return {'error': f'Could not fetch webpage. Status code: {status_code}'}
            
            parser = SEOParser()
            parser.base_url = self._GetBaseUrl( url )
            parser.feed( html_content )
            
            self.results = {
                'url': url,
                'title_analysis': self._AnalyzeTitle( parser.title ),
                'meta_analysis': self._AnalyzeMeta( parser.meta_description ),
                'heading_analysis': self._AnalyzeHeadings( parser.headings ),
                'image_analysis': self._AnalyzeImages( parser.images ),
                'link_analysis': self._AnalyzeLinks( parser.links ),
                'content_analysis': self._AnalyzeContent( html_content ),
                'technical_analysis': self._AnalyzeTech( url, html_content ),
                'meta_tags': parser.meta_tags
            }
            
            self._CalcScore()
            
            return self.results
            
        except Exception as e:
            return {'error': f'Analysis failed: {str( e )}'}
    
    # Fetch webpage content with proper headers
    def _Fetch( self, url: str ) -> Tuple[Optional[str], int]:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            req = urllib.request.Request( url, headers=headers )
            with urllib.request.urlopen( req, timeout=10 ) as response:
                return response.read().decode( 'utf-8', errors='ignore' ), response.status
                
        except urllib.error.HTTPError as e:
            return None, e.code
        except urllib.error.URLError:
            return None, 0
        except Exception:
            return None, 0
    
    # Extract base URL from full URL
    def _GetBaseUrl( self, url: str ) -> str:
        parsed = urllib.parse.urlparse( url )
        return f"{parsed.scheme}://{parsed.netloc}"
    
    # Analyze page title for SEO optimization
    def _AnalyzeTitle( self, title: str ) -> Dict:
        analysis = {
            'title': title,
            'length': len( title ),
            'issues': [],
            'score': 0
        }
        
        if not title:
            analysis['issues'].append( "No title tag found - critical SEO issue!" )
            analysis['score'] = 0
        elif len( title ) < 30:
            analysis['issues'].append( "Title is too short (less than 30 characters)" )
            analysis['score'] = 3
        elif len( title ) > 60:
            analysis['issues'].append( "Title is too long (over 60 characters) - may be truncated in search results" )
            analysis['score'] = 6
        else:
            analysis['issues'].append( "Title length is optimal (30-60 characters)" )
            analysis['score'] = 10
        
        if title and title == title.upper():
            analysis['issues'].append( "Title is in ALL CAPS - not recommended" )
        
        if title and '|' not in title and '-' not in title and ':' not in title:
            analysis['issues'].append( "Consider adding brand/site name separator (| or -)" )
        
        return analysis
    
    # Analyze meta description for SEO optimization
    def _AnalyzeMeta( self, description: str ) -> Dict:
        analysis = {
            'description': description,
            'length': len( description ),
            'issues': [],
            'score': 0
        }
        
        if not description:
            analysis['issues'].append( "No meta description found - missing opportunity!" )
            analysis['score'] = 0
        elif len( description ) < 120:
            analysis['issues'].append( "Meta description is too short (less than 120 characters)" )
            analysis['score'] = 4
        elif len( description ) > 160:
            analysis['issues'].append( "Meta description is too long (over 160 characters) - may be truncated" )
            analysis['score'] = 6
        else:
            analysis['issues'].append( "Meta description length is optimal (120-160 characters)" )
            analysis['score'] = 10
        
        return analysis
    
    # Analyze heading structure for SEO
    def _AnalyzeHeadings( self, headings: Dict ) -> Dict:
        analysis = {
            'headings': headings,
            'issues': [],
            'score': 0
        }
        
        h1_count = len( headings['h1'] )
        
        if h1_count == 0:
            analysis['issues'].append( "No H1 tag found - critical for SEO!" )
            analysis['score'] = 0
        elif h1_count == 1:
            analysis['issues'].append( "Exactly one H1 tag found - perfect!" )
            analysis['score'] = 10
        else:
            analysis['issues'].append( f"Multiple H1 tags found ({h1_count}) - should be only one" )
            analysis['score'] = 5
        
        total_headings = sum( len( h ) for h in headings.values() )
        if total_headings == 0:
            analysis['issues'].append( "No heading tags found" )
        elif total_headings < 3:
            analysis['issues'].append( "Very few headings - consider adding more structure" )
        else:
            analysis['issues'].append( f"Good heading structure ({total_headings} total headings)" )
        
        return analysis
    
    # Analyze images for SEO optimization
    def _AnalyzeImages( self, images: List[Dict] ) -> Dict:
        analysis = {
            'total_images': len( images ),
            'images_with_alt': sum( 1 for img in images if img['has_alt'] ),
            'images_without_alt': sum( 1 for img in images if not img['has_alt'] ),
            'issues': [],
            'score': 0
        }
        
        if not images:
            analysis['issues'].append( "No images found on page" )
            analysis['score'] = 5
        else:
            missing_alt = analysis['images_without_alt']
            if missing_alt == 0:
                analysis['issues'].append( "All images have alt text - excellent!" )
                analysis['score'] = 10
            elif missing_alt <= len( images ) * 0.2:
                analysis['issues'].append( f"{missing_alt} images missing alt text - mostly good" )
                analysis['score'] = 7
            else:
                analysis['issues'].append( f"{missing_alt} images missing alt text - needs improvement" )
                analysis['score'] = 3
        
        return analysis
    
    # Analyze internal and external links
    def _AnalyzeLinks( self, links: Dict ) -> Dict:
        analysis = {
            'internal_links': len( links['internal'] ),
            'external_links': len( links['external'] ),
            'issues': [],
            'score': 0
        }
        
        internal_count = analysis['internal_links']
        external_count = analysis['external_links']
        
        if internal_count == 0:
            analysis['issues'].append( "No internal links found - consider adding navigation" )
            analysis['score'] = 3
        elif internal_count < 3:
            analysis['issues'].append( "Very few internal links - consider adding more" )
            analysis['score'] = 5
        else:
            analysis['issues'].append( f"Good internal linking ({internal_count} links)" )
            analysis['score'] = 8
        
        if external_count > internal_count * 2:
            analysis['issues'].append( "Many external links - ensure they're relevant and valuable" )
        
        return analysis
    
    # Analyze content for SEO factors
    def _AnalyzeContent( self, html_content: str ) -> Dict:
        text_content = re.sub( r'<[^>]+>', ' ', html_content )
        text_content = re.sub( r'\s+', ' ', text_content ).strip()
        
        word_count = len( text_content.split() )
        
        analysis = {
            'word_count': word_count,
            'character_count': len( text_content ),
            'issues': [],
            'score': 0
        }
        
        if word_count < 300:
            analysis['issues'].append( "Content is quite short (under 300 words) - consider adding more" )
            analysis['score'] = 4
        elif word_count < 600:
            analysis['issues'].append( "Content length is okay but could be expanded (300-600 words)" )
            analysis['score'] = 6
        else:
            analysis['issues'].append( f"Good content length ({word_count} words)" )
            analysis['score'] = 9
        
        return analysis
    
    # Analyze technical SEO factors
    def _AnalyzeTech( self, url: str, html_content: str ) -> Dict:
        analysis = {
            'https': url.startswith( 'https://' ),
            'issues': [],
            'score': 0
        }
        
        if analysis['https']:
            analysis['issues'].append( "Site uses HTTPS - good for security and SEO" )
            analysis['score'] += 5
        else:
            analysis['issues'].append( "Site doesn't use HTTPS - security and SEO concern" )
        
        if 'schema.org' in html_content or 'application/ld+json' in html_content:
            analysis['issues'].append( "Schema markup detected - excellent for rich snippets" )
            analysis['score'] += 3
        else:
            analysis['issues'].append( "No schema markup detected - consider adding structured data" )
        
        page_size_kb = len( html_content.encode( 'utf-8' ) ) / 1024
        if page_size_kb > 1000:
            analysis['issues'].append( f"Large page size ({page_size_kb:.1f}KB) - may affect loading speed" )
        else:
            analysis['issues'].append( f"Reasonable page size ({page_size_kb:.1f}KB)" )
            analysis['score'] += 2
        
        return analysis
    
    # Calculate overall SEO score
    def _CalcScore( self ):
        scores = []
        
        for section, data in self.results.items():
            if isinstance( data, dict ) and 'score' in data:
                scores.append( data['score'] )
        
        if scores:
            self.score = round( sum( scores ) / len( scores ) )
        else:
            self.score = 0
        
        self.results['overall_score'] = self.score
    
    # Print a comprehensive SEO analysis report
    def ShowReport( self ):
        if 'error' in self.results:
            print( f"Error: {self.results['error']}" )
            return
        
        print( f"\n{'='*60}" )
        print( f"SEO ANALYSIS REPORT" )
        print( f"{'='*60}" )
        print( f"URL: {self.results['url']}" )
        print( f"Overall SEO Score: {self.score}/10 {self._GetRating( self.score )}" )
        print( f"{'='*60}" )
        
        print( f"\nTITLE ANALYSIS" )
        title_data = self.results['title_analysis']
        print( f"Title: '{title_data['title']}'" )
        print( f"Length: {title_data['length']} characters" )
        for issue in title_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nMETA DESCRIPTION ANALYSIS" )
        meta_data = self.results['meta_analysis']
        if meta_data['description']:
            print( f"Description: '{meta_data['description'][:100]}{'...' if len( meta_data['description'] ) > 100 else ''}'" )
        print( f"Length: {meta_data['length']} characters" )
        for issue in meta_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nHEADING STRUCTURE ANALYSIS" )
        heading_data = self.results['heading_analysis']
        for tag in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            count = len( heading_data['headings'][tag] )
            if count > 0:
                print( f"   {tag.upper()}: {count} tag(s)" )
                for heading in heading_data['headings'][tag][:3]:
                    print( f"      - '{heading[:60]}{'...' if len( heading ) > 60 else ''}'" )
        for issue in heading_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nIMAGE ANALYSIS" )
        image_data = self.results['image_analysis']
        print( f"Total Images: {image_data['total_images']}" )
        print( f"Images with Alt Text: {image_data['images_with_alt']}" )
        print( f"Images without Alt Text: {image_data['images_without_alt']}" )
        for issue in image_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nLINK ANALYSIS" )
        link_data = self.results['link_analysis']
        print( f"Internal Links: {link_data['internal_links']}" )
        print( f"External Links: {link_data['external_links']}" )
        for issue in link_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nCONTENT ANALYSIS" )
        content_data = self.results['content_analysis']
        print( f"Word Count: {content_data['word_count']}" )
        print( f"Character Count: {content_data['character_count']}" )
        for issue in content_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nTECHNICAL ANALYSIS" )
        tech_data = self.results['technical_analysis']
        print( f"HTTPS: {'Yes' if tech_data['https'] else 'No'}" )
        for issue in tech_data['issues']:
            print( f"   {issue}" )
        
        print( f"\nKEY RECOMMENDATIONS" )
        self._GenRecs()
        for i, rec in enumerate( self.recommendations[:10], 1 ):
            print( f"   {i}. {rec}" )
        
        print( f"\n{'='*60}" )
        print( f"Analysis completed! Overall Score: {self.score}/10" )
        print( f"{'='*60}" )
    
    # Get rating based on score
    def _GetRating( self, score: int ) -> str:
        if score >= 8:
            return "Excellent"
        elif score >= 6:
            return "Good"
        elif score >= 4:
            return "Needs Improvement"
        else:
            return "Poor"
    
    # Generate actionable SEO recommendations
    def _GenRecs( self ):
        self.recommendations = []
        
        title_data = self.results['title_analysis']
        if not title_data['title']:
            self.recommendations.append( "Add a descriptive title tag (30-60 characters)" )
        elif title_data['length'] < 30:
            self.recommendations.append( "Expand your title tag to 30-60 characters" )
        elif title_data['length'] > 60:
            self.recommendations.append( "Shorten your title tag to under 60 characters" )
        
        meta_data = self.results['meta_analysis']
        if not meta_data['description']:
            self.recommendations.append( "Add a compelling meta description (120-160 characters)" )
        elif meta_data['length'] < 120:
            self.recommendations.append( "Expand your meta description to 120-160 characters" )
        elif meta_data['length'] > 160:
            self.recommendations.append( "Shorten your meta description to under 160 characters" )
        
        heading_data = self.results['heading_analysis']
        if len( heading_data['headings']['h1'] ) == 0:
            self.recommendations.append( "Add an H1 tag to your page" )
        elif len( heading_data['headings']['h1'] ) > 1:
            self.recommendations.append( "Use only one H1 tag per page" )
        
        image_data = self.results['image_analysis']
        if image_data['images_without_alt'] > 0:
            self.recommendations.append( f"Add alt text to {image_data['images_without_alt']} images" )
        
        content_data = self.results['content_analysis']
        if content_data['word_count'] < 300:
            self.recommendations.append( "Add more content - aim for at least 300 words" )
        
        tech_data = self.results['technical_analysis']
        if not tech_data['https']:
            self.recommendations.append( "Implement HTTPS for better security and SEO" )
    
    # Export analysis results to JSON file
    def Export( self, filename: str ):
        try:
            with open( filename, 'w', encoding='utf-8' ) as f:
                json.dump( self.results, f, indent=2, ensure_ascii=False )
            print( f"Report exported to {filename}" )
        except Exception as e:
            print( f"Failed to export report: {e}" )

# Print application banner
def ShowBanner():
    banner = """
    ==============================================================
                         SEO Website Analyzer                       
                         Author: Andrew Piggot                
    ==============================================================
    """
    print( banner )

# Print help information
def ShowHelp():
    help_text = """
    Usage:
    1. Single URL analysis: Enter a website URL when prompted
    2. Export report: Enter 'export filename.json' after analysis
    3. Help: Enter 'help' for this information
    4. Exit: Enter 'quit' or 'exit' to close the program
    
    What this tool analyzes:
    - Title tags (length, optimization)
    - Meta descriptions (length, presence)
    - Heading structure (H1-H6 hierarchy)
    - Image alt text optimization
    - Internal/external link analysis
    - Content length and quality
    - Technical SEO factors (HTTPS, page size)
    
    SEO Score Breakdown:
    8-10: Excellent SEO optimization
    6-7:  Good, minor improvements needed
    4-5:  Needs improvement
    0-3:  Poor, major issues to address
    
    Examples:
    Enter URL: https://example.com
    Enter URL: export my_seo_report.json
    """
    print( help_text )

# Main application function
def main():
    ShowBanner()
    analyzer = SEOTool()
    
    print( "Welcome to the SEO Website Analyzer!" )
    print( "Type 'help' for usage information or 'quit' to exit.\n" )
    
    last_analysis = None
    
    while True:
        try:
            user_input = input( "Enter website URL to analyze (or command): " ).strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print( "Thanks for using SEO Analyzer! Keep optimizing!" )
                break
            elif user_input.lower() == 'help':
                ShowHelp()
                continue
            elif user_input.lower().startswith( 'export ' ):
                if last_analysis:
                    filename = user_input[7:].strip()
                    if not filename:
                        filename = 'seo_report.json'
                    analyzer.Export( filename )
                else:
                    print( "No analysis to export. Please analyze a website first." )
                continue
            
            if not user_input.startswith( ( 'http://', 'https://' ) ):
                user_input = 'https://' + user_input
            
            print( f"\nAnalyzing website: {user_input}" )
            print( "This may take a few seconds..." )
            
            results = analyzer.Analyze( user_input )
            
            if 'error' in results:
                print( f"Analysis failed: {results['error']}" )
                print( "Try checking:" )
                print( "   - URL is correct and accessible" )
                print( "   - Website is not blocking automated requests" )
                print( "   - Your internet connection is working" )
            else:
                analyzer.ShowReport()
                last_analysis = results
                print( f"\nTip: Type 'export filename.json' to save this report" )
            
        except KeyboardInterrupt:
            print( "\n\nThanks for using SEO Analyzer! Keep optimizing!" )
            break
        except Exception as e:
            print( f"Unexpected error: {e}" )

if __name__ == "__main__":
    main()
