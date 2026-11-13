## 🌐 SEO Website Analyzer

**File:** `seo_tools/seo_analyzer.py`

A comprehensive SEO analysis tool that audits websites for optimization opportunities and provides actionable recommendations to improve search engine rankings.

### Features
- Complete on-page SEO analysis with scoring system
- Title tag optimization analysis (length, structure)
- Meta description evaluation and recommendations
- Heading structure analysis (H1-H6 hierarchy)
- Image alt text optimization checking
- Internal/external link analysis
- Content quality assessment (word count, readability)
- Technical SEO factors (HTTPS, page size, schema markup)
- Detailed reporting with actionable recommendations
- JSON export functionality for reports

### Analysis Categories
- **Title & Meta:** Title tags, meta descriptions, meta keywords
- **Content Structure:** Heading hierarchy, content length, text quality
- **Images:** Alt text optimization, image count analysis
- **Links:** Internal linking structure, external link evaluation
- **Technical SEO:** HTTPS usage, page size, structured data detection
- **Overall Scoring:** 0-10 scale with improvement recommendations

### Installation & Usage
```bash
# Clone repository (if not already done)
git clone https://github.com/AndrewPDev/andrews-python-tools.git
cd andrews-python-tools

# Run the SEO analyzer
python seo_tools/seo_analyzer.py
```

### Usage Examples
#### Basic Website Analysis
```
Enter website URL to analyze: https://example.com
Enter website URL to analyze: example.com  # HTTPS added automatically
```

#### Export Analysis Report
```
Enter website URL to analyze: export my_seo_report.json
```

### Sample Analysis Output
```
==============================================================
SEO ANALYSIS REPORT
==============================================================
URL: https://example.com
Overall SEO Score: 7/10 🟡 Good
==============================================================

📝 TITLE ANALYSIS
Title: 'Example Domain - Your Website Title Here'
Length: 42 characters
   ✅ Title length is optimal (30-60 characters)

📄 META DESCRIPTION ANALYSIS
Description: 'This domain is for use in illustrative examples in documents...'
Length: 140 characters
   ✅ Meta description length is optimal (120-160 characters)

💡 KEY RECOMMENDATIONS
   1. Add more internal links for better navigation
   2. Consider adding schema markup for rich snippets
   3. Expand content to over 600 words for better SEO
```

### SEO Score Breakdown
| Score | Rating | Description |
|-------|--------|-------------|
| 🟢 8-10 | Excellent | Well-optimized, minor tweaks needed |
| 🟡 6-7 | Good | Solid foundation, some improvements needed |
| 🟠 4-5 | Needs Work | Several issues to address |
| 🔴 0-3 | Poor | Major SEO problems requiring attention |

### Commands
| Command | Description |
|---------|-------------|
| `URL` | Analyze any website URL |
| `export filename.json` | Export last analysis to JSON file |
| `help` | Display usage information |
| `quit`, `exit` | Exit the program |

### What Gets Analyzed
- **Title Tags:** Length, optimization, brand inclusion
- **Meta Descriptions:** Length, compelling content, keyword usage
- **Heading Structure:** Proper H1-H6 hierarchy and usage
- **Images:** Alt text presence, optimization opportunities
- **Links:** Internal linking strategy, external link quality
- **Content:** Word count, readability, content depth
- **Technical Factors:** HTTPS, page speed indicators, structured data

### Use Cases
- **Website Audits:** Comprehensive SEO health checks
- **Content Optimization:** Improve existing page performance
- **Competitor Analysis:** Compare SEO implementations
- **Client Reporting:** Professional SEO audit reports
- **Learning Tool:** Understand SEO best practices