# AI Phishing Investigator

An automated phishing email investigation tool that parses, analyzes, and generates comprehensive reports on suspicious emails for Security Operations Center (SOC) teams.

![Python](https://img.shields.io/badge/python-3.12+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview

This tool automates the analysis of phishing emails by extracting indicators of compromise (IoCs), detecting malicious patterns, and generating detailed investigation reports for Security Operations Center (SOC) teams.

## Features

- **Email Parsing**: Extracts headers and body content from `.eml` files
- **IOC Extraction**: Identifies URLs, domains, IP addresses, and email addresses
- **Phishing Detection**: Analyzes email authentication (SPF, DKIM, DMARC) and suspicious patterns
- **Threat Scoring**: Assigns risk scores and verdicts (PHISHING/SUSPICIOUS) based on detection rules
- **Report Generation**: Creates comprehensive investigation reports with MITRE ATT&CK mapping
- **AI Explanation**: Optional integration with Ollama for AI-powered analysis explanation

## Project Structure

```
ai-phishing-investigator/
├── main.py                    # Main entry point
├── parser/
│   ├── __init__.py           # Package init
│   └── email_parser.py        # Email parsing functionality
├── ioc/
│   ├── __init__.py           # Package init
│   └── extractor.py           # IOC extraction module
├── detector.py                # Phishing detection engine
├── reporter.py                # Report generation module
├── ai_explainer.py           # AI explanation integration (Ollama)
├── whitelist.py               # Whitelisted legitimate domains
├── requirements.txt         # Python dependencies
└── sample.eml                 # Sample phishing email for testing
```

## Detection Rules

The detector analyzes emails for:

1. **SPF/DKIM/DMARC Failures** - Email authentication bypass
2. **Suspicious Return Path** - Linux host indicators (e.g., "ubuntu", "root@")
3. **Malicious Domain Patterns** - Newly registered or lookalike domains (`.me`, `blog`, `segui`)
4. **Cloud VPS Infrastructure** - IPs from known cloud provider ranges (e.g., `137.x.x.x`)

## Requirements

- Python 3.12+
- Standard library only (uses `email` module for parsing)
- Optional: requests (for AI explainer feature with Ollama)

### Installation

```bash
# Clone the repository
git clone https://github.com/PRASANNAKUCHARLAPATI/ai-phishing-investigator.git
cd ai-phishing-investigator

# Install dependencies (optional, for AI explainer)
pip install -r requirements.txt
```

### AI Explainer Setup (Optional)

For AI-powered explanations, install [Ollama](https://ollama.ai) and pull the model:

```bash
ollama pull llama3.2
```

## Usage

```bash
# Run with sample email
python main.py
```

Or import as a module:

```python
from parser.email_parser import parse_email
from ioc.extractor import extract_iocs
from detector import analyze_email
from reporter import generate_report

email_data = parse_email("sample.eml")
combined_text = str(email_data["headers"]) + email_data["body"]
iocs = extract_iocs(combined_text)

extracted_data = {
    "headers": str(email_data["headers"]),
    "urls": iocs["urls"],
    "domains": iocs["domains"],
    "ips": iocs["ips"]
}

result = analyze_email(extracted_data)
report_file = generate_report(email_data, iocs, result)
```

## Output

The tool generates a `report.txt` containing:

- Verdict and risk score with confidence level
- Detection reasons for the analysis
- Extracted IoCs (malicious URLs, domains, IPs, emails)
- Email authentication summary (SPF/DKIM/DMARC status)
- MITRE ATT&CK technique mapping
- Risk assessment and recommended SOC actions

## MITRE ATT&CK Mapping

- T1566.002 - Phishing: Link
- T1583.001 - Acquire Infrastructure: Domains
- T1583.003 - Acquire Infrastructure: VPS

## License

MIT License
