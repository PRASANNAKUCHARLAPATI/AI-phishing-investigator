# AI Phishing Investigator

An automated phishing email investigation tool that parses, analyzes, and generates comprehensive reports on suspicious emails for Security Operations Center (SOC) teams.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Overview

This tool automates the analysis of phishing emails by extracting indicators of compromise (IoCs), detecting malicious patterns, and generating detailed investigation reports optimized for SOC workflows.

## Features

- **CLI-First Design**: Production-ready CLI with `argparse`, logging, and error handling (`phish-investigator` command)
- **Email Parsing**: Extracts headers, plain-text body, HTML body, forms, and attachments from `.eml` files
- **HTML Analysis**: Parses HTML bodies with BeautifulSoup to extract links, hidden elements, and credential-harvesting forms
- **IOC Extraction**: Identifies URLs, domains, IP addresses, and email addresses with deduplication
- **Enhanced Phishing Detection**: Rule-based engine with brand impersonation, fear-language scoring, cloud VPS detection, and header chain analysis
- **Pluggable Rules Architecture**: Each detection rule is a standalone class in `rules/` for easy tuning and extension
- **Whitelist Management**: Configurable whitelist file (`whitelist.txt`) with exact and subdomain matching modes
- **Threat Intelligence Integration**: Optional URLhaus and VirusTotal lookups for URL/domain/IP reputation
- **AI-Powered Explanations**: Provider-agnostic AI integration supporting Ollama, OpenAI, and Anthropic
- **Multiple Output Formats**: Text reports, JSON (SIEM-ready), and MITRE ATT&CK Navigator layer exports
- **Batch & Monitoring Modes**: Scan directories of `.eml` files or watch a folder for live analysis
- **Unique Case IDs**: Timestamped, hash-based case directories prevent report overwrites
- **Robust Error Handling**: Input validation, graceful fallbacks, and comprehensive logging

## Project Structure

```
ai-phishing-investigator/
├── main.py                    # CLI entry point with argparse
├── pyproject.toml             # Packaging, dependencies, and tool config
├── requirements.txt           # Core dependencies
├── whitelist.py               # Whitelist manager (exact/subdomain matching)
├── whitelist.txt              # Configurable whitelist file
├── detector.py                # Pluggable detection engine
├── reporter.py                # Report generation (text + JSON + MITRE layer)
├── ai_explainer.py            # AI explanation (Ollama / OpenAI / Anthropic)
├── sample.eml                 # Sample phishing email for testing
├── parser/
│   ├── __init__.py
│   └── email_parser.py        # Email parsing (headers, HTML, forms, attachments)
├── ioc/
│   ├── __init__.py
│   └── extractor.py           # IOC extraction module
├── intel/
│   ├── __init__.py            # Threat intelligence integrations
│   └── ...                    # URLhaus + VirusTotal providers
├── rules/
│   ├── __init__.py
│   ├── base.py                # Abstract Rule base class
│   ├── auth_rules.py          # SPF/DKIM/DMARC rules
│   ├── header_rules.py        # Suspicious header / hostname rules
│   ├── domain_rules.py        # Brand impersonation, TLD, length rules
│   ├── content_rules.py       # Fear language + form exfiltration rules
│   └── ip_rules.py            # Cloud VPS IP range rules
├── tests/
│   ├── __init__.py
│   ├── test_core.py           # Parser + extractor tests
│   └── test_detector.py       # Rule + engine tests
├── .pre-commit-config.yaml    # Pre-commit hooks (ruff, trailing whitespace, etc.)
└── README.md
```

## Detection Rules

The detector analyzes emails for:

1. **Email Authentication Failures** — SPF, DKIM, DMARC hard/soft failures and missing results
2. **Suspicious Infrastructure** — Linux host indicators, root user, Postfix running as root, Reply-To mismatches
3. **Domain Threats** — Brand impersonation (e.g., `g00gle.com`), suspicious TLDs (.xyz, .top, .click), unusually long domains
4. **Cloud VPS IPs** — IPs from DigitalOcean, Hetzner, and other cloud ranges commonly used for phishing infrastructure
5. **Social Engineering Content** — Fear and urgency language detection (e.g., "urgent", "verify immediately", "account will be suspended")
6. **HTML Form Exfiltration** — Detects forms posting credentials to external attacker-controlled domains

## Requirements

- Python 3.9+
- Core: `requests`, `beautifulsoup4`, `lxml`
- Optional AI: `openai` or `anthropic`
- Optional monitoring: `watchdog`
- Optional intel: `requests` (shared)

### Installation

```bash
# Clone the repository
git clone https://github.com/PRASANNAKUCHARLAPATI/ai-phishing-investigator.git
cd ai-phishing-investigator

# Install core dependencies
pip install -r requirements.txt

# Install with optional extras
pip install -e ".[ai,intel,dev]"
```

### AI Provider Setup (Optional)

**Ollama (local):**
```bash
ollama pull llama3.2
```

**OpenAI:**
```bash
export OPENAI_API_KEY="sk-..."
```

**Anthropic:**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Threat Intel Setup (Optional)

No API key required for URLhaus:
```bash
phish-investigator sample.eml --intel-provider urlhaus
```

VirusTotal requires an API key:
```bash
phish-investigator sample.eml --intel-provider virustotal --intel-api-key YOUR_KEY
```

## Usage

### Single File Analysis

```bash
# Basic analysis with text report
python main.py sample.eml

# JSON output for SIEM ingestion
python main.py sample.eml --format json

# Disable AI explanations
python main.py sample.eml --no-ai
```

### Batch Analysis

```bash
# Analyze all .eml files in a directory
python main.py ./incoming_emails --output ./reports
```

### Directory Monitoring

```bash
# Watch a directory and auto-analyze new .eml files
python main.py ./maildir --monitor --output ./reports
```

### Customize Whitelist

```bash
# Use your own whitelist file
python main.py sample.eml --whitelist ./my_whitelist.txt --whitelist-mode exact
```

### AI Provider Selection

```bash
# Use OpenAI GPT-4o instead of Ollama
python main.py sample.eml --ai-provider openai --ai-model gpt-4o --ai-api-key sk-...

# Use Anthropic Claude
python main.py sample.eml --ai-provider anthropic --ai-model claude-sonnet-4-20250514 --ai-api-key sk-ant-...
```

### Threat Intel Integration

```bash
# Check IoCs against URLhaus
python main.py sample.eml --intel-provider urlhaus

# Check IoCs against VirusTotal
python main.py sample.eml --intel-provider virustotal --intel-api-key YOUR_KEY
```

### Module Usage

```python
from parser.email_parser import parse_email
from ioc.extractor import extract_iocs
from detector import analyze_email
from reporter import generate_report, generate_mitre_navigator_layer
from ai_explainer import ai_explain, AIProviderConfig

email_data = parse_email("sample.eml")
headers_str = "\n".join(f"{k}: {v}" for k, v in email_data.headers.items())
combined_text = headers_str + "\n" + email_data.body_text + "\n" + email_data.body_html
iocs = extract_iocs(combined_text)

extracted_data = {
    "headers": headers_str,
    "urls": iocs["urls"],
    "domains": iocs["domains"],
    "ips": iocs["ips"],
    "body_text": email_data.body_text,
    "body_html": email_data.body_html,
    "forms": email_data.forms,
}

result = analyze_email(extracted_data)
report_file = generate_report(email_data.__dict__, iocs, result, email_path="sample.eml")
ai_explain(extracted_data, result)
```

## Output

The tool generates a unique case directory per analysis containing:

- **Text Report** — Human-readable investigation report with vertercle, IoCs, auth summary, MITRE ATT&CK mapping, and SOC recommendations
- **JSON Report** — Machine-readable output for SIEM ingestion and automation
- **MITRE Navigator Layer** — ATT&CK Navigator JSON layer for visualization
- **AI Explanation** (optional) — AI-generated analysis appended to the report

### Report Contents

- Verdict and risk score with confidence level (HIGH / MEDIUM / LOW)
- Detection reasons for each triggered rule
- Extracted IoCs (malicious URLs, domains, IPs, emails)
- Distinction between malicious and whitelisted Iocs
- Email authentication summary (SPF/DKIM/DMARC status)
- MITRE ATT&CK technique mapping
- Risk assessment and recommended SOC actions
- Attachment hashes (MD5, SHA-256)

## MITRE ATT&CK Mapping

- T1566.002 - Phishing: Link
- T1583.001 - Acquire Infrastructure: Domains
- T1583.003 - Acquire Infrastructure: VPS
- T1056.004 - Input Capture: Credential Phishing

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=parser --cov=detector --cov=ioc --cov=reporter
```

## Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

Runs `ruff` (lint + format), trailing whitespace removal, and YAML/TOML/JSON checks.

## Development

```bash
# Install in editable mode with all extras
pip install -e ".[ai,intel,monitor,dev]"

# Run linting
ruff check .
ruff format .
```

## License

MIT License
