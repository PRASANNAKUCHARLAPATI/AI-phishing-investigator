# PHISHX

Open-source automated phishing email investigation tool for SOC teams.

> "One Email. One Investigation. One Campaign. Everything Connected."

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## What PHISHX Does

PHISHX transforms phishing investigation from a one-off scan into a persistent intelligence workflow:

1. **Investigate** — Parse emails, extract IOCs, run detection rules, and generate reports
2. **Remember** — Every case is stored in a local SQLite database with full IOC history
3. **Correlate** — Threat DNA fingerprinting links related emails and campaigns automatically
4. **Enrich** — Free OSINT integrations (URLhaus, AbuseIPDB, CISA KEV, RDAP, etc.)
5. **Automate** — Generate Sigma, YARA, and Suricata rules directly from investigation results
6. **Assist** — On-demand AI Q&A via Ollama, OpenAI, or Anthropic

## Features

### Interactive SOC Console

A Metasploit-inspired investigation console for phishing analysis.

```bash
phishx
```

```
phishx > load sample.eml
✓ Loaded sample.eml

phishx(sample.eml) > analyze
[1/6] Parsing email... ✓
[2/6] Extracting IoCs... ✓
[3/6] Authentication checks... ✓
[4/6] Running detection rules... ✓
[5/6] Threat intelligence... ✓
[6/6] Report generation... ✓

phishx(sample.eml) > summary
phishx(sample.eml) > urls
phishx(sample.eml) > intel urlhaus
phishx(sample.eml) > intel history https://evil.com/login
phishx(sample.eml) > intel osint abuseipdb
phishx(sample.eml) > dna
phishx(sample.eml) > campaign
phishx(sample.eml) > relationships
phishx(sample.eml) > rules sigma
phishx(sample.eml) > note "Escalate to IR team"
phishx(sample.eml) > ask "Why is this phishing?"
phishx(sample.eml) > exit
```

### Console Commands

| Command | Description |
|---------|-------------|
| `load <path>` | Load `.eml` file or directory |
| `analyze` | Run full investigation on loaded case |
| `summary` | Show investigation summary with threat meter |
| `urls` / `domains` / `ips` | List extracted indicators |
| `headers` / `forms` / `attachments` | Drill into email structure |
| `mitre` | Show MITRE ATT&CK mapping |
| `intel <provider>` | Enrich IoCs with URLhaus or VirusTotal |
| `intel history <ioc>` | Look up IOC history in local DB |
| `intel osint <provider>` | Query free OSINT (abuseipdb, rdap, doh, phishtank, alienvault-otx, cisa-kev) |
| `dna` | Show threat DNA fingerprint and similar cases |
| `campaign` | Show linked campaigns or related cases |
| `relationships` | Show related cases from memory |
| `rules [sigma\|yara\|suricata\|all]` | Generate detection rules |
| `note <text>` | Add analyst note to case |
| `ask <question>` | Ask the AI assistant about the case |
| `cases` / `use <id>` | Multi-case workspace management |
| `history` / `clear` | Session utilities |
| `export [format]` | Export report (text/json/mitre) |
| `exit` / `quit` | Exit console |

### Single-File Analysis

```bash
phishx sample.eml
phishx sample.eml --format json
phishx sample.eml --no-ai
```

### Batch & Monitoring Modes

```bash
# Analyze all .eml files in a directory
phishx ./incoming_emails --output ./reports

# Monitor a directory for new emails
phishx ./maildir --monitor
```

### Email Forensics

Complete email parsing supporting:

- Header analysis (Received, Authentication-Results, From, Reply-To, etc.)
- MIME structure parsing
- HTML body extraction and link harvesting
- Credential harvesting form detection
- Attachment analysis with MD5/SHA-256 hashing
- URL extraction from HTML attributes (`href`, `src`, `data-src`)
- Email authentication validation (SPF, DKIM, DMARC)

### Detection Engine

Pluggable rule-based detection covering:

- Email authentication failures (SPF, DKIM, DMARC)
- Suspicious infrastructure (Linux hosts, root users, Postfix anomalies)
- Reply-To mismatches
- Brand impersonation (lookalike domains)
- Suspicious TLDs and unusually long domains
- Cloud VPS IP detection (DigitalOcean, Hetzner, AWS, GCP, Azure)
- Fear and urgency language
- Credential-harvesting HTML forms
- URL obfuscation (punycode, excessive subdomains, long random domains)

### Investigation Memory (SQLite)

Every investigation is persisted locally:

- Cases with verdicts, scores, and timestamps
- IOC history with seen counts across investigations
- Analyst notes per case
- Case relationships and similarity links via Threat DNA
- Campaign tracking tables
- Rule suggestions per case

Database location: `phishx_memory.db` (configurable via `--db`)

### Threat DNA

Per-email fingerprinting computed during analysis:

- HTML hash
- CSS signature
- Subject pattern (normalized)
- Sender domain
- Sender timezone
- Attachment MIME types
- Form action domains
- URL patterns (standard, punycode, long-random, excessive-subdomains)
- Verdict and detection reasons

DNA enables similarity search across investigations.

### Free OSINT Integration

Built-in providers:

- **URLhaus** — URL reputation (no key required)
- **VirusTotal** — URL/domain/IP reputation (API key required)
- **AbuseIPDB** — IP abuse scoring (optional key)
- **AlienVault OTX** — Threat intelligence pulses (optional key)
- **CISA KEV** — Known exploited vulnerabilities catalog
- **RDAP** — Registration data for IPs/domains
- **DNS over HTTPS** — Domain resolution via Google DNS
- **PhishTank** — Phishing URL database

### Detection Rule Generator

Automatically generates detection content from investigation results:

- **Sigma** — SIEM detection rules (splunk, elastic, sentinel, etc.)
- **YARA** — File-based detection rules
- **Suricata** — Network IDS rules

### AI Assistant

On-demand AI analysis via multiple providers:

- **Ollama** (default, local, streaming)
- **OpenAI** (GPT-4o, etc.)
- **Anthropic** (Claude)

Supports investigative questions like "Why is this phishing?", "Explain the infrastructure", and "What should the SOC do next?"

### Report Generation

Multiple output formats:

- Text report (human-readable)
- JSON report (SIEM-ready)
- MITRE ATT&CK Navigator layer
- AI explanation (appended to text report)

## Installation

```bash
# Clone the repository
git clone https://github.com/PRASANNAKUCHARLAPATI/ai-phishing-investigator.git
cd ai-phishing-investigator

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package and console entry points
pip install -e .

# Run interactive console
phishx
```

## Requirements

- Python 3.9+
- Core: `requests`, `beautifulsoup4`, `lxml`, `rich`

## CLI Reference

```
usage: phishx [-h] [-o OUTPUT] [--no-ai] [--ai-provvider {ollama,openai,anthropic}]
              [--ai-model AI_MODEL] [--ai-api-key AI_API_KEY] [--ai-base-url AI_BASE_URL]
              [--no-mitre] [--whitelist WHITELIST] [--whitelist-mode {exact,subdomain}]
              [--format {text,json,both}] [--monitor] [--verbose] [--log-file LOG_FILE]
              [--sound] [--db DB]
              [input]

positional arguments:
  input                 Path to .eml file or directory of .eml files

optional arguments:
  -o, --output OUTPUT   Output directory (default: reports)
  --no-ai               Disable AI explanation generation
  --ai-provider {ollama,openai,anthropic}
                        AI provider (default: ollama)
  --ai-model AI_MODEL   AI model name (default: llama3.2)
  --ai-api-key AI_API_KEY
                        API key for OpenAI/Anthropic
  --ai-base-url AI_BASE_URL
                        Base URL for Ollama (default: http://127.0.0.1:11434)
  --no-mitre            Skip MITRE ATT&CK Navigator layer generation
  --whitelist WHITELIST
                        Path to custom whitelist file
  --whitelist-mode {exact,subdomain}
                        Whitelist matching mode (default: subdomain)
  --format {text,json,both}
                        Report format (default: both)
  --monitor             Monitor directory for new .eml files
  --verbose, -v         Enable debug logging
  --log-file LOG_FILE   Write logs to file
  --sound               Enable sound alerts for critical findings
  --db DB               Path to investigation memory database (default: phishx_memory.db)
```

## AI Configuration

### Ollama (local, default)

```bash
ollama pull llama3.2
phishx --ai-provider ollama --ai-model llama3.2
```

### OpenAI

```bash
export OPENAI_API_KEY="sk-..."
phishx --ai-provider openai --ai-model gpt-4o
```

### Anthropic

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
phishx --ai-provider anthropic --ai-model claude-sonnet-4-20250514
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Development

```bash
pip install -e .
ruff check .
ruff format .
```

## Disclaimer

PHISHX is intended for defensive security, malware analysis, phishing investigation, incident response, and educational purposes only.

The project is not intended to facilitate unauthorized access or offensive cyber operations.

## License

MIT License
