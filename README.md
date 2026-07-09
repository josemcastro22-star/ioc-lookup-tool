# Threat Intel IOC Lookup Tool + Splunk SIEM Integration

A production threat intelligence pipeline that enriches suspicious IPs, domains, and file hashes against multiple threat databases, feeds results into a Splunk SIEM, and triggers automated alerts when HIGH or CRITICAL indicators are detected.

Built to mirror the triage workflow used in real SOC and MDR operations.

---

## Architecture

```
IOC Input
   ↓
ioc_lookup.py  →  reports/ioc_report_YYYY-MM-DD.json
                         ↓
               splunk_feed.py  →  splunk_events/feed.jsonl
                                         ↓
                                    Splunk SIEM
                                    ├── Dashboard (severity breakdown)
                                    └── Alert (CRITICAL/HIGH → triggered alert)
```

---

## Features

- **Multi-source enrichment** — queries VirusTotal, AbuseIPDB, URLhaus, and IPInfo
- **Auto-detects IOC type** — IPv4, domain, MD5, SHA1, SHA256
- **Severity classification** — CRITICAL / HIGH / MEDIUM / LOW / CLEAN
- **Dual output** — structured JSON + readable Markdown incident report
- **Splunk integration** — live SIEM dashboard + hourly alert on HIGH/CRITICAL hits
- **CI/CD pipeline** — GitHub Actions runs a scan automatically on every push
- **Exit codes for alerting** — exits with code 2 if any HIGH/CRITICAL IOCs detected

---

## Usage

```bash
# Install dependencies
pip install requests

# Scan a file of IOCs
python ioc_lookup.py --file sample_iocs.txt

# Scan a single IOC
python ioc_lookup.py --ioc 185.220.101.45
python ioc_lookup.py --ioc evildomain.xyz
python ioc_lookup.py --ioc 44d88612fea8a8f36de82e1278abb02f
```

Reports are saved to `reports/ioc_report_YYYY-MM-DD_HH-MM.{json,md}`.

---

## API Keys

Two free-tier API keys unlock full enrichment. Without them, URLhaus and IPInfo still run (no key required).

| Source | Key Required | Get One |
|--------|-------------|---------|
| VirusTotal | Yes | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | Yes | [abuseipdb.com/register](https://www.abuseipdb.com/register) |
| URLhaus | No | — |
| IPInfo | No | — |

**Set as environment variables:**
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
```

**For GitHub Actions:** add as repository secrets under Settings → Secrets → Actions.

---

## IOC File Format

```
# Comments start with #
185.220.101.45        # optional inline comment
evildomain-c2.xyz
44d88612fea8a8f36de82e1278abb02f
```

---

## Sample Output

```
🔍 IOC Lookup Tool — 2026-07-06 12:00
   VirusTotal:  ✅ key loaded
   AbuseIPDB:   ✅ key loaded
   URLhaus:     ✅ no key required
   IPInfo:      ✅ no key required

   Processing 9 IOC(s)...

  → Enriching IPV4: 185.220.101.45
    🔴 Severity: CRITICAL
  → Enriching DOMAIN: evildomain-c2.xyz
    🟠 Severity: HIGH
  → Enriching IPV4: 8.8.8.8
    🟢 Severity: CLEAN

=======================================================
SUMMARY
=======================================================
  🔴  CRITICAL    1
  🟠  HIGH        1
  🟢  CLEAN       2
=======================================================
⚠ 2 HIGH/CRITICAL IOC(s) detected. Investigate immediately.
```

---

## Splunk Setup

```bash
# Start Splunk via Docker
docker run -d -p 8000:8000 \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_GENERAL_TERMS='--accept-sgt-current-at-splunk-com' \
  -e SPLUNK_PASSWORD='your_password' \
  -v $(pwd)/splunk_events:/splunk-events \
  --name splunk splunk/splunk:latest

# Normalize reports into SIEM-ready JSONL (one event per IOC)
python3 splunk_feed.py

# In Splunk UI: Add Data → Monitor → Files & Directories → /splunk-events
```

Dashboard SPL query:
```
source="/splunk-events/feed.jsonl" | stats count by severity
```

Alert query (runs hourly, triggers if results > 0):
```
source="/splunk-events/feed.jsonl" severity=CRITICAL OR severity=HIGH
```

---

## Project Structure

```
ioc-lookup-tool/
├── ioc_lookup.py           # Main enrichment tool
├── splunk_feed.py          # Splunk connector (converts reports to JSONL)
├── sample_iocs.txt         # Demo IOCs for testing
├── reports/                # JSON + Markdown reports (gitignored)
├── splunk_events/          # SIEM feed (gitignored)
└── .github/
    └── workflows/
        └── ioc_scan.yml    # CI/CD pipeline
```

---

## Relevance to SOC / MDR Roles

This tool demonstrates:
- **IOC triage** — the first step in any alert investigation
- **Multi-source correlation** — cross-referencing VT, AbuseIPDB, URLhaus
- **Severity scoring** — prioritizing what to investigate first
- **Automation** — CI/CD pipeline for continuous monitoring
- **Reporting** — structured output usable in incident tickets

---

*Built by Jose Castro — [LinkedIn](https://linkedin.com/in/jose-castro-florida) | [GitHub](https://github.com/josemcastro22-star)*
