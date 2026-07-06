#!/usr/bin/env python3
"""
Threat Intel IOC Lookup Tool
Author: Jose Castro

Enriches Indicators of Compromise (IOCs) against multiple threat intelligence
sources and generates a structured incident report — mirroring the triage
workflow used in managed detection and response (MDR) operations.

Supported IOC types:  IPv4, Domain, MD5, SHA1, SHA256
Intel sources:        VirusTotal, AbuseIPDB, URLhaus, IPInfo (geo)

Usage:
    python3 ioc_lookup.py --file sample_iocs.txt
    python3 ioc_lookup.py --ioc 192.168.1.1
    python3 ioc_lookup.py --ioc evil.com
    python3 ioc_lookup.py --ioc 44d88612fea8a8f36de82e1278abb02f

API Keys (set as environment variables or GitHub Secrets):
    VIRUSTOTAL_API_KEY   — https://www.virustotal.com/gui/join-us
    ABUSEIPDB_API_KEY    — https://www.abuseipdb.com/register
    (URLhaus and IPInfo require no key)
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ─── CONFIG ──────────────────────────────────────────────────────────────────

VT_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
REQUEST_TIMEOUT  = 12
VT_RATE_LIMIT    = 15   # seconds between VT calls (free tier: 4/min)

HEADERS = {
    "User-Agent": "IOC-Lookup-Tool/1.0 (github.com/josemcastro22-star/ioc-lookup-tool)"
}

# Severity scoring thresholds
SEVERITY_THRESHOLDS = {
    "CRITICAL": 70,   # VT malicious detections or AbuseIPDB score
    "HIGH":     40,
    "MEDIUM":   15,
    "LOW":      1,
    "CLEAN":    0,
}

SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "CLEAN":    "🟢",
    "UNKNOWN":  "⚪",
}


# ─── IOC TYPE DETECTION ──────────────────────────────────────────────────────

IPV4_RE   = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE   = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def detect_ioc_type(ioc: str) -> str:
    ioc = ioc.strip()
    if IPV4_RE.match(ioc):
        return "ipv4"
    if MD5_RE.match(ioc):
        return "md5"
    if SHA1_RE.match(ioc):
        return "sha1"
    if SHA256_RE.match(ioc):
        return "sha256"
    if DOMAIN_RE.match(ioc):
        return "domain"
    return "unknown"


def parse_ioc_file(path: str) -> list[dict]:
    """Read IOCs from a file, skipping blank lines and comments (#)."""
    iocs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Support optional inline comments:  8.8.8.8  # google dns
            ioc_value = line.split("#")[0].split()[0].strip()
            if not ioc_value:
                continue
            ioc_type = detect_ioc_type(ioc_value)
            iocs.append({"value": ioc_value, "type": ioc_type})
    return iocs


# ─── SAFE HTTP ───────────────────────────────────────────────────────────────

def safe_get(url: str, headers: dict = None, params: dict = None) -> dict | None:
    try:
        r = requests.get(
            url,
            headers={**HEADERS, **(headers or {})},
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 429:
            print("    ⏳ Rate limited — waiting 60s...")
            time.sleep(60)
            r = requests.get(url, headers={**HEADERS, **(headers or {})},
                             params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        print(f"    ⚠ HTTP {r.status_code} from {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"    ⚠ Timeout: {url}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"    ⚠ Connection error: {e}")
        return None
    except Exception as e:
        print(f"    ⚠ Unexpected error: {e}")
        return None


# ─── INTEL SOURCES ───────────────────────────────────────────────────────────

def query_virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal v3 API for IPs, domains, and file hashes."""
    if not VT_API_KEY:
        return {"source": "VirusTotal", "status": "skipped", "reason": "No API key set"}

    endpoint_map = {
        "ipv4":   f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "md5":    f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha1":   f"https://www.virustotal.com/api/v3/files/{ioc}",
        "sha256": f"https://www.virustotal.com/api/v3/files/{ioc}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"source": "VirusTotal", "status": "skipped", "reason": f"Unsupported type: {ioc_type}"}

    data = safe_get(url, headers={"x-apikey": VT_API_KEY})
    time.sleep(VT_RATE_LIMIT)  # respect free tier rate limit

    if not data:
        return {"source": "VirusTotal", "status": "error", "reason": "No response"}

    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious    = stats.get("malicious", 0)
        suspicious   = stats.get("suspicious", 0)
        undetected   = stats.get("undetected", 0)
        total        = malicious + suspicious + undetected + stats.get("harmless", 0)
        reputation   = data["data"]["attributes"].get("reputation", None)
        tags         = data["data"]["attributes"].get("tags", [])

        return {
            "source":       "VirusTotal",
            "status":       "success",
            "malicious":    malicious,
            "suspicious":   suspicious,
            "total_engines": total,
            "reputation":   reputation,
            "tags":         tags,
            "detection_rate": f"{malicious}/{total}" if total else "0/0",
            "link":         f"https://www.virustotal.com/gui/{'ip-address' if ioc_type == 'ipv4' else ioc_type}/{ioc}",
        }
    except (KeyError, TypeError) as e:
        return {"source": "VirusTotal", "status": "error", "reason": f"Parse error: {e}"}


def query_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for IP reputation. Only works for IPv4."""
    if not ABUSEIPDB_KEY:
        return {"source": "AbuseIPDB", "status": "skipped", "reason": "No API key set"}

    data = safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )

    if not data:
        return {"source": "AbuseIPDB", "status": "error", "reason": "No response"}

    try:
        d = data["data"]
        return {
            "source":          "AbuseIPDB",
            "status":          "success",
            "abuse_score":     d.get("abuseConfidenceScore", 0),
            "total_reports":   d.get("totalReports", 0),
            "last_reported":   d.get("lastReportedAt", "Never"),
            "country":         d.get("countryCode", "Unknown"),
            "isp":             d.get("isp", "Unknown"),
            "usage_type":      d.get("usageType", "Unknown"),
            "is_whitelisted":  d.get("isWhitelisted", False),
            "link":            f"https://www.abuseipdb.com/check/{ip}",
        }
    except (KeyError, TypeError) as e:
        return {"source": "AbuseIPDB", "status": "error", "reason": f"Parse error: {e}"}


def query_urlhaus(ioc: str, ioc_type: str) -> dict:
    """Query URLhaus for domain or IP reputation. No API key required."""
    if ioc_type not in ("ipv4", "domain"):
        return {"source": "URLhaus", "status": "skipped", "reason": "Only supports IPs and domains"}

    data = None
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ioc},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
    except Exception as e:
        return {"source": "URLhaus", "status": "error", "reason": str(e)}

    if not data:
        return {"source": "URLhaus", "status": "error", "reason": "No response"}

    query_status = data.get("query_status", "")
    if query_status == "no_results":
        return {"source": "URLhaus", "status": "success", "found": False, "malicious_urls": 0}

    urls_online = [u for u in data.get("urls", []) if u.get("url_status") == "online"]
    return {
        "source":        "URLhaus",
        "status":        "success",
        "found":         True,
        "query_status":  query_status,
        "malicious_urls": len(data.get("urls", [])),
        "urls_online":   len(urls_online),
        "tags":          data.get("tags", []),
        "link":          f"https://urlhaus.abuse.ch/host/{ioc}",
    }


def query_ipinfo(ip: str) -> dict:
    """Get geolocation and ASN info for an IP. No API key required for basic use."""
    data = safe_get(f"https://ipinfo.io/{ip}/json")
    if not data or "bogon" in data:
        return {"source": "IPInfo", "status": "skipped", "reason": "Private/reserved IP"}

    return {
        "source":   "IPInfo",
        "status":   "success",
        "country":  data.get("country", "Unknown"),
        "region":   data.get("region", "Unknown"),
        "city":     data.get("city", "Unknown"),
        "org":      data.get("org", "Unknown"),
        "hostname": data.get("hostname", "None"),
    }


# ─── SEVERITY SCORING ────────────────────────────────────────────────────────

def calculate_severity(results: list[dict]) -> str:
    """Derive overall severity from all intel source results."""
    max_score = 0

    for r in results:
        if r.get("status") != "success":
            continue
        # VirusTotal malicious detections
        if r.get("source") == "VirusTotal":
            max_score = max(max_score, r.get("malicious", 0))
        # AbuseIPDB confidence score (0-100)
        if r.get("source") == "AbuseIPDB":
            max_score = max(max_score, r.get("abuse_score", 0))
        # URLhaus any malicious URLs found
        if r.get("source") == "URLhaus" and r.get("found"):
            max_score = max(max_score, 50)  # minimum HIGH if URLhaus hit

    for level, threshold in SEVERITY_THRESHOLDS.items():
        if max_score >= threshold:
            return level
    return "CLEAN"


# ─── ENRICHMENT ORCHESTRATOR ─────────────────────────────────────────────────

def enrich_ioc(ioc: str, ioc_type: str) -> dict:
    """Run all applicable intel sources for a given IOC."""
    print(f"  → Enriching {ioc_type.upper()}: {ioc}")
    intel_results = []

    if ioc_type in ("ipv4",):
        intel_results.append(query_ipinfo(ioc))
        intel_results.append(query_abuseipdb(ioc))
        intel_results.append(query_urlhaus(ioc, ioc_type))
        intel_results.append(query_virustotal(ioc, ioc_type))

    elif ioc_type == "domain":
        intel_results.append(query_urlhaus(ioc, ioc_type))
        intel_results.append(query_virustotal(ioc, ioc_type))

    elif ioc_type in ("md5", "sha1", "sha256"):
        intel_results.append(query_virustotal(ioc, ioc_type))

    else:
        intel_results.append({"source": "All", "status": "skipped", "reason": f"Unknown IOC type: {ioc_type}"})

    severity = calculate_severity(intel_results)
    icon     = SEVERITY_COLORS.get(severity, "⚪")
    print(f"    {icon} Severity: {severity}")

    return {
        "ioc":      ioc,
        "type":     ioc_type,
        "severity": severity,
        "results":  intel_results,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── REPORT GENERATION ───────────────────────────────────────────────────────

def build_json_report(enriched: list[dict], filename: str):
    report = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "total_iocs":       len(enriched),
        "severity_summary": {
            sev: sum(1 for e in enriched if e["severity"] == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"]
        },
        "iocs": enriched,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📋 JSON report: {filename}")
    return report


def build_markdown_report(enriched: list[dict], filename: str):
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Threat Intelligence — IOC Lookup Report",
        f"*Generated: {now}*",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    counts = {
        sev: sum(1 for e in enriched if e["severity"] == sev)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"]
    }
    for sev, count in counts.items():
        if count:
            icon = SEVERITY_COLORS.get(sev, "⚪")
            lines.append(f"| {icon} {sev} | {count} |")

    lines += ["", "---", "## IOC Details", ""]

    # Sort by severity (critical first)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"]
    sorted_iocs    = sorted(enriched, key=lambda x: severity_order.index(x.get("severity", "UNKNOWN")))

    for ioc in sorted_iocs:
        icon = SEVERITY_COLORS.get(ioc["severity"], "⚪")
        lines.append(f"### {icon} `{ioc['ioc']}` — {ioc['type'].upper()} — {ioc['severity']}")
        lines.append("")

        for r in ioc["results"]:
            src    = r.get("source", "Unknown")
            status = r.get("status", "unknown")

            if status == "skipped":
                lines.append(f"**{src}:** Skipped — {r.get('reason', '')}")

            elif status == "error":
                lines.append(f"**{src}:** ❌ Error — {r.get('reason', '')}")

            elif src == "VirusTotal" and status == "success":
                lines.append(f"**VirusTotal:** {r['detection_rate']} engines detected · "
                              f"Reputation: {r.get('reputation', 'N/A')} · "
                              f"[View Report]({r.get('link', '')})")
                if r.get("tags"):
                    lines.append(f"  Tags: {', '.join(r['tags'])}")

            elif src == "AbuseIPDB" and status == "success":
                lines.append(f"**AbuseIPDB:** Score: {r['abuse_score']}/100 · "
                              f"Reports: {r['total_reports']} · "
                              f"ISP: {r['isp']} · Country: {r['country']} · "
                              f"[View Report]({r.get('link', '')})")

            elif src == "URLhaus" and status == "success":
                if r.get("found"):
                    lines.append(f"**URLhaus:** ⚠ Found — {r['malicious_urls']} malicious URLs "
                                 f"({r['urls_online']} currently online) · "
                                 f"[View Report]({r.get('link', '')})")
                else:
                    lines.append(f"**URLhaus:** Not found in database")

            elif src == "IPInfo" and status == "success":
                lines.append(f"**IPInfo:** {r['city']}, {r['region']}, {r['country']} · "
                              f"ASN: {r['org']}")

        lines.append(f"*Enriched: {ioc['enriched_at']}*")
        lines.append("")

    lines += [
        "---",
        "## Analyst Notes",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Analyst | Jose Castro |",
        f"| Date | {now} |",
        f"| Tool | ioc-lookup-tool v1.0 |",
        f"| Sources | VirusTotal, AbuseIPDB, URLhaus, IPInfo |",
        "",
        "> **Recommendation:** Investigate all CRITICAL and HIGH severity IOCs immediately.",
        "> Block CRITICAL IOCs at the perimeter. Escalate to senior analyst if active compromise suspected.",
    ]

    content = "\n".join(lines)
    with open(filename, "w") as f:
        f.write(content)
    print(f"📄 Markdown report: {filename}")


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel IOC Lookup Tool — enriches IOCs against multiple intel sources"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to file containing one IOC per line")
    group.add_argument("--ioc",  "-i", help="Single IOC to look up")
    parser.add_argument("--out", "-o", default="reports", help="Output directory (default: reports/)")
    args = parser.parse_args()

    # Collect IOCs
    if args.ioc:
        ioc_type = detect_ioc_type(args.ioc)
        if ioc_type == "unknown":
            print(f"❌ Could not detect type for '{args.ioc}'. "
                  f"Expected IPv4, domain, MD5, SHA1, or SHA256.")
            sys.exit(1)
        iocs = [{"value": args.ioc, "type": ioc_type}]
    else:
        if not Path(args.file).exists():
            print(f"❌ File not found: {args.file}")
            sys.exit(1)
        iocs = parse_ioc_file(args.file)

    if not iocs:
        print("❌ No valid IOCs found.")
        sys.exit(1)

    # Announce API key status
    print(f"\n🔍 IOC Lookup Tool — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"   VirusTotal:  {'✅ key loaded' if VT_API_KEY else '⚠ no key — set VIRUSTOTAL_API_KEY'}")
    print(f"   AbuseIPDB:   {'✅ key loaded' if ABUSEIPDB_KEY else '⚠ no key — set ABUSEIPDB_API_KEY'}")
    print(f"   URLhaus:     ✅ no key required")
    print(f"   IPInfo:      ✅ no key required")
    print(f"\n   Processing {len(iocs)} IOC(s)...\n")

    # Enrich all IOCs
    enriched = []
    for ioc in iocs:
        result = enrich_ioc(ioc["value"], ioc["type"])
        enriched.append(result)

    # Write reports
    Path(args.out).mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M")
    json_file   = f"{args.out}/ioc_report_{timestamp}.json"
    md_file     = f"{args.out}/ioc_report_{timestamp}.md"

    report = build_json_report(enriched, json_file)
    build_markdown_report(enriched, md_file)

    # Final summary
    print("\n" + "=" * 55)
    print("SUMMARY")
    print("=" * 55)
    for sev, count in report["severity_summary"].items():
        if count:
            icon = SEVERITY_COLORS.get(sev, "⚪")
            print(f"  {icon}  {sev:<10} {count}")
    print("=" * 55)

    # Exit with error code if any CRITICAL or HIGH found (useful for CI/CD alerting)
    critical = report["severity_summary"].get("CRITICAL", 0)
    high     = report["severity_summary"].get("HIGH", 0)
    if critical or high:
        print(f"\n⚠ {critical + high} HIGH/CRITICAL IOC(s) detected. Investigate immediately.")
        sys.exit(2)


if __name__ == "__main__":
    main()
