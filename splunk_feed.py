#!/usr/bin/env python3
"""
Splunk Feed — IOC Lookup Tool
Reads JSON reports from the reports/ folder and writes one flat JSON event
per IOC to splunk_events/feed.jsonl so Splunk can parse each field cleanly.

Usage:
    python3 splunk_feed.py
    python3 splunk_feed.py --reports reports/ --out splunk_events/feed.jsonl
"""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone

def process_reports(reports_dir: str, out_file: str):
    reports_path = Path(reports_dir)
    out_path     = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Track already-processed reports to avoid duplicates
    processed_file = out_path.parent / ".processed"
    processed = set()
    if processed_file.exists():
        processed = set(processed_file.read_text().splitlines())

    new_events = 0

    with open(out_path, "a") as out:
        for json_file in sorted(reports_path.glob("ioc_report_*.json")):
            if json_file.name in processed:
                continue

            try:
                with open(json_file) as f:
                    report = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"  ⚠ Skipping {json_file.name}: {e}")
                continue

            report_id  = json_file.stem
            generated  = report.get("report_generated", "")

            for ioc in report.get("iocs", []):
                # Build one flat event per IOC
                event = {
                    "timestamp":    generated,
                    "report_id":    report_id,
                    "ioc":          ioc.get("ioc", ""),
                    "ioc_type":     ioc.get("type", ""),
                    "severity":     ioc.get("severity", "UNKNOWN"),
                    "enriched_at":  ioc.get("enriched_at", ""),
                }

                # Pull useful fields from individual source results
                for r in ioc.get("results", []):
                    src = r.get("source", "")
                    if r.get("status") != "success":
                        continue
                    if src == "VirusTotal":
                        event["vt_malicious"]     = r.get("malicious", 0)
                        event["vt_total_engines"] = r.get("total_engines", 0)
                        event["vt_detection_rate"] = r.get("detection_rate", "")
                    elif src == "AbuseIPDB":
                        event["abuse_score"]    = r.get("abuse_score", 0)
                        event["abuse_reports"]  = r.get("total_reports", 0)
                        event["abuse_country"]  = r.get("country", "")
                        event["abuse_isp"]      = r.get("isp", "")
                    elif src == "URLhaus":
                        event["urlhaus_found"]    = r.get("found", False)
                        event["urlhaus_malicious"] = r.get("malicious_urls", 0)
                    elif src == "IPInfo":
                        event["geo_country"] = r.get("country", "")
                        event["geo_city"]    = r.get("city", "")
                        event["geo_org"]     = r.get("org", "")

                out.write(json.dumps(event) + "\n")
                new_events += 1

            processed.add(json_file.name)

    # Save processed list
    processed_file.write_text("\n".join(sorted(processed)))
    print(f"✅ Wrote {new_events} new events to {out_file}")

def main():
    parser = argparse.ArgumentParser(description="Convert IOC reports to Splunk-friendly JSONL")
    parser.add_argument("--reports", default="reports",           help="Reports folder (default: reports/)")
    parser.add_argument("--out",     default="splunk_events/feed.jsonl", help="Output JSONL file")
    args = parser.parse_args()
    process_reports(args.reports, args.out)

if __name__ == "__main__":
    main()
