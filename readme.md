# IOC Reputation & Telemetry Pipeline

A free, self-contained threat intelligence pipeline that checks whether an IP address, domain, URL, or file hash is malicious — and tells you who is behind it, what campaign it belongs to, and what techniques they are using.

No paid subscriptions. No vendor lock-in. Just four free public feeds, a local cache, and a single Python file.

---

## The Problem

Security teams deal with hundreds or thousands of suspicious indicators every day — IPs from firewall logs, domains from phishing alerts, file hashes from endpoint detections. Manually checking each one against threat intel platforms is slow, expensive, and doesn't scale.

Commercial solutions like VirusTotal or Recorded Future are powerful but come with cost and rate limits that make bulk lookups impractical for smaller teams or personal labs.

---

## What This Does

This pipeline automates the enrichment of IOCs against four free public feeds, caches every result locally so repeated lookups are instant, and outputs a clean report you can act on immediately.

You give it a list of indicators. It tells you:

- **Is it malicious?** — a 0–100 reputation score and a CLEAN / LOW / MEDIUM / HIGH severity label
- **Where is it?** — country and ASN for IP addresses
- **Who is behind it?** — threat actor or APT attribution from OTX
- **What campaign?** — campaign names with direct links to the OTX pulse
- **What techniques?** — MITRE ATT&CK TTP IDs extracted from pulse data
- **What malware family?** — family name for file hashes from MalwareBazaar
- **What tags?** — all community threat tags, deduplicated and normalised

---

## The Four Free Feeds

| Feed | What it covers | Key data returned |
|---|---|---|
| **AbuseIPDB** | IPv4 addresses | Abuse confidence score, country, ISP, report count |
| **OTX AlienVault** | IPs, domains, URLs, hashes | Pulse count, tags, adversary, campaigns, TTPs, ASN |
| **URLHaus** | Malicious URLs and domains | Live/offline status, malware type, first/last seen |
| **MalwareBazaar** | File hashes | Malware family, file type, first seen |

Together they cover every IOC type a typical security operation encounters.

---

## How It Works

```
Your IOC list  (.txt or .csv)
        │
        ▼
  Check local SQLite cache
        │
        ├── Fresh result found  ──►  Return immediately (no API call)
        │
        └── Missing or stale
                  │
                  ▼
            Call the right feeds
            for each IOC type
                  │
                  ▼
            Aggregate scores
            Extract all fields
                  │
                  ▼
            Save to cache
                  │
            ┌─────┴─────┐
            ▼           ▼
        Terminal      CSV + JSON
        (colour)       report
```

The local cache means you can run the same list multiple times — on day 1 it hits the APIs, on day 2 everything loads from disk in milliseconds. Cache entries expire after 7 days by default so results stay fresh without hammering the free-tier rate limits.

---

## Scoring

Every IOC ends up with a single 0–100 score aggregated from whichever feeds apply to its type.

For IP addresses, AbuseIPDB carries 60% of the weight and OTX carries 40%. When both independently confirm something is dangerous (both ≥ 70), the higher score wins outright rather than being softened by averaging.

For domains, URLs, and hashes the worst signal wins — if any feed says it is actively malicious, the final score reflects that.

| Score | Severity | Meaning |
|---|---|---|
| 0 | 🟢 CLEAN | Never reported anywhere |
| 1–39 | 🔵 LOW | Seen somewhere, low confidence |
| 40–74 | 🟡 MEDIUM | Notable presence, worth investigating |
| 75–100 | 🔴 HIGH | Strongly flagged, treat as malicious |

---

## Output

**Terminal** — colour-coded table with one row per IOC. Tags, TTPs, and campaign links printed on indented lines below each row.

**CSV** — one row per IOC with all enriched fields including per-feed raw scores. Ready to load into Excel, a SIEM, or any downstream tooling.

**JSON** — optional structured export with `campaigns_detail` as a proper list of `{name, url}` objects rather than a flat string.

---

## Quickstart

```bash
# Install dependencies
pip install requests urllib3

# Set your API keys (free accounts)
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."

# Run against a list of IOCs
python ioc_pipeline_v2.py --file iocs.txt

# Show only medium severity and above, also write JSON
python ioc_pipeline_v2.py --file iocs.txt --min-score 40 --json
```

Your input file is just one IOC per line — the script detects whether each line is an IP, domain, URL, or hash automatically.

---

## Versioning

| Version | Highlights |
|---|---|
| **v1** | Core pipeline — four feeds, SQLite cache, terminal + CSV output, full scoring logic |
| **v2** | Tag deduplication, campaign links, MITRE TTPs, per-feed score columns, `--min-score` filter, JSON export |

---

## Free API Registration

| Feed | Registration | Rate limit (free tier) |
|---|---|---|
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com) | 1,000 checks / day |
| OTX AlienVault | [otx.alienvault.com](https://otx.alienvault.com) | Generous, no hard published limit |
| URLHaus | No key required | No limit |
| MalwareBazaar | No key required | No limit |

The local cache is the main tool for staying within free-tier limits on large batches — once an IOC is cached it costs zero API calls until it expires.
