# IOC Reputation & Telemetry Pipeline — v2

**Version:** 2.0  
**Status:** Current Release  
**File:** `ioc_pipeline_v2.py`  
**Upgraded from:** v1

---

## What Changed in v2

| Area | v1 | v2 |
|---|---|---|
| Tags | Capped at 10, no normalisation | All tags, lowercased, fully deduplicated across all pulses |
| Campaigns | Name only, capped at 5 | Name + OTX pulse URL, no cap, deduplicated by (name, url) pair |
| TTPs | Not extracted | MITRE ATT&CK technique IDs from OTX `attack_ids`, sorted |
| Per-feed scores | Aggregated only | Separate columns in CSV: `score_abuseipdb`, `score_otx`, `score_urlhaus`, `score_malwarebazaar` |
| Output formats | Terminal + CSV | Terminal + CSV + optional JSON (`--json`) |
| Filtering | None | `--min-score N` suppresses results below threshold |
| Campaign terminal display | One line, semicolon-separated | One line per campaign with its URL printed inline |

---

## Overview

A lightweight, free-tier threat intelligence pipeline that enriches Indicators of Compromise (IOCs) against four public feeds, caches results locally in SQLite, and outputs a colour-coded terminal report alongside a CSV and optional JSON export.

No paid APIs. No external services beyond the four feeds. Runs from a single Python file.

---

## Supported IOC Types

| Type | Example |
|---|---|
| `IPv4` | `91.230.168.133` |
| `domain` | `malware.wicar.org` |
| `hostname` | `evil.internal.net` |
| `url` | `http://evil.com/payload.exe` |
| `hash` | SHA-256 / SHA-1 / MD5 |

Type is auto-detected when reading `.txt` files. For `.csv` input, an explicit `type` column overrides auto-detection.

---

## Feed Coverage

| Feed | IPv4 | Domain / Hostname | URL | Hash |
|---|:---:|:---:|:---:|:---:|
| AbuseIPDB | ✅ | — | — | — |
| OTX AlienVault | ✅ | ✅ | ✅ | ✅ |
| URLHaus | — | ✅ | ✅ | — |
| MalwareBazaar | — | — | — | ✅ |

---

## Enriched Output Fields

| Field | Source | Description |
|---|---|---|
| `score` | Aggregated | Final reputation score, 0–100 |
| `severity` | Derived | `CLEAN` / `LOW` / `MEDIUM` / `HIGH` |
| `country` | AbuseIPDB → OTX | Two-letter country code |
| `asn` | OTX | Autonomous System Number |
| `tags` | OTX pulses | All tags, lowercased, deduplicated, semicolon-separated |
| `adversary` | OTX pulses | First non-empty threat actor / APT name across pulses |
| `campaigns` | OTX pulses | `"Name \| URL"` pairs, separated by ` \|\| ` |
| `malware_family` | MalwareBazaar | Malware family name (`signature` field) |
| `ttps` | OTX `attack_ids` | MITRE ATT&CK technique IDs, sorted, semicolon-separated |
| `score_abuseipdb` | AbuseIPDB | Raw feed score (IPv4 only) |
| `score_otx` | OTX | Raw OTX pulse score |
| `score_urlhaus` | URLHaus | Raw URLHaus score (domain/url only) |
| `score_malwarebazaar` | MalwareBazaar | Raw MalwareBazaar score (hash only) |
| `status` | Internal | `cached` / `new` / `error` |

---

## Tag Deduplication — v2 Detail

In v1, tags were collected per-pulse and capped at 10. In v2 the logic is:

1. Iterate all pulses in the OTX response.
2. For each tag, strip whitespace and lowercase it.
3. Check against a `seen` set — if already present, skip.
4. Otherwise add to the ordered list and to the `seen` set.

The result is a fully deduplicated, case-normalised list with **no cap** — every tag from every pulse is preserved exactly once, in first-seen order.

In the CSV this is written as a single semicolon-separated string. In the JSON output it is kept as a list.

---

## Campaign Links — v2 Detail

Each OTX pulse is treated as a campaign entry. The URL is constructed as follows:

1. If the pulse has an `id` field → URL is `https://otx.alienvault.com/pulse/<id>`
2. Otherwise, if the pulse has a direct `url` field → that value is used.
3. Otherwise → URL is left empty.

In the CSV, each campaign is serialised as `"Name | URL"` and entries are separated by `  ||  `. In the JSON output, `campaigns_detail` is a list of `{"name": str, "url": str}` objects. In the terminal, each campaign is printed on its own indented line:

```
           campaign  : Operation Fancy Bear  →  https://otx.alienvault.com/pulse/abc123
           campaign  : Winter Storm 2024     →  https://otx.alienvault.com/pulse/def456
```

---

## Scoring Logic

### Per-feed scores

**AbuseIPDB** returns a native `abuseConfidenceScore` (0–100) based on community abuse reports.

**OTX pulse score** is derived from the pulse count:

| Pulse count | Score |
|---|---|
| 0 | 0 |
| 1 | 30 |
| 2–4 | 50 |
| 5–9 | 70 |
| 10+ | 90 (capped at 100) |

**URLHaus** maps URL/host status to a score:

| Status | Score |
|---|---|
| `no_results` | 0 |
| Known but offline | 40 |
| Actively serving malware (`online`) | 80 |

**MalwareBazaar** is binary — found scores 90, not found scores 0.

### Aggregation

**IPv4** — weighted average with override:

```
final = (AbuseIPDB × 0.60) + (OTX × 0.40)
```

If both AbuseIPDB ≥ 70 and OTX ≥ 70, `max(AbuseIPDB, OTX)` is used directly.

**Domain / hostname / URL** — worst signal wins:

```
final = max(OTX score, URLHaus score)
```

**Hash** — worst signal wins:

```
final = max(OTX score, MalwareBazaar score)
```

### Severity thresholds

| Score range | Severity |
|---|---|
| 0 | 🟢 CLEAN |
| 1–39 | 🔵 LOW |
| 40–74 | 🟡 MEDIUM |
| 75–100 | 🔴 HIGH |

---

## Architecture

```
Input file (.txt / .csv)
        │
        ▼
  Type detection
        │
        ▼
  SQLite cache check
    ├── Fresh (< N days) ──► Return cached result (incl. per-feed scores)
    └── Missing / stale
              │
              ▼
        Branch by type
         ├── IPv4    → AbuseIPDB + OTX
         ├── domain  → OTX + URLHaus
         ├── url     → OTX + URLHaus
         └── hash    → OTX + MalwareBazaar
              │
              ▼
        HTTP retry layer (3 attempts, exponential backoff)
              │
              ▼
        Score aggregation  (per-feed scores stored separately)
        Field extraction:
          tags (dedup) · campaigns (name + URL) · adversary
          ttps · asn · country · malware_family
              │
              ▼
        Write to SQLite cache  (_per_feed stored inside raw JSON)
              │
        ┌─────┴──────────┐
        ▼                ▼
  --min-score filter   (all results still cached regardless)
        │
   ┌────┴────────┬──────────┐
   ▼             ▼          ▼
Terminal       CSV       JSON (--json flag)
(colour)   (ioc_report) (ioc_report.json)
```

---

## Local Cache

Results are stored in `ioc_cache.db` (SQLite, WAL mode).

| Column | Type | Description |
|---|---|---|
| `ioc` | TEXT (PK) | The indicator value |
| `ioc_type` | TEXT | Detected or declared type |
| `reputation_score` | INTEGER | Aggregated 0–100 score |
| `data` | TEXT | Full raw feed payloads + `_per_feed` scores (JSON) |
| `last_updated` | TEXT | ISO-8601 timestamp |

Per-feed scores are stored inside the `data` JSON under the key `_per_feed` so they survive cache round-trips and are available without re-fetching.

---

## Setup

### Requirements

```bash
pip install requests urllib3
```

### API keys

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"
```

> OTX keys are free at [otx.alienvault.com](https://otx.alienvault.com).  
> AbuseIPDB keys are free at [abuseipdb.com](https://www.abuseipdb.com).  
> URLHaus and MalwareBazaar require no API key.

---

## Input File Format

### Plain text (`.txt`)

One IOC per line. Lines starting with `#` are skipped. Type is auto-detected.

```
# My IOC list
91.230.168.133
malware.wicar.org
http://evil.com/payload.exe
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### CSV (`.csv`)

Two columns: `ioc` and `type`. Header row is auto-detected. If `type` is missing, it is auto-detected.

```csv
ioc,type
91.230.168.133,IPv4
malware.wicar.org,hostname
http://evil.com/payload.exe,url
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,hash
```

---

## Usage

```bash
# Basic run
python ioc_pipeline_v2.py --file iocs.txt

# Custom output file
python ioc_pipeline_v2.py --file iocs.csv --out results_2026_03.csv

# Also write JSON
python ioc_pipeline_v2.py --file iocs.txt --json

# Only show MEDIUM and above
python ioc_pipeline_v2.py --file iocs.txt --min-score 40

# Shorter cache window
python ioc_pipeline_v2.py --file iocs.txt --cache-days 1

# Custom DB
python ioc_pipeline_v2.py --file iocs.txt --db /data/cache.db
```

### CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--file` / `-f` | *(required)* | Input `.txt` or `.csv` file |
| `--out` / `-o` | `ioc_report.csv` | Output CSV file path |
| `--json` | off | Also write JSON report (same stem as `--out`) |
| `--min-score` | `0` | Suppress output for IOCs below this score |
| `--cache-days` | `7` | Cache expiry in days |
| `--db` | `ioc_cache.db` | SQLite database path |

> `--min-score` affects **output only**. All results are still written to the SQLite cache regardless of score.

---

## Terminal Output

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  SEV     SCR  STATUS    TYPE        CC    ASN             ADVERSARY             FAMILY            IOC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  HIGH     88  new       IPv4        RU    AS12345         APT28                 —                 91.230.168.133
           tags      : botnet; c2; scanning; russia; apt28; fancy-bear
           ttps      : T1071; T1059; T1190
           campaign  : Operation Fancy Bear  →  https://otx.alienvault.com/pulse/abc123
           campaign  : Winter Storm 2024     →  https://otx.alienvault.com/pulse/def456
  CLEAN     0  cached    domain      —     —               —                     —                 google.com
  HIGH     90  new       hash        —     —               —                     Emotet            275a021b...
           tags      : emotet; trojan; malspam; loader; banking
           campaign  : Emotet Resurgence Q1  →  https://otx.alienvault.com/pulse/xyz789
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  Processed : 3 IOCs  (2 live API calls, 1 from cache)

  HIGH     ██  (2)
  CLEAN    █   (1)
```

---

## CSV Output

Columns written to the CSV report:

```
ioc, type, score, severity, country, asn,
tags, adversary, campaigns, malware_family, ttps,
score_abuseipdb, score_otx, score_urlhaus, score_malwarebazaar,
status
```

Multi-value fields (`tags`, `ttps`) are semicolon-separated.  
Campaign entries use the format `Name | URL` separated by `  ||  `.

---

## JSON Output

Enabled with `--json`. Written to the same path as `--out` with a `.json` extension.

Each entry in the JSON array contains all CSV fields plus a structured `campaigns_detail` list:

```json
{
  "ioc": "91.230.168.133",
  "type": "IPv4",
  "score": 88,
  "severity": "HIGH",
  "country": "RU",
  "asn": "AS12345",
  "tags": "botnet; c2; scanning; russia",
  "adversary": "APT28",
  "campaigns": "Operation Fancy Bear | https://otx.alienvault.com/pulse/abc123",
  "campaigns_detail": [
    { "name": "Operation Fancy Bear", "url": "https://otx.alienvault.com/pulse/abc123" },
    { "name": "Winter Storm 2024",    "url": "https://otx.alienvault.com/pulse/def456" }
  ],
  "malware_family": "",
  "ttps": "T1071; T1059",
  "score_abuseipdb": 90,
  "score_otx": 50,
  "score_urlhaus": "",
  "score_malwarebazaar": "",
  "status": "new"
}
```

---

## Reliability Features

**HTTP retry with exponential backoff** — 3 attempts on `429`, `500`, `502`, `503`, `504` (1 s → 2 s → 4 s).

**Rate limiting** — 0.5 s delay between live API calls to protect free-tier quotas.

**Per-feed score persistence** — stored inside the cache JSON under `_per_feed` so they are available on cache hits without re-fetching.

**Safe cache timestamps** — `datetime.fromisoformat()` with `strptime` fallback for legacy v1 entries.

**Context-managed DB connection** — always closed even on mid-run errors.

**WAL mode** — safe for concurrent reads.

---

## Known Limitations in v2

- AbuseIPDB v2 basic tier does not return ASN — sourced from OTX only.
- OTX adversary field takes the first non-empty value across pulses; multiple attributed actors are not all captured.
- URLHaus is not queried for raw IPv4 addresses.
- `--min-score` suppresses terminal and file output only; the SQLite cache always receives all results.

---

## File Structure

```
ioc_pipeline_v2.py     Main script
ioc_cache.db           SQLite cache (auto-created on first run)
ioc_report.csv         CSV output  (auto-created on each run)
ioc_report.json        JSON output (created when --json is passed)
iocs_sample.txt        Sample plain-text input
iocs_sample.csv        Sample CSV input
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | Yes (for IPv4) | — | AbuseIPDB API key |
| `OTX_API_KEY` | Yes | — | OTX AlienVault API key |
| `CACHE_EXPIRY_DAYS` | No | `7` | Override cache TTL |
| `IOC_DB_PATH` | No | `ioc_cache.db` | Override database path |
