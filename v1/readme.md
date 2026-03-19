# IOC Reputation & Telemetry Pipeline — v1

**Version:** 1.0  
**Status:** Initial Release  
**File:** `ioc_pipeline.py`

---

## Overview

A lightweight, free-tier threat intelligence pipeline that enriches Indicators of Compromise (IOCs) against four public feeds, caches results locally, and outputs a colour-coded terminal report alongside a CSV export.

No paid APIs. No external services beyond the four feeds. Runs entirely from a single Python file.

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
| `tags` | OTX pulses | Deduplicated threat tags (max 10) |
| `adversary` | OTX pulses | Threat actor or APT name |
| `campaigns` | OTX pulse names | Associated campaign names (max 5) |
| `malware_family` | MalwareBazaar | Malware family name (hashes only) |
| `status` | Internal | `cached` / `new` / `error` |

---

## Scoring Logic

### Per-feed scores

**AbuseIPDB** returns a native `abuseConfidenceScore` (0–100) based on community abuse reports.

**OTX pulse score** is derived from the pulse count associated with the indicator:

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

**MalwareBazaar** is binary — found in the database scores 90, not found scores 0.

### Aggregation

**IPv4** — weighted average with override:

```
final = (AbuseIPDB × 0.60) + (OTX × 0.40)
```

If both AbuseIPDB ≥ 70 and OTX ≥ 70, the higher of the two is used directly (confirmed-bad signals are not softened by averaging).

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
    ├── Fresh (< N days) ──► Return cached result
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
        HTTP retry layer
        (3 attempts, exponential backoff)
              │
              ▼
        Score aggregation
        Field extraction
              │
              ▼
        Write to SQLite cache
              │
        ┌─────┴─────┐
        ▼           ▼
   Terminal      CSV export
   (colour)    (ioc_report.csv)
```

---

## Local Cache

Results are stored in a SQLite database (`ioc_cache.db` by default).

| Column | Type | Description |
|---|---|---|
| `ioc` | TEXT (PK) | The indicator value |
| `ioc_type` | TEXT | Detected or declared type |
| `reputation_score` | INTEGER | Aggregated 0–100 score |
| `data` | TEXT | Full raw feed payloads (JSON) |
| `last_updated` | TEXT | ISO-8601 timestamp |

Cache entries expire after `CACHE_EXPIRY_DAYS` (default: 7). Stale entries are refreshed transparently on next run. WAL mode is enabled for safe concurrent reads.

---

## Setup

### Requirements

```bash
pip install requests urllib3
```

### API keys

Set as environment variables — never hard-code them in the script.

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

One IOC per line. Lines starting with `#` are treated as comments and skipped. Type is auto-detected.

```
# My IOC list
91.230.168.133
malware.wicar.org
http://evil.com/payload.exe
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### CSV (`.csv`)

Two columns: `ioc` and `type`. A header row is auto-detected and skipped. If the `type` column is missing or empty, type is auto-detected.

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
# Basic run — reads iocs.txt, writes ioc_report.csv
python ioc_pipeline.py --file iocs.txt

# Custom output file
python ioc_pipeline.py --file iocs.csv --out results_2026_03.csv

# Shorter cache window (re-check everything older than 1 day)
python ioc_pipeline.py --file iocs.txt --cache-days 1

# Custom database path
python ioc_pipeline.py --file iocs.txt --db /data/my_cache.db
```

### CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--file` / `-f` | *(required)* | Input `.txt` or `.csv` file |
| `--out` / `-o` | `ioc_report.csv` | Output CSV file |
| `--cache-days` | `7` | Cache expiry in days |
| `--db` | `ioc_cache.db` | SQLite database path |

---

## Terminal Output

```
──────────────────────────────────────────────────────────────────────────────────────────────────
  SEV     SCR  STATUS    TYPE        CC    ASN           ADVERSARY           FAMILY            IOC
──────────────────────────────────────────────────────────────────────────────────────────────────
  HIGH     88  new       IPv4        RU    AS12345       APT28               —                 91.230.168.133
                          tags      : botnet; c2; scanning; russia
                          campaigns : Operation Fancy Bear; Winter Storm 2024
  CLEAN     0  cached    domain      —     —             —                   —                 google.com
  HIGH     90  new       hash        —     —             —                   Emotet            275a021b...
──────────────────────────────────────────────────────────────────────────────────────────────────

  Processed : 3 IOCs  (2 live API calls, 1 from cache)

  HIGH     ██  (2)
  CLEAN    █   (1)
```

Severity colours: 🔴 HIGH (red) · 🟡 MEDIUM (yellow) · 🔵 LOW (blue) · 🟢 CLEAN (green).

Tags and campaign names are printed on indented lines below the main row, only when present.

---

## CSV Output

The report written to `ioc_report.csv` contains one row per IOC with the following columns:

```
ioc, type, score, severity, country, asn, tags, adversary, campaigns, malware_family, status
```

Multi-value fields (`tags`, `campaigns`) are semicolon-separated within a single cell.

---

## Reliability Features

**HTTP retry with exponential backoff** — every outbound request is wrapped in a retry adapter. On `429`, `500`, `502`, `503`, or `504` responses the adapter waits and retries up to 3 times (1 s → 2 s → 4 s). If all attempts fail the IOC is scored 0 and marked `error`.

**Rate limiting** — a 0.5-second delay is inserted between live API calls to avoid triggering rate limits during large batch runs.

**Safe cache timestamps** — `datetime.fromisoformat()` is used for all timestamp parsing, with a `strptime` fallback for legacy entries written by older versions.

**Context-managed database connection** — the SQLite connection is always closed via a `contextmanager`, even if the pipeline crashes mid-run.

**WAL mode** — the database runs in Write-Ahead Logging mode, safe for concurrent readers.

---

## Known Limitations in v1

- AbuseIPDB v2 basic tier does not return ASN in the response; ASN is sourced from OTX only.
- OTX adversary extraction takes the first non-empty value across pulses — multiple adversaries attributed to the same IOC are not fully captured.
- URLHaus is not queried for IPv4 addresses (it is a URL/host feed).
- No MITRE ATT&CK TTP extraction in this version.
- No confidence threshold filtering — all IOCs above score 0 are reported regardless of severity.

---

## Planned for v2

- MITRE TTP extraction from OTX pulse descriptions
- Per-feed raw score columns in CSV output
- `--min-score` filter flag to suppress low-noise results
- `--json` output flag alongside CSV
- Confidence weighting per feed based on IOC type reliability

---

## File Structure

```
ioc_pipeline.py      Main script
ioc_cache.db         SQLite cache (auto-created on first run)
ioc_report.csv       Output report (auto-created on each run)
iocs_sample.txt      Sample plain-text input
iocs_sample.csv      Sample CSV input
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | Yes (for IPv4) | — | AbuseIPDB API key |
| `OTX_API_KEY` | Yes | — | OTX AlienVault API key |
| `CACHE_EXPIRY_DAYS` | No | `7` | Override cache TTL |
| `IOC_DB_PATH` | No | `ioc_cache.db` | Override database path |
