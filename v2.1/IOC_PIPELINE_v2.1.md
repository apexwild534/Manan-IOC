# IOC Reputation & Telemetry Pipeline — v2.1

**Version:** 2.1  
**Status:** Current Release  
**File:** `ioc_pipeline_v2.1.py`  
**Upgraded from:** v2

---

## What Changed in v2.1

One focused addition: **automatic defang detection and refanging on ingestion.**

Defanged IOCs — indicators deliberately obfuscated to prevent accidental clicks or auto-linking in reports and chat tools — are now cleaned transparently before any type detection, cache lookup, or API call happens.

| Area | v2 | v2.1 |
|---|---|---|
| Defanged input | Breaks type detection, fails API calls | Auto-cleaned silently on read |
| `ioc_raw` field | Not present | Original defanged value preserved for traceability |
| `was_defanged` field | Not present | `true` / `false` flag in CSV and JSON |
| Terminal display | IOC value only | Appends `[defanged: original]` when cleaned |
| Summary footer | Processed count only | Also reports how many IOCs were refanged |

Everything else — scoring, feeds, tag deduplication, campaign links, TTPs, per-feed scores, `--min-score`, `--json` — is carried over unchanged from v2.

---

## Overview

A lightweight, free-tier threat intelligence pipeline that enriches Indicators of Compromise (IOCs) against four public feeds, caches results locally in SQLite, and outputs a colour-coded terminal report alongside a CSV and optional JSON export.

Accepts both clean and defanged IOC lists with no preprocessing required.

---

## Defanging — What It Is and What Is Handled

**Defanged IOCs** are indicators with dots or protocol prefixes intentionally modified to make them safe to paste into emails, reports, tickets, and chat tools without triggering auto-linking or accidental navigation.

v2.1 handles the following patterns automatically:

| Defanged input | Refanged output | Pattern |
|---|---|---|
| `185(.)199(.)109(.)153` | `185.199.109.153` | `(.)` dot substitution |
| `185[.]199[.]109[.]153` | `185.199.109.153` | `[.]` dot substitution |
| `evil[.]com` | `evil.com` | `[.]` in domain |
| `evil(.)com` | `evil.com` | `(.)` in domain |
| `evil[dot]com` | `evil.com` | `[dot]` literal |
| `evil(dot)com` | `evil.com` | `(dot)` literal |
| `hxxp://evil.com` | `http://evil.com` | `hxxp` protocol |
| `hxxps://evil.com` | `https://evil.com` | `hxxps` protocol |
| `hXXp://evil.com` | `http://evil.com` | case-insensitive match |

Refanging is applied before type detection, so a defanged IP like `185(.)199(.)109(.)153` is correctly identified as `IPv4` and routed to AbuseIPDB + OTX.

The original defanged string is always preserved in `ioc_raw` and written to the CSV and JSON output for full traceability back to the source report or ticket.

---

## Traceability Fields

| Field | Description |
|---|---|
| `ioc` | The refanged, canonical value used for lookups and cache |
| `ioc_raw` | The original value exactly as it appeared in the input file |
| `was_defanged` | `True` if the value was modified during refanging, `False` otherwise |

---

## Supported IOC Types

| Type | Example |
|---|---|
| `IPv4` | `185.199.109.153` |
| `domain` | `malware.wicar.org` |
| `hostname` | `evil.internal.net` |
| `url` | `http://evil.com/payload.exe` |
| `hash` | SHA-256 / SHA-1 / MD5 |

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
| `ioc` | Refanged input | Canonical clean value |
| `ioc_raw` | Input file | Original value as supplied |
| `was_defanged` | Refang step | Whether the value was modified |
| `type` | Auto-detect / CSV | IOC type |
| `score` | Aggregated | Final reputation score, 0–100 |
| `severity` | Derived | `CLEAN` / `LOW` / `MEDIUM` / `HIGH` |
| `country` | AbuseIPDB → OTX | Two-letter country code |
| `asn` | OTX | Autonomous System Number |
| `tags` | OTX pulses | All tags, lowercased, deduplicated, semicolon-separated |
| `adversary` | OTX pulses | First non-empty threat actor / APT name |
| `campaigns` | OTX pulses | `"Name \| URL"` pairs separated by ` \|\| ` |
| `malware_family` | MalwareBazaar | Malware family name |
| `ttps` | OTX `attack_ids` | MITRE ATT&CK technique IDs, sorted |
| `score_abuseipdb` | AbuseIPDB | Raw feed score (IPv4 only) |
| `score_otx` | OTX | Raw OTX pulse score |
| `score_urlhaus` | URLHaus | Raw URLHaus score (domain/url only) |
| `score_malwarebazaar` | MalwareBazaar | Raw MalwareBazaar score (hash only) |
| `status` | Internal | `cached` / `new` / `error` |

---

## Scoring Logic

### Per-feed scores

**AbuseIPDB** — native `abuseConfidenceScore` (0–100).

**OTX pulse score:**

| Pulse count | Score |
|---|---|
| 0 | 0 |
| 1 | 30 |
| 2–4 | 50 |
| 5–9 | 70 |
| 10+ | 90 (capped at 100) |

**URLHaus:**

| Status | Score |
|---|---|
| `no_results` | 0 |
| Known but offline | 40 |
| Actively serving malware | 80 |

**MalwareBazaar** — found: 90, not found: 0.

### Aggregation

**IPv4** — `(AbuseIPDB × 0.60) + (OTX × 0.40)`. If both ≥ 70, `max(AbuseIPDB, OTX)` is used.

**Domain / hostname / URL** — `max(OTX, URLHaus)`.

**Hash** — `max(OTX, MalwareBazaar)`.

### Severity thresholds

| Score | Severity |
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
  Read raw IOC strings
        │
        ▼
  Refang  ◄── strips (.) [.] hxxp:// etc.
  (preserves ioc_raw for traceability)
        │
        ▼
  Type detection  (on refanged value)
        │
        ▼
  SQLite cache check  (keyed on refanged value)
    ├── Fresh  ──►  Return cached result
    └── Stale / missing
              │
              ▼
        Branch by type → call feeds
              │
              ▼
        Score aggregation + field extraction
              │
              ▼
        Write to cache
              │
        ┌─────┴──────────┐
        ▼                ▼
  --min-score filter
        │
   ┌────┴─────────┬────────────┐
   ▼              ▼            ▼
Terminal         CSV          JSON
(colour +     (ioc +        (structured,
defang marker) ioc_raw +    campaigns_detail
               was_defanged) as list)
```

---

## Setup

```bash
pip install requests urllib3

export ABUSEIPDB_API_KEY="your_key_here"
export OTX_API_KEY="your_key_here"
```

---

## Input File Format

The script accepts defanged IOCs directly — no preprocessing needed.

### Plain text (`.txt`)

```
# Defanged IPs from incident report
185(.)199(.)109(.)153
185[.]199[.]110[.]153

# Clean IOCs work exactly the same
8.8.8.8
malware.wicar.org
hxxp://evil.com/payload.exe
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### CSV (`.csv`)

```csv
ioc,type
185(.)199(.)109(.)153,IPv4
evil[.]com,domain
hxxps://phishing[.]site/login,url
```

---

## Usage

```bash
# Basic run
python ioc_pipeline_v2.1.py --file iocs.txt

# Custom output file
python ioc_pipeline_v2.1.py --file iocs.csv --out results.csv

# Also write JSON
python ioc_pipeline_v2.1.py --file iocs.txt --json

# Only show MEDIUM and above
python ioc_pipeline_v2.1.py --file iocs.txt --min-score 40

# Shorter cache window
python ioc_pipeline_v2.1.py --file iocs.txt --cache-days 1
```

### CLI arguments

| Argument | Default | Description |
|---|---|---|
| `--file` / `-f` | *(required)* | Input `.txt` or `.csv` file |
| `--out` / `-o` | `ioc_report.csv` | Output CSV file |
| `--json` | off | Also write JSON (same stem as `--out`) |
| `--min-score` | `0` | Suppress output below this score |
| `--cache-days` | `7` | Cache expiry in days |
| `--db` | `ioc_cache.db` | SQLite database path |

---

## Terminal Output

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  SEV     SCR  STATUS    TYPE        CC    ASN             ADVERSARY             FAMILY            IOC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  HIGH     72  new       IPv4        US    AS36459         —                     —                 185.199.109.153  [defanged: 185(.)199(.)109(.)153]
           tags      : cdn; github; hosting
  CLEAN     0  cached    domain      —     —               —                     —                 google.com
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  Processed  : 2 IOCs  (1 live API calls, 1 from cache)
  Refanged   : 1 IOC(s) were defanged and cleaned automatically

  HIGH     █  (1)
  CLEAN    █  (1)
```

---

## CSV Output

New columns added in v2.1 vs v2:

```
ioc, ioc_raw, was_defanged, type, score, severity,
country, asn, tags, adversary, campaigns, malware_family, ttps,
score_abuseipdb, score_otx, score_urlhaus, score_malwarebazaar,
status
```

---

## Version History

| Version | Key addition |
|---|---|
| v1 | Core pipeline — four feeds, SQLite cache, terminal + CSV, scoring |
| v2 | Tag deduplication, campaign links, TTPs, per-feed scores, `--min-score`, JSON |
| v2.1 | Defang / refang — accepts defanged input, preserves original in `ioc_raw` |

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ABUSEIPDB_API_KEY` | Yes (IPv4) | — | AbuseIPDB API key |
| `OTX_API_KEY` | Yes | — | OTX AlienVault API key |
| `CACHE_EXPIRY_DAYS` | No | `7` | Cache TTL in days |
| `IOC_DB_PATH` | No | `ioc_cache.db` | SQLite database path |
