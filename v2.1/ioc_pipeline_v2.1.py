"""
IOC Reputation & Telemetry Pipeline  —  v2.1
=============================================
Feeds       : AbuseIPDB · OTX AlienVault · URLHaus · MalwareBazaar
Input       : .txt (one IOC per line)  |  .csv (columns: ioc, type)
Output      : terminal (colour)  +  CSV report  +  optional JSON

What changed in v2.1 vs v2
---------------------------
  - Refanging : defanged IOCs are automatically cleaned on ingestion
                before type detection, cache lookup, or API calls.
                Patterns handled:
                  185(.)199(.)109(.)153  →  185.199.109.153
                  185[.]199[.]109[.]153  →  185.199.109.153
                  evil[.]com             →  evil.com
                  hxxp://evil.com        →  http://evil.com
                  hxxps://evil.com       →  https://evil.com
                  hXXp://evil.com        →  http://evil.com   (case-insensitive)
                The original defanged value is preserved as `ioc_raw` in
                the result and written to the CSV/JSON for traceability.

What changed in v2 vs v1
-------------------------
  - Tags       : fully deduplicated across all pulses, case-normalised,
                 no cap — every tag is preserved
  - Campaigns  : each entry now carries its OTX pulse URL when available
                 format in CSV → "Campaign Name | https://otx.../pulse/<id>"
  - Per-feed scores included as separate CSV columns
  - --min-score flag — suppress results below a threshold
  - --json flag  — write a JSON report alongside the CSV
  - MITRE ATT&CK TTP extraction from OTX pulse attack_ids

Enriched fields per IOC
-----------------------
  ioc_raw            Original value as supplied (may be defanged)
  score              0-100 aggregated
  severity           CLEAN / LOW / MEDIUM / HIGH
  country            Two-letter country code
  asn                Autonomous System Number
  tags               All OTX tags, deduplicated + case-normalised
  adversary          Threat actor / APT name (OTX)
  campaigns          "Name | URL" pairs from OTX pulses
  malware_family     Family name from MalwareBazaar
  ttps               MITRE ATT&CK technique IDs from OTX
  score_abuseipdb    Raw AbuseIPDB score (IPv4 only)
  score_otx          Raw OTX pulse score
  score_urlhaus      Raw URLHaus score (domain/url only)
  score_malwarebazaar Raw MalwareBazaar score (hash only)
  status             cached | new | error
  was_defanged       true | false

Environment variables
---------------------
  ABUSEIPDB_API_KEY
  OTX_API_KEY

Usage
-----
  python ioc_pipeline_v2.1.py --file iocs.txt
  python ioc_pipeline_v2.1.py --file iocs.csv --out report.csv
  python ioc_pipeline_v2.1.py --file iocs.txt --min-score 40 --json
  python ioc_pipeline_v2.1.py --file iocs.txt --cache-days 1 --db custom.db
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import re
import sqlite3
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
ABUSEIPDB_API_KEY: str   = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY:       str   = os.getenv("OTX_API_KEY", "")
CACHE_EXPIRY_DAYS: int   = int(os.getenv("CACHE_EXPIRY_DAYS", "7"))
DB_PATH:           str   = os.getenv("IOC_DB_PATH", "ioc_cache.db")
REQUEST_TIMEOUT:   int   = 10
RATE_LIMIT_DELAY:  float = 0.5

OTX_PULSE_BASE = "https://otx.alienvault.com/pulse"

# ---------------------------------------------------------------------------
# LOGGING
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# REFANGING  —  v2.1
# ---------------------------------------------------------------------------
# Ordered substitution rules applied left-to-right.
# Each rule is (compiled_pattern, replacement_string).
_REFANG_RULES: list[tuple[re.Pattern, str]] = [
    # hxxp / hxxps  (case-insensitive)
    (re.compile(r"^hxxps://",  re.IGNORECASE), "https://"),
    (re.compile(r"^hxxp://",   re.IGNORECASE), "http://"),
    # (.) and [.] dot substitutions — inside brackets, between digits or words
    (re.compile(r"\(\.\)"),  "."),
    (re.compile(r"\[\.\]"),  "."),
    # Stray lone parens/brackets sometimes wrap individual octets: 185(.)199
    # above already handled; catch any remaining [\.\]] or [\(\)] leftovers
    (re.compile(r"\[dot\]",  re.IGNORECASE), "."),
    (re.compile(r"\(dot\)",  re.IGNORECASE), "."),
]

def refang(raw: str) -> tuple[str, bool]:
    """
    Clean a potentially defanged IOC string.

    Returns:
        (refanged_value, was_defanged)

    was_defanged is True when the value changed, so callers can log/flag it.
    """
    value = raw.strip()
    for pattern, replacement in _REFANG_RULES:
        value = pattern.sub(replacement, value)
    return value, (value != raw.strip())

# ---------------------------------------------------------------------------
# HTTP SESSION  —  retry on transient failures
# ---------------------------------------------------------------------------
def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,                           # 1 s -> 2 s -> 4 s
        status_forcelist={429, 500, 502, 503, 504},
        allowed_methods={"GET", "POST"},
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session

_SESSION = _build_session()

# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------
def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ioc_data (
            ioc              TEXT PRIMARY KEY,
            ioc_type         TEXT,
            reputation_score INTEGER,
            data             TEXT,
            last_updated     TEXT
        )
    """)
    conn.commit()
    return conn

@contextmanager
def db_connection(db_path: str = DB_PATH):
    conn = init_db(db_path)
    try:
        yield conn
    finally:
        conn.close()

# ---------------------------------------------------------------------------
# TYPE AUTO-DETECTION
# ---------------------------------------------------------------------------
_HASH_RE = re.compile(
    r"^[0-9a-fA-F]{32}$"    # MD5
    r"|^[0-9a-fA-F]{40}$"   # SHA-1
    r"|^[0-9a-fA-F]{64}$"   # SHA-256
)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

def detect_type(ioc: str) -> str:
    """Infer IOC type from its refanged value."""
    ioc = ioc.strip()
    if _HASH_RE.match(ioc):
        return "hash"
    if _URL_RE.match(ioc):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "IPv4"
    except ValueError:
        pass
    return "domain"

# ---------------------------------------------------------------------------
# FEED 1  —  AbuseIPDB  (IPv4)
# ---------------------------------------------------------------------------
def feed_abuseipdb(ip: str) -> tuple[int, dict]:
    if not ABUSEIPDB_API_KEY:
        log.warning("ABUSEIPDB_API_KEY not set — skipping.")
        return 0, {}
    try:
        resp = _SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return int(data.get("abuseConfidenceScore", 0)), data
    except Exception as exc:
        log.error("AbuseIPDB error for %s: %s", ip, exc)
    return 0, {}

# ---------------------------------------------------------------------------
# FEED 2  —  OTX AlienVault  (IPv4 · domain · url · hash)
# ---------------------------------------------------------------------------
_OTX_TYPE_MAP = {
    "IPv4":     "IPv4",
    "domain":   "domain",
    "hostname": "domain",
    "url":      "url",
    "hash":     "file",
}

def feed_otx(ioc: str, ioc_type: str) -> dict:
    if not OTX_API_KEY:
        log.warning("OTX_API_KEY not set — skipping.")
        return {}
    otype = _OTX_TYPE_MAP.get(ioc_type)
    if not otype:
        log.warning("OTX: unsupported type '%s'", ioc_type)
        return {}
    try:
        resp = _SESSION.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otype}/{ioc}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log.error("OTX error for %s (%s): %s", ioc, ioc_type, exc)
    return {}

# ---------------------------------------------------------------------------
# FEED 3  —  URLHaus  (url · domain · hostname)
# ---------------------------------------------------------------------------
def feed_urlhaus(ioc: str, ioc_type: str) -> dict:
    try:
        if ioc_type == "url":
            resp = _SESSION.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": ioc},
                timeout=REQUEST_TIMEOUT,
            )
        elif ioc_type in ("domain", "hostname"):
            resp = _SESSION.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": ioc},
                timeout=REQUEST_TIMEOUT,
            )
        else:
            return {}
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log.error("URLHaus error for %s: %s", ioc, exc)
    return {}

# ---------------------------------------------------------------------------
# FEED 4  —  MalwareBazaar  (hash)
# ---------------------------------------------------------------------------
def feed_malwarebazaar(hash_value: str) -> dict:
    try:
        resp = _SESSION.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        log.error("MalwareBazaar error for %s: %s", hash_value, exc)
    return {}

# ---------------------------------------------------------------------------
# FIELD EXTRACTORS
# ---------------------------------------------------------------------------
def extract_otx_fields(otx: dict) -> dict:
    pulses = otx.get("pulse_info", {}).get("pulses", [])

    # Tags — deduplicated, lowercased, first-seen order, no cap
    seen_tags: set[str] = set()
    tags: list[str] = []
    for pulse in pulses:
        for raw_tag in pulse.get("tags", []):
            normalised = raw_tag.strip().lower()
            if normalised and normalised not in seen_tags:
                seen_tags.add(normalised)
                tags.append(normalised)

    # Campaigns — deduplicated by (name, url), with OTX pulse link
    seen_campaigns: set[tuple[str, str]] = set()
    campaigns: list[dict] = []
    for pulse in pulses:
        name = (pulse.get("name") or "").strip()
        if not name:
            continue
        pulse_id = (pulse.get("id") or "").strip()
        url = f"{OTX_PULSE_BASE}/{pulse_id}" if pulse_id else (pulse.get("url") or "").strip()
        key = (name, url)
        if key not in seen_campaigns:
            seen_campaigns.add(key)
            campaigns.append({"name": name, "url": url})

    # Adversary — first non-empty across pulses
    adversary = ""
    for pulse in pulses:
        adv = (pulse.get("adversary") or "").strip()
        if adv:
            adversary = adv
            break

    # TTPs — MITRE ATT&CK technique IDs, deduplicated, sorted
    seen_ttps: set[str] = set()
    ttps: list[str] = []
    for pulse in pulses:
        for attack in pulse.get("attack_ids", []):
            tid = (attack.get("id") or "").strip()
            if tid and tid not in seen_ttps:
                seen_ttps.add(tid)
                ttps.append(tid)
    ttps.sort()

    return {
        "tags":      tags,
        "campaigns": campaigns,
        "adversary": adversary,
        "ttps":      ttps,
        "asn":       str(otx.get("asn",          "")).strip(),
        "country":   str(otx.get("country_code", "")).strip(),
    }

def extract_abuseipdb_geo(data: dict) -> dict:
    return {
        "country": str(data.get("countryCode", "")).strip(),
        "isp":     str(data.get("isp",         "")).strip(),
    }

def extract_malwarebazaar_family(mb: dict) -> str:
    if mb.get("query_status") != "ok":
        return ""
    data = mb.get("data", [])
    if isinstance(data, list) and data:
        return str(data[0].get("signature", "") or "").strip()
    return ""

# ---------------------------------------------------------------------------
# SCORING
# ---------------------------------------------------------------------------
def _otx_pulse_score(otx: dict) -> int:
    count = int(otx.get("pulse_info", {}).get("count", 0))
    if count == 0:  return 0
    if count == 1:  return 30
    if count < 5:   return 50
    if count < 10:  return 70
    return min(90 + (count - 10), 100)

def _urlhaus_score(uh: dict) -> int:
    if uh.get("query_status") == "no_results":
        return 0
    urls = uh.get("urls", []) or []
    if any(u.get("url_status") == "online" for u in urls):
        return 80
    return 40 if uh.get("query_status") not in ("", None) else 0

def _malwarebazaar_score(mb: dict) -> int:
    return 90 if mb.get("query_status") == "ok" else 0

def _aggregate_ip_score(abuse: int, otx: int) -> int:
    """60% AbuseIPDB + 40% OTX. Override with max when both >= 70."""
    weighted = int(abuse * 0.6 + otx * 0.4)
    if abuse >= 70 and otx >= 70:
        return max(abuse, otx)
    return weighted

def severity_label(score: int) -> str:
    if score >= 75: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >  0:  return "LOW"
    return "CLEAN"

# ---------------------------------------------------------------------------
# TERMINAL COLOURS
# ---------------------------------------------------------------------------
_COLORS = {
    "HIGH":   "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW":    "\033[94m",
    "CLEAN":  "\033[92m",
}
RESET = "\033[0m"

def _c(label: str) -> str:
    return _COLORS.get(label, "")

# ---------------------------------------------------------------------------
# CAMPAIGN SERIALISER
# ---------------------------------------------------------------------------
def _campaigns_to_str(campaigns: list[dict]) -> str:
    parts: list[str] = []
    for c in campaigns:
        name = c.get("name", "")
        url  = c.get("url",  "")
        parts.append(f"{name} | {url}" if url else name)
    return "  ||  ".join(parts)

# ---------------------------------------------------------------------------
# ENRICHED RESULT BUILDER
# ---------------------------------------------------------------------------
def _build_result(
    ioc: str,
    ioc_raw: str,
    ioc_type: str,
    final_score: int,
    raw: dict,
    status: str,
    was_defanged: bool = False,
    per_feed: dict | None = None,
) -> dict:
    otx_fields = extract_otx_fields(raw.get("otx", {}))
    mb_family  = extract_malwarebazaar_family(raw.get("malwarebazaar", {}))
    ab_geo     = extract_abuseipdb_geo(raw.get("abuseipdb", {}))

    country = ab_geo["country"] or otx_fields["country"]
    asn     = otx_fields["asn"]
    pf      = per_feed or {}

    return {
        # Identity
        "ioc":               ioc,           # refanged (canonical)
        "ioc_raw":           ioc_raw,       # original as supplied
        "was_defanged":      was_defanged,
        "type":              ioc_type,
        # Scoring
        "score":             final_score,
        "severity":          severity_label(final_score),
        # Geo / network
        "country":           country,
        "asn":               asn,
        # Threat intel
        "tags":              "; ".join(otx_fields["tags"]),
        "adversary":         otx_fields["adversary"],
        "campaigns":         _campaigns_to_str(otx_fields["campaigns"]),
        "campaigns_raw":     otx_fields["campaigns"],
        "malware_family":    mb_family,
        "ttps":              "; ".join(otx_fields["ttps"]),
        # Per-feed raw scores
        "score_abuseipdb":      pf.get("abuseipdb",     ""),
        "score_otx":            pf.get("otx",            ""),
        "score_urlhaus":        pf.get("urlhaus",         ""),
        "score_malwarebazaar":  pf.get("malwarebazaar",  ""),
        # Meta
        "status":            status,
        "raw":               raw,
    }

# ---------------------------------------------------------------------------
# CORE PIPELINE
# ---------------------------------------------------------------------------
def process_ioc(
    ioc_raw: str,
    ioc_type_hint: str,
    conn: sqlite3.Connection,
) -> dict:
    """
    Enrich one IOC.

    ioc_raw        : the value exactly as read from the input file
    ioc_type_hint  : type string from CSV column, or auto-detected from raw
    """
    # ── Refang first — everything downstream uses the clean value ────────────
    ioc, was_defanged = refang(ioc_raw)
    if was_defanged:
        log.info("Refanged: '%s'  →  '%s'", ioc_raw, ioc)

    # Re-detect type on refanged value if it came from a .txt (hint = auto)
    ioc_type = detect_type(ioc) if ioc_type_hint == "auto" else ioc_type_hint

    cursor = conn.cursor()

    # ── Cache check (keyed on refanged canonical value) ──────────────────────
    cursor.execute(
        "SELECT reputation_score, data, last_updated FROM ioc_data WHERE ioc = ?",
        (ioc,),
    )
    row = cursor.fetchone()
    if row:
        try:
            last_updated = datetime.fromisoformat(row[2])
        except ValueError:
            last_updated = datetime.strptime(row[2], "%Y-%m-%d %H:%M:%S")
        if datetime.now() - last_updated < timedelta(days=CACHE_EXPIRY_DAYS):
            cached_raw = json.loads(row[1])
            return _build_result(
                ioc, ioc_raw, ioc_type, row[0], cached_raw, "cached",
                was_defanged=was_defanged,
                per_feed=cached_raw.get("_per_feed", {}),
            )
        log.info("Cache stale for %s — refreshing.", ioc)

    # ── Live enrichment ──────────────────────────────────────────────────────
    log.info("Fetching: %s (%s)", ioc, ioc_type)
    final_score  = 0
    raw: dict    = {}
    per_feed: dict = {}
    status       = "new"

    try:
        if ioc_type == "IPv4":
            abuse_score, abuse_data = feed_abuseipdb(ioc)
            otx_data  = feed_otx(ioc, ioc_type)
            otx_score = _otx_pulse_score(otx_data)
            final_score = _aggregate_ip_score(abuse_score, otx_score)
            raw      = {"abuseipdb": abuse_data, "otx": otx_data}
            per_feed = {"abuseipdb": abuse_score, "otx": otx_score}

        elif ioc_type in ("domain", "hostname"):
            otx_data  = feed_otx(ioc, ioc_type)
            uh_data   = feed_urlhaus(ioc, ioc_type)
            otx_score = _otx_pulse_score(otx_data)
            uh_score  = _urlhaus_score(uh_data)
            final_score = max(otx_score, uh_score)
            raw      = {"otx": otx_data, "urlhaus": uh_data}
            per_feed = {"otx": otx_score, "urlhaus": uh_score}

        elif ioc_type == "url":
            otx_data  = feed_otx(ioc, ioc_type)
            uh_data   = feed_urlhaus(ioc, ioc_type)
            otx_score = _otx_pulse_score(otx_data)
            uh_score  = _urlhaus_score(uh_data)
            final_score = max(otx_score, uh_score)
            raw      = {"otx": otx_data, "urlhaus": uh_data}
            per_feed = {"otx": otx_score, "urlhaus": uh_score}

        elif ioc_type == "hash":
            otx_data  = feed_otx(ioc, ioc_type)
            mb_data   = feed_malwarebazaar(ioc)
            otx_score = _otx_pulse_score(otx_data)
            mb_score  = _malwarebazaar_score(mb_data)
            final_score = max(otx_score, mb_score)
            raw      = {"otx": otx_data, "malwarebazaar": mb_data}
            per_feed = {"otx": otx_score, "malwarebazaar": mb_score}

        else:
            log.warning("Unknown type '%s' for %s — skipped.", ioc_type, ioc)
            status = "error"

    except Exception as exc:
        log.error("Pipeline error for %s: %s", ioc, exc)
        raw    = {"error": str(exc)}
        status = "error"

    raw["_per_feed"] = per_feed

    # ── Write to cache (refanged key) ────────────────────────────────────────
    cursor.execute(
        """
        INSERT OR REPLACE INTO ioc_data
            (ioc, ioc_type, reputation_score, data, last_updated)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ioc, ioc_type, final_score, json.dumps(raw), datetime.now().isoformat()),
    )
    conn.commit()

    return _build_result(
        ioc, ioc_raw, ioc_type, final_score, raw, status,
        was_defanged=was_defanged, per_feed=per_feed,
    )

# ---------------------------------------------------------------------------
# FILE READER
# ---------------------------------------------------------------------------
def read_iocs(file_path: str) -> list[tuple[str, str]]:
    """
    Returns list of (raw_ioc_string, type_hint).
    type_hint is the explicit type from CSV, or "auto" for .txt files.
    Refanging happens later in process_ioc so the raw value is preserved.
    """
    path = Path(file_path)
    if not path.exists():
        log.error("File not found: %s", file_path)
        sys.exit(1)

    iocs: list[tuple[str, str]] = []

    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            sample = f.read(1024)
            f.seek(0)
            has_header = csv.Sniffer().has_header(sample)
            reader = csv.reader(f)
            if has_header:
                next(reader)
            for row in reader:
                if not row or not row[0].strip():
                    continue
                raw_ioc = row[0].strip()
                # For CSV, refang now to get the type, but pass original raw
                refanged, _ = refang(raw_ioc)
                itype = (
                    row[1].strip()
                    if len(row) > 1 and row[1].strip()
                    else detect_type(refanged)
                )
                iocs.append((raw_ioc, itype))
    else:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                iocs.append((line, "auto"))

    log.info("Loaded %d IOCs from %s", len(iocs), file_path)
    return iocs

# ---------------------------------------------------------------------------
# TERMINAL OUTPUT
# ---------------------------------------------------------------------------
def print_header() -> None:
    print(f"\n{'─' * 115}")
    print(
        f"  {'SEV':<7}  {'SCR':>3}  {'STATUS':<8}  {'TYPE':<10}  "
        f"{'CC':<4}  {'ASN':<14}  {'ADVERSARY':<20}  {'FAMILY':<16}  IOC"
    )
    print(f"{'─' * 115}")

def print_result(r: dict) -> None:
    sev   = r["severity"]
    color = _c(sev)
    # Show refanged IOC; append [defanged] marker when applicable
    ioc_display = r["ioc"]
    if r["was_defanged"]:
        ioc_display += f"  [defanged: {r['ioc_raw']}]"
    print(
        f"  {color}{sev:<7}{RESET}  "
        f"{r['score']:>3}  "
        f"{r['status']:<8}  "
        f"{r['type']:<10}  "
        f"{r['country']:<4}  "
        f"{r['asn']:<14}  "
        f"{r['adversary']:<20}  "
        f"{r['malware_family']:<16}  "
        f"{ioc_display}"
    )
    if r["tags"]:
        print(f"           tags      : {r['tags']}")
    if r["ttps"]:
        print(f"           ttps      : {r['ttps']}")
    for c in r.get("campaigns_raw", []):
        line = f"           campaign  : {c['name']}"
        if c.get("url"):
            line += f"  →  {c['url']}"
        print(line)

def print_summary(results: list[dict], live_calls: int) -> None:
    counts      = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    defanged_n  = sum(1 for r in results if r["was_defanged"])
    for r in results:
        counts[r["severity"]] += 1
    total = len(results)
    print(f"{'─' * 115}")
    print(f"\n  Processed  : {total} IOCs  "
          f"({live_calls} live API calls, {total - live_calls} from cache)")
    if defanged_n:
        print(f"  Refanged   : {defanged_n} IOC(s) were defanged and cleaned automatically")
    print()
    for label in ("HIGH", "MEDIUM", "LOW", "CLEAN"):
        c = counts[label]
        if c:
            bar = "█" * c
            print(f"  {_c(label)}{label:<7}{RESET}  {bar}  ({c})")
    print()

# ---------------------------------------------------------------------------
# CSV EXPORT
# ---------------------------------------------------------------------------
CSV_FIELDS = [
    "ioc", "ioc_raw", "was_defanged", "type", "score", "severity",
    "country", "asn",
    "tags", "adversary", "campaigns", "malware_family", "ttps",
    "score_abuseipdb", "score_otx", "score_urlhaus", "score_malwarebazaar",
    "status",
]

def write_csv(results: list[dict], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    log.info("CSV report saved  → %s", out_path)

# ---------------------------------------------------------------------------
# JSON EXPORT
# ---------------------------------------------------------------------------
def write_json(results: list[dict], out_path: str) -> None:
    export = []
    for r in results:
        row = {k: v for k, v in r.items() if k not in ("raw", "campaigns_raw")}
        row["campaigns_detail"] = r.get("campaigns_raw", [])
        export.append(row)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)
    log.info("JSON report saved → %s", out_path)

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main() -> None:
    global CACHE_EXPIRY_DAYS, DB_PATH

    parser = argparse.ArgumentParser(
        description=(
            "IOC Reputation Pipeline v2.1  —  "
            "AbuseIPDB · OTX · URLHaus · MalwareBazaar"
        )
    )
    parser.add_argument("--file",       "-f", required=True,
                        help="Input .txt or .csv file")
    parser.add_argument("--out",        "-o", default="ioc_report.csv",
                        help="Output CSV path (default: ioc_report.csv)")
    parser.add_argument("--json",       action="store_true",
                        help="Also write a JSON report (same stem as --out)")
    parser.add_argument("--min-score",  type=int, default=0,
                        help="Suppress output for IOCs below this score (default: 0)")
    parser.add_argument("--cache-days", type=int, default=CACHE_EXPIRY_DAYS,
                        help=f"Cache expiry days (default: {CACHE_EXPIRY_DAYS})")
    parser.add_argument("--db",         default=DB_PATH,
                        help=f"SQLite path (default: {DB_PATH})")
    args = parser.parse_args()

    CACHE_EXPIRY_DAYS = args.cache_days
    DB_PATH           = args.db

    iocs = read_iocs(args.file)
    if not iocs:
        log.error("No IOCs found — exiting.")
        sys.exit(1)

    all_results: list[dict] = []
    live_calls: int         = 0

    print_header()

    with db_connection(DB_PATH) as conn:
        for ioc_raw, itype in iocs:
            result = process_ioc(ioc_raw, itype, conn)
            all_results.append(result)
            if result["status"] == "new":
                live_calls += 1
                time.sleep(RATE_LIMIT_DELAY)

    displayed = [r for r in all_results if r["score"] >= args.min_score]
    for r in displayed:
        print_result(r)

    print_summary(all_results, live_calls)

    if args.min_score > 0:
        suppressed = len(all_results) - len(displayed)
        if suppressed:
            log.info("Suppressed %d result(s) below --min-score %d",
                     suppressed, args.min_score)

    write_csv(displayed, args.out)

    if args.json:
        json_path = str(Path(args.out).with_suffix(".json"))
        write_json(displayed, json_path)


if __name__ == "__main__":
    main()
