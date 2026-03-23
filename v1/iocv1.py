"""
IOC Reputation & Telemetry Pipeline  —  v2 (enriched)
=======================================================
Feeds       : AbuseIPDB · OTX AlienVault · URLHaus · MalwareBazaar
Input       : .txt (one IOC per line)  |  .csv (columns: ioc, type)
Output      : terminal (colour)  +  CSV report

Enriched fields per IOC
-----------------------
  reputation_score   0-100 aggregated
  severity           CLEAN / LOW / MEDIUM / HIGH
  tags               OTX pulse tags (deduplicated)
  asn                Autonomous System Number
  country            Two-letter country code
  adversary          Threat actor / APT name (OTX)
  campaigns          Campaign names from OTX pulses
  malware_family     Family name from MalwareBazaar
  status             cached | new | error

Environment variables
---------------------
  ABUSEIPDB_API_KEY
  OTX_API_KEY

Usage
-----
  python ioc_pipeline.py --file iocs.txt
  python ioc_pipeline.py --file iocs.csv --out report.csv --cache-days 3
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
    """
    Returns (abuse_confidence_score 0-100, raw data).
    Raw data contains: abuseConfidenceScore, countryCode, isp, domain,
    totalReports, lastReportedAt, usageType.
    """
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
    """
    Returns raw OTX /general JSON.
    Key fields used downstream:
      pulse_info.count, pulse_info.pulses[].tags,
      pulse_info.pulses[].adversary, pulse_info.pulses[].name,
      pulse_info.pulses[].targeted_countries,
      asn, country_code (IPv4 only)
    """
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
    """
    Pull tags, adversary, campaigns, ASN, country from OTX response.
    Returns a dict with string/list values safe for CSV serialisation.
    """
    pulses   = otx.get("pulse_info", {}).get("pulses", [])

    # Tags — flat deduplicated list across all pulses
    tags: list[str] = []
    for p in pulses:
        for t in p.get("tags", []):
            t = t.strip()
            if t and t not in tags:
                tags.append(t)

    # Adversary — first non-empty adversary field across pulses
    adversary = ""
    for p in pulses:
        adv = (p.get("adversary") or "").strip()
        if adv:
            adversary = adv
            break

    # Campaigns — pulse names (good proxy for campaign names in OTX)
    campaigns: list[str] = []
    for p in pulses:
        name = (p.get("name") or "").strip()
        if name and name not in campaigns:
            campaigns.append(name)

    # ASN and country  (populated for IPv4 indicators)
    asn     = str(otx.get("asn", "")).strip()
    country = str(otx.get("country_code", "")).strip()

    return {
        "tags":      tags,
        "adversary": adversary,
        "campaigns": campaigns,
        "asn":       asn,
        "country":   country,
    }

def extract_abuseipdb_geo(data: dict) -> dict:
    """Pull ASN, country, ISP from AbuseIPDB response."""
    return {
        "asn":     str(data.get("abuseConfidenceScore", "")),   # not in v2 basic
        "country": str(data.get("countryCode", "")).strip(),
        "isp":     str(data.get("isp", "")).strip(),
    }

def extract_malwarebazaar_family(mb: dict) -> str:
    """Return the malware family name from MalwareBazaar or empty string."""
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
    """60 % AbuseIPDB + 40 % OTX. Override with max when both >= 70."""
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
# ENRICHED RESULT BUILDER
# ---------------------------------------------------------------------------
def _build_result(
    ioc: str,
    ioc_type: str,
    final_score: int,
    raw: dict,
    status: str,
) -> dict:
    """
    Flatten all enriched fields into one result dict ready for
    terminal printing and CSV export.
    """
    otx_fields = extract_otx_fields(raw.get("otx", {}))
    mb_family  = extract_malwarebazaar_family(raw.get("malwarebazaar", {}))

    # Country / ASN  —  prefer AbuseIPDB (more reliable for IPs),
    # fall back to OTX for domains and hashes
    ab_geo = extract_abuseipdb_geo(raw.get("abuseipdb", {}))
    country = ab_geo["country"] or otx_fields["country"]
    asn     = otx_fields["asn"]   # AbuseIPDB v2 basic doesn't return ASN

    return {
        "ioc":            ioc,
        "type":           ioc_type,
        "score":          final_score,
        "severity":       severity_label(final_score),
        "country":        country,
        "asn":            asn,
        "tags":           "; ".join(otx_fields["tags"][:10]),      # cap at 10
        "adversary":      otx_fields["adversary"],
        "campaigns":      "; ".join(otx_fields["campaigns"][:5]),  # cap at 5
        "malware_family": mb_family,
        "status":         status,
        "raw":            raw,     # kept for cache; not written to CSV directly
    }

# ---------------------------------------------------------------------------
# CORE PIPELINE
# ---------------------------------------------------------------------------
def process_ioc(ioc: str, ioc_type: str, conn: sqlite3.Connection) -> dict:
    ioc    = ioc.strip()
    cursor = conn.cursor()

    # ── Cache check ──────────────────────────────────────────────────────────
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
            return _build_result(
                ioc, ioc_type, row[0], json.loads(row[1]), "cached"
            )
        log.info("Cache stale for %s — refreshing.", ioc)

    # ── Live enrichment ──────────────────────────────────────────────────────
    log.info("Fetching: %s (%s)", ioc, ioc_type)
    final_score = 0
    raw: dict   = {}
    status      = "new"

    try:
        if ioc_type == "IPv4":
            abuse_score, abuse_data = feed_abuseipdb(ioc)
            otx_data    = feed_otx(ioc, ioc_type)
            otx_score   = _otx_pulse_score(otx_data)
            final_score = _aggregate_ip_score(abuse_score, otx_score)
            raw = {"abuseipdb": abuse_data, "otx": otx_data}

        elif ioc_type in ("domain", "hostname"):
            otx_data  = feed_otx(ioc, ioc_type)
            uh_data   = feed_urlhaus(ioc, ioc_type)
            final_score = max(_otx_pulse_score(otx_data), _urlhaus_score(uh_data))
            raw = {"otx": otx_data, "urlhaus": uh_data}

        elif ioc_type == "url":
            otx_data  = feed_otx(ioc, ioc_type)
            uh_data   = feed_urlhaus(ioc, ioc_type)
            final_score = max(_otx_pulse_score(otx_data), _urlhaus_score(uh_data))
            raw = {"otx": otx_data, "urlhaus": uh_data}

        elif ioc_type == "hash":
            otx_data  = feed_otx(ioc, ioc_type)
            mb_data   = feed_malwarebazaar(ioc)
            final_score = max(_otx_pulse_score(otx_data), _malwarebazaar_score(mb_data))
            raw = {"otx": otx_data, "malwarebazaar": mb_data}

        else:
            log.warning("Unknown type '%s' for %s — skipped.", ioc_type, ioc)
            status = "error"

    except Exception as exc:
        log.error("Pipeline error for %s: %s", ioc, exc)
        raw    = {"error": str(exc)}
        status = "error"

    # ── Write to cache ───────────────────────────────────────────────────────
    cursor.execute(
        """
        INSERT OR REPLACE INTO ioc_data
            (ioc, ioc_type, reputation_score, data, last_updated)
        VALUES (?, ?, ?, ?, ?)
        """,
        (ioc, ioc_type, final_score, json.dumps(raw), datetime.now().isoformat()),
    )
    conn.commit()

    return _build_result(ioc, ioc_type, final_score, raw, status)

# ---------------------------------------------------------------------------
# FILE READER
# ---------------------------------------------------------------------------
def read_iocs(file_path: str) -> list[tuple[str, str]]:
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
                ioc   = row[0].strip()
                itype = row[1].strip() if len(row) > 1 and row[1].strip() else detect_type(ioc)
                iocs.append((ioc, itype))
    else:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                iocs.append((line, detect_type(line)))

    log.info("Loaded %d IOCs from %s", len(iocs), file_path)
    return iocs

# ---------------------------------------------------------------------------
# TERMINAL OUTPUT
# ---------------------------------------------------------------------------
_COL_W = {
    "severity": 7,
    "score":    3,
    "status":   8,
    "type":     10,
    "country":  4,
    "asn":      12,
    "adversary":18,
    "family":   16,
}

def print_header() -> None:
    print(f"\n{'─' * 110}")
    print(
        f"  {'SEV':<7}  {'SCR':>3}  {'STATUS':<8}  {'TYPE':<10}  "
        f"{'CC':<4}  {'ASN':<12}  {'ADVERSARY':<18}  {'FAMILY':<16}  IOC"
    )
    print(f"{'─' * 110}")

def print_result(r: dict) -> None:
    sev   = r["severity"]
    color = _c(sev)
    print(
        f"  {color}{sev:<7}{RESET}  "
        f"{r['score']:>3}  "
        f"{r['status']:<8}  "
        f"{r['type']:<10}  "
        f"{r['country']:<4}  "
        f"{r['asn']:<12}  "
        f"{r['adversary']:<18}  "
        f"{r['malware_family']:<16}  "
        f"{r['ioc']}"
    )
    # Tags and campaigns on indented lines (only when present)
    if r["tags"]:
        print(f"  {'':7}   {'':3}   {'':8}   tags      : {r['tags']}")
    if r["campaigns"]:
        print(f"  {'':7}   {'':3}   {'':8}   campaigns : {r['campaigns']}")

def print_summary(results: list[dict], live_calls: int) -> None:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for r in results:
        counts[r["severity"]] += 1
    total = len(results)
    print(f"{'─' * 110}")
    print(f"\n  Processed : {total} IOCs  "
          f"({live_calls} live API calls, {total - live_calls} from cache)\n")
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
    "ioc", "type", "score", "severity",
    "country", "asn",
    "tags", "adversary", "campaigns", "malware_family",
    "status",
]

def write_csv(results: list[dict], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    log.info("CSV report saved to %s", out_path)

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main() -> None:
    global CACHE_EXPIRY_DAYS, DB_PATH
    
    parser = argparse.ArgumentParser(
        description=(
            "IOC Reputation Pipeline  —  "
            "AbuseIPDB · OTX · URLHaus · MalwareBazaar"
        )
    )
    parser.add_argument("--file", "-f", required=True,
                        help="Input .txt or .csv file")
    parser.add_argument("--out",  "-o", default="ioc_report.csv",
                        help="Output CSV path (default: ioc_report.csv)")
    parser.add_argument("--cache-days", type=int, default=CACHE_EXPIRY_DAYS,
                        help=f"Cache expiry days (default: {CACHE_EXPIRY_DAYS})")
    parser.add_argument("--db", default=DB_PATH,
                        help=f"SQLite path (default: {DB_PATH})")
    args = parser.parse_args()

    
    CACHE_EXPIRY_DAYS = args.cache_days
    DB_PATH           = args.db

    iocs = read_iocs(args.file)
    if not iocs:
        log.error("No IOCs found — exiting.")
        sys.exit(1)

    results:    list[dict] = []
    live_calls: int        = 0

    print_header()

    with db_connection(DB_PATH) as conn:
        for ioc, itype in iocs:
            result = process_ioc(ioc, itype, conn)
            print_result(result)
            results.append(result)
            if result["status"] == "new":
                live_calls += 1
                time.sleep(RATE_LIMIT_DELAY)

    print_summary(results, live_calls)
    write_csv(results, args.out)


if __name__ == "__main__":
    main()
