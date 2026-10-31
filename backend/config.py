"""Central, documented configuration. Override any value with an environment variable."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EVE_PATH = os.environ.get("SENTINEL_EVE", "/var/log/suricata/eve.json")
DB_PATH = os.environ.get("SENTINEL_DB", str(ROOT / "data" / "sentinel.db"))
RULES_PATH = os.environ.get("SENTINEL_RULES", str(ROOT / "rules" / "local.rules"))
PCAP_DIR = os.environ.get("SENTINEL_PCAP_DIR", str(ROOT / "data" / "pcap"))
SAMPLE_EVE = str(ROOT / "data" / "sample" / "eve.sample.json")

# --- Correlation (LAB CONFIGURATION, not a security standard) ---
CASE_WINDOW_SEC = int(os.environ.get("SENTINEL_CASE_WINDOW", "60"))   # max gap between alerts of one case
CASE_MIN_ALERTS = int(os.environ.get("SENTINEL_CASE_MIN", "3"))       # alerts needed to flag a correlated incident

# --- Severity mapping: Suricata alert.severity (= rule 'priority') -> label ---
SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium"}   # anything >= 4 -> "low"
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# --- Health: Suricata emits a 'stats' event every stats.interval seconds (8 in config/suricata.yaml) ---
STATS_INTERVAL_SEC = int(os.environ.get("SENTINEL_STATS_INTERVAL", "8"))
STALE_AFTER_SEC = STATS_INTERVAL_SEC * 4

POLL_INTERVAL_SEC = 1.0
RELATED_WINDOW_SEC = 300   # +/- window used by "related events from same source"
