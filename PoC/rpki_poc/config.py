"""config.py - every setting of the PoC in one place, so nothing is hard-coded elsewhere."""

# ---- who we protect --------------------------------------------------------------------------------------
MONITORED_ASNS = {9541, 24440}            # Cybernet's AS numbers; we alert on routes that touch these
WHITELIST_FILE = "whitelist.json"         # Cybernet prefixes -> expected origin ASNs (same format as the other PoCs)
CUSTOMERS_FILE = "customers.json"         # Cybernet customer ASNs that may originate inside Cybernet space

# ---- detection rules -------------------------------------------------------------------------------------
MIN_PEERS = 2                             # an alert becomes ACTIVE only when this many RIS peers carry the route
REVALIDATE_ON_VRP_CHANGE = True           # re-check every route we hold whenever the VRP set changes
ROA_EXPIRY_WARN_HOURS = 24                # warn when a Cybernet ROA expires within this many hours (needs /jsonext)

# ---- Routinator ------------------------------------------------------------------------------------------
ROUTINATOR_BASE_URL = "http://127.0.0.1:8323"                        # where Routinator's HTTP server listens
ROUTINATOR_JSON_URL = ROUTINATOR_BASE_URL + "/jsonext"               # VRPs with their ROA validity (expiry)
ROUTINATOR_JSON_FALLBACK_URL = ROUTINATOR_BASE_URL + "/json"         # plain VRPs, used if /jsonext is not served
ROUTINATOR_VALIDITY_URL = ROUTINATOR_BASE_URL + "/api/v1/validity"   # endpoint that judges ONE route
CROSS_CHECK_WITH_ROUTINATOR = True        # ask Routinator for a second opinion on every alert that becomes ACTIVE

VRP_REFRESH_SECONDS = 600                 # reload VRPs every 10 minutes so ROA changes are picked up
VRP_STALE_SECONDS = 1800                  # warn when the last successful VRP load is older than 30 minutes

# ---- BGP feed --------------------------------------------------------------------------------------------
RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-cybernet-rpki-poc"   # RIS Live WebSocket; ?client= names us

# ---- files -----------------------------------------------------------------------------------------------
DB_FILE = "rpki.db"                       # live runs write here (the dashboard reads it)
DEMO_DB_FILE = "demo.db"                  # --demo writes here, so demo alerts never mix with live ones
ALERT_LOG = "alerts.jsonl"                # every alert event is also appended here as one JSON line

DEMO_VRP_FILE = "demo_data/demo_vrps.json"           # fake VRPs used only with --demo
DEMO_UPDATES_FILE = "demo_data/demo_updates.jsonl"   # fake RIS Live messages (and ROA changes) used only with --demo
DEMO_WHITELIST_FILE = "demo_data/demo_whitelist.json"
DEMO_CUSTOMERS_FILE = "demo_data/demo_customers.json"
