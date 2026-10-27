"""config.py - every setting of the PoC in one place, so nothing is hard-coded elsewhere."""

MONITORED_ASNS = {9541, 24440}            # Cybernet's AS numbers; we alert on routes that touch these

ROUTINATOR_BASE_URL = "http://127.0.0.1:8323"                        # where Routinator's HTTP server listens
ROUTINATOR_JSON_URL = ROUTINATOR_BASE_URL + "/json"                  # endpoint that returns ALL VRPs as JSON
ROUTINATOR_VALIDITY_URL = ROUTINATOR_BASE_URL + "/api/v1/validity"   # endpoint that judges ONE route
CROSS_CHECK_WITH_ROUTINATOR = True        # True = ask Routinator to confirm every new Invalid we find

VRP_REFRESH_SECONDS = 600                 # reload VRPs every 10 minutes so ROA changes are picked up

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-cybernet-rpki-poc"   # RIS Live WebSocket; ?client= names us

DEMO_VRP_FILE = "demo_data/demo_vrps.json"           # fake VRPs used only with --demo
DEMO_UPDATES_FILE = "demo_data/demo_updates.jsonl"   # fake RIS Live messages used only with --demo

ALERT_FILE = "alerts.jsonl"               # every NEW / REOPENED / RESOLVED alert is appended here