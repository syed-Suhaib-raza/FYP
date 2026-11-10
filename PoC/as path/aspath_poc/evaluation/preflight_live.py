"""Run this once before the two 45-minute live runs:   python preflight_live.py
Checks what silently ruins a live run: no real CAIDA relationship file (the route-leak rule would never fire), a PC clock that is off
(feed delay would be wrong), a missing `websockets` package, too little disk for the full-collector capture, and whether RIS Live is
reachable. Measures the real message rate of rrc00 for 10 seconds and estimates the capture size of Run A.
   python preflight_live.py --host rrc00 --seconds 10
"""
import argparse, asyncio, email.utils, importlib, json, os, shutil, sys, time, urllib.request

import caida

URL = "wss://ris-live.ripe.net/v1/ws/?client=fyp-aspath-preflight"
ok = lambda m: print("  OK    ", m)
warn = lambda m: print("  WARN  ", m)
bad = lambda m: print("  FAIL  ", m)


def clock_skew():
    """Our clock minus the server's, from an HTTP Date header (1 s resolution, so only a skew of 2 s or more is meaningful)."""
    try:
        t0 = time.time()
        with urllib.request.urlopen(urllib.request.Request("https://stat.ripe.net/data/rrc-info/data.json", method="HEAD", headers={"User-Agent": "fyp-aspath-preflight"}), timeout=15) as r:
            date = r.headers.get("Date")
        t1 = time.time()
        return (t0 + t1) / 2 - email.utils.parsedate_to_datetime(date).timestamp()
    except Exception as e:
        return e


async def sample(host, seconds):
    import websockets
    n = ann = 0
    lag = []
    async with websockets.connect(URL, ping_interval=30, max_size=None) as ws:
        await ws.send(json.dumps({"type": "ris_subscribe", "data": {"type": "UPDATE", "socketOptions": {"includeRaw": False}, "host": host}}))
        end = time.time() + seconds
        while time.time() < end:
            try:
                m = json.loads(await asyncio.wait_for(ws.recv(), 5))
            except asyncio.TimeoutError:
                continue
            if m.get("type") == "ris_message":
                d = m["data"]; n += 1; ann += bool(d.get("announcements"))
                if d.get("timestamp") is not None:
                    lag.append(time.time() - d["timestamp"])
    return n, ann, lag


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--host", default="rrc00"); ap.add_argument("--seconds", type=int, default=10); ap.add_argument("--minutes", type=int, default=45)
    a = ap.parse_args()
    print("AS-path live-test preflight"); fails = 0
    print(f"python {sys.version.split()[0]}"); ok("python >= 3.9") if sys.version_info >= (3, 9) else bad("python 3.9+ needed")
    for mod, why in (("websockets", "needed to record RIS Live"), ("openpyxl", "needed by build_results.py (Excel workbook)")):
        try:
            importlib.import_module(mod); ok(f"{mod} installed")
        except ImportError:
            fails += mod == "websockets"; (bad if mod == "websockets" else warn)(f"{mod} missing ({why}): pip install {mod}")
    f = caida.local()
    if f:
        from asrel import ASRel
        n = len(ASRel(f).rel); ok(f"real CAIDA relationships: {f} ({n:,} links)") if n > 100000 else warn(f"{f} has only {n:,} links: is it the real file?")
    else:
        fails += 1; bad("no CAIDA file in ./data -> the valley (route-leak) rule would be silent. Run:  python aspath.py caida")
    free = shutil.disk_usage(".").free / 1e9
    ok(f"disk free {free:.0f} GB") if free >= 5 else warn(f"only {free:.1f} GB free; the full-collector capture can need several GB")
    skew = clock_skew()
    if isinstance(skew, Exception):
        warn(f"could not check the clock ({type(skew).__name__}); sync it yourself (Windows: w32tm /resync)")
    elif abs(skew) > 2:
        warn(f"your clock differs from the server's by about {skew:+.0f} s: feed delay would be wrong. Windows: w32tm /resync")
    else:
        ok(f"clock within ~2 s of the server (measured {skew:+.1f} s, 1 s resolution)")
    try:
        n, ann, lag = asyncio.run(sample(a.host, a.seconds))
        rate = n / a.seconds
        ok(f"RIS Live reachable; {a.host}: {n} UPDATEs in {a.seconds}s = {rate:.0f} messages/s ({ann} with announcements)")
        if lag:
            lag.sort(); print(f"         feed delay now: median {lag[len(lag) // 2]:.2f} s, max {lag[-1]:.2f} s")
        print(f"         estimate for Run A ({a.minutes} min): about {rate * a.minutes * 60:,.0f} messages, capture ~{rate * a.minutes * 60 * 450 / 1e9:.1f} GB (450 bytes/message rough guess)")
    except ImportError:
        pass
    except Exception as e:
        fails += 1; bad(f"cannot reach RIS Live: {type(e).__name__}: {e}")
    print("\nREADY" if not fails else f"\n{fails} problem(s) above: fix them before the long runs")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
