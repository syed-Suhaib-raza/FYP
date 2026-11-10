"""Network-latency probes for the live test (standard library only). Used by live_eval.py; does not touch flap.py.

sntp_offset()    how far this PC's clock is from true time (SNTP, UDP 123). Needed because RIS stamps each message with ITS
                 clock and we subtract it from OUR clock: a PC clock that is 2 s slow adds 2 s to every 'feed delay'.
connect_times()  DNS lookup, TCP connect (~1 network round trip) and TLS handshake time to the RIS Live server.
The WebSocket ping round-trip is measured inside live_eval.py (it needs the open connection).
"""
import socket, ssl, statistics, struct, time

NTP_EPOCH = 2208988800          # seconds between 1900-01-01 (NTP) and 1970-01-01 (Unix)


def sntp_offset(server="pool.ntp.org", port=123, samples=4, timeout=2.0):
    """-> dict(offset_s, rtt_ms, server) or None.  offset_s = TRUE time - this PC's clock (add it to a local timestamp
    to get true time; positive = PC clock is behind). Takes the lowest-round-trip of `samples` queries (standard SNTP).
    Accuracy is about +-(rtt/2) of the NTP path, and +-15 ms on older Windows clocks."""
    best = None
    for _ in range(samples):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                t1 = time.time()
                s.sendto(b"\x1b" + 47 * b"\0", (server, port))
                data, _ = s.recvfrom(512)
                t4 = time.time()
        except OSError:
            continue
        if len(data) < 48:
            continue
        a, b = struct.unpack("!II", data[32:40]); t2 = a - NTP_EPOCH + b / 2 ** 32      # server receive
        a, b = struct.unpack("!II", data[40:48]); t3 = a - NTP_EPOCH + b / 2 ** 32      # server transmit
        delay = (t4 - t1) - (t3 - t2)
        if best is None or delay < best["rtt_s"]:
            best = dict(offset_s=((t2 - t1) + (t3 - t4)) / 2, rtt_s=delay, server=server)
    if best:
        best = dict(offset_s=round(best["offset_s"], 4), rtt_ms=round(best["rtt_s"] * 1000, 2), server=best["server"])
    return best


def connect_times(host="ris-live.ripe.net", port=443, tls=True, samples=3, timeout=10.0):
    """-> dict(dns_ms, tcp_ms, tls_ms, addr, samples) (medians) or None. tcp_ms is one network round trip to the server."""
    got = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            fam, typ, _, _, addr = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
            t1 = time.perf_counter()
            s = socket.socket(fam, typ); s.settimeout(timeout); s.connect(addr)
            t2 = time.perf_counter()
            if tls:
                s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            t3 = time.perf_counter()
            s.close()
            got.append((t1 - t0, t2 - t1, t3 - t2))
        except OSError:
            continue
    if not got:
        return None
    med = lambda i: round(statistics.median(g[i] for g in got) * 1000, 2)
    return dict(dns_ms=med(0), tcp_ms=med(1), tls_ms=med(2), addr=addr[0], samples=len(got))
