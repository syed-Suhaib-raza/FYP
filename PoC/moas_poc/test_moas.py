import json
from moas import MoasDetector, extract_origins
def upd(ts, path, prefix, peer=1):
    return {"type":"UPDATE","timestamp":ts,"peer_asn":str(peer),"host":"rrc00","path":path,"announcements":[{"prefixes":[prefix]}]}
def test_origin_extraction():
    assert extract_origins([1,2,3]) == [3]
    assert extract_origins([1,2,[7,8]]) == ['{7,8}']
    assert extract_origins([]) == []
def test_single_origin_no_alert():
    d = MoasDetector(); assert d.process(upd(0,[1,2],"10.0.0.0/8")) == [] and d.process(upd(1,[5,2],"10.0.0.0/8")) == []
def test_hijack_high_severity():
    d = MoasDetector(whitelist={"10.0.0.0/8":[2]}); d.process(upd(0,[1,2],"10.0.0.0/8"))
    a = d.process(upd(1,[5,666],"10.0.0.0/8")); assert len(a)==1 and a[0]["severity"]=="high" and a[0]["new_origin"]==666
def test_no_duplicate_alert():
    d = MoasDetector(); d.process(upd(0,[1,2],"p/8".replace("p","10.0.0.0"))); 
    assert len(d.process(upd(1,[5,9],"10.0.0.0/8")))==1 and d.process(upd(2,[6,9],"10.0.0.0/8"))==[]
def test_window_expiry():
    d = MoasDetector(window=100); d.process(upd(0,[1,2],"10.0.0.0/8")); assert d.process(upd(500,[5,9],"10.0.0.0/8"))==[]
def test_withdraw_and_non_update_ignored():
    assert MoasDetector().process({"type":"KEEPALIVE"})==[]
