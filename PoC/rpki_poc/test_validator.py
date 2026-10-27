"""test_validator.py - proves every deterministic rule with a small fixed VRP set. Run: pytest -v"""

import ipaddress                                     # build prefixes for the tests

from bgp_feed import origin_from_path, parse_ris_message      # parser functions under test
from validator import (INVALID_AS, INVALID_AS_AND_ML, INVALID_ML,   # the five possible states
                       NOT_FOUND, VALID, validate_route)
from vrp_store import VRP, VrpStore                  # build a VRP store by hand


def net(text):
    return ipaddress.ip_network(text)                # shortcut: "198.18.0.0/22" -> network object


STORE = VrpStore([                                   # fixed truth used by most tests
    VRP(9541, net("198.18.0.0/22"), 23, "test"),     # Cybernet, /22 to /23 allowed
    VRP(0, net("198.18.16.0/24"), 24, "test"),       # AS0 ROA: nobody may announce this
    VRP(9541, net("2001:db8::/32"), 48, "test"),     # IPv6 block, up to /48 allowed
], source="unit-test")


def state(prefix, origin):
    return validate_route(net(prefix), origin, STORE).state   # shortcut: only the state


def test_exact_match_is_valid():
    assert state("198.18.0.0/22", 9541) == VALID     # same prefix, same AS

def test_more_specific_within_maxlength_is_valid():
    assert state("198.18.2.0/23", 9541) == VALID     # /23 <= max /23

def test_too_specific_is_invalid_ml():
    assert state("198.18.1.0/24", 9541) == INVALID_ML   # right AS, /24 > /23

def test_wrong_origin_is_invalid_as():
    assert state("198.18.0.0/22", 64511) == INVALID_AS  # wrong AS, length fine

def test_wrong_origin_and_too_specific_is_invalid_as_and_ml():
    assert state("198.18.2.0/24", 64511) == INVALID_AS_AND_ML   # wrong AS and /24 > /23

def test_uncovered_prefix_is_not_found():
    assert state("198.51.100.0/24", 64511) == NOT_FOUND   # no VRP covers it

def test_as0_vrp_never_matches():
    assert state("198.18.16.0/24", 9541) == INVALID_AS    # AS0 ROA makes every origin invalid

def test_any_matching_vrp_wins():
    store = VrpStore([VRP(64500, net("198.18.4.0/22"), 22, "t"),    # first VRP does not match
                      VRP(9541, net("198.18.4.0/22"), 24, "t")],    # second VRP matches
                     source="t")
    assert validate_route(net("198.18.5.0/24"), 9541, store).state == VALID

def test_as_set_origin_cannot_be_valid():
    assert origin_from_path([3356, [64500, 64511]]) is None    # AS_SET -> no single origin
    assert state("198.18.0.0/22", None) == INVALID_AS          # so the route cannot be VALID

def test_ipv6_prefixes_work():
    assert state("2001:db8:1::/48", 9541) == VALID           # /48 <= max /48
    assert state("2001:db8:1::/56", 9541) == INVALID_ML      # /56 > max /48

def test_parse_ris_message_extracts_origin_and_prefixes():
    msg = {"type": "ris_message", "data": {"type": "UPDATE", "host": "rrc00", "peer": "192.0.2.1",
           "peer_asn": "3356", "timestamp": 1.0, "path": [3356, 9541],
           "announcements": [{"next_hop": "192.0.2.1", "prefixes": ["198.18.1.0/24"]}],
           "withdrawals": ["198.18.3.0/24"]}}                 # one announcement + one withdrawal
    events = parse_ris_message(msg)
    assert [(e.kind, str(e.prefix), e.origin_asn) for e in events] == [
        ("announce", "198.18.1.0/24", 9541),                     # origin = last AS in the path
        ("withdraw", "198.18.3.0/24", None)]                     # withdrawals have no origin