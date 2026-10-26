"""CAIDA AS-relationship lookups -> evidence sentences (same idea as the RouteLLM repo's inference.py).
File format (as-rel / as-rel2, .txt or .bz2):  <as1>|<as2>|<rel>|<source>   rel: -1 = as1 is provider of as2, 0 = peers, 1 = siblings
Download: https://publicdata.caida.org/datasets/as-relationships/serial-2/"""
import bz2, collections


class ASRel:
    def __init__(self, path=None):
        self.rel = {}                       # frozenset({a,b}) -> sentence
        self.by_asn = collections.defaultdict(list)
        self.nbr = collections.defaultdict(dict)    # asn -> {other_asn: 'customer'|'provider'|'peer'|'sibling'} (other's role relative to asn)
        if path:
            self.load(path)

    def load(self, path):
        op = bz2.open if str(path).endswith(".bz2") else open
        with op(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                p = line.strip().split("|")
                if len(p) < 3:
                    continue
                a, b, r = int(p[0]), int(p[1]), p[2]
                s = {"-1": f"AS{a} is a provider of AS{b}.", "0": f"AS{a} and AS{b} are peers.",
                     "1": f"AS{a} and AS{b} are siblings."}.get(r, f"AS{a} and AS{b} have an unknown relationship.")
                if r == "-1":
                    self.nbr[a][b] = "customer"; self.nbr[b][a] = "provider"
                elif r == "0":
                    self.nbr[a][b] = self.nbr[b][a] = "peer"
                elif r == "1":
                    self.nbr[a][b] = self.nbr[b][a] = "sibling"
                self.rel[frozenset((a, b))] = s
                self.by_asn[a].append(s); self.by_asn[b].append(s)

    def pair(self, a, b):
        return self.rel.get(frozenset((a, b)))

    def evidence(self, path_asns, origin, expected, top_k=8):
        """Ordered, de-duplicated evidence sentences, most informative first:
        1) origin vs. each expected origin  2) each adjacent AS pair on the path  3) other facts about the origin."""
        out = []
        def add(s):
            if s and s not in out:
                out.append(s)
        for e in sorted(expected):
            add(self.pair(origin, e) or f"No known relationship between AS{origin} and expected origin AS{e}.")
        for a, b in zip(path_asns, path_asns[1:]):
            if a != b:
                add(self.pair(a, b) or f"No known relationship between AS{a} and AS{b}.")
        for s in self.by_asn.get(origin, [])[:top_k]:
            add(s)
        return out[:top_k]

    def related(self, asn, kinds=None):
        return {o for o, k in self.nbr.get(asn, {}).items() if kinds is None or k in kinds}

    def cone2(self, asn):
        """customers and customers-of-customers (depth 2), excluding direct customers"""
        d1 = self.related(asn, {"customer"})
        return {c2 for c in d1 for c2 in self.related(c, {"customer"})} - d1 - {asn}
