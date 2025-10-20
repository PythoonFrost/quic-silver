#!/usr/bin/env python3
import json, os
from collections import defaultdict, deque
from datetime import datetime, timedelta

class AlertLogger:
    """Write alerts to alerts.json."""
    def __init__(self, path: str):
        self.path = path
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"alerts": []}, f, indent=2)

    def _read(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"alerts": []}
        if "alerts" not in data:
            data["alerts"] = []
        return data

    def write(self, alert: dict):
        data = self._read()
        data["alerts"].append(alert)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

class RuleEngine:
    """Apply detection thresholds from detection_rules.json."""
    def __init__(self, cfg: dict):
        self.rules = cfg.get("rules", {})
        self.logger = AlertLogger(cfg.get("alerts_file", "alerts.json"))
        self._pkts_per_ip = defaultdict(deque)
        self._hs_per_pair = defaultdict(deque)
        self._mal_per_src = defaultdict(deque)

    @staticmethod
    def _now(): return datetime.utcnow()
    def _prune(self, dq: deque, seconds: int):
        cutoff = self._now() - timedelta(seconds=seconds)
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def on_summary(self, ev: dict):
        t = self._now()
        ip = ev["src_ip"] or ev["dst_ip"]

        # packet rate rule
        if ip:
            dq = self._pkts_per_ip[ip]; dq.append((t, int(ev["pkt_count"])))
            self._prune(dq, 1)
            limit = self.rules.get("max_packets_per_ip_per_sec")
            if limit and sum(c for _, c in dq) > int(limit):
                self._raise("packet_rate_spike", {"ip": ip, "iface": ev["iface"]})

        # handshake burst rule
        if int(ev["initial_count"]) > 0:
            pair = f'{ev["src_ip"]}>{ev["dst_ip"]}'
            dq = self._hs_per_pair[pair]; dq.append((t, int(ev["initial_count"])))
            self._prune(dq, 60)
            limit = self.rules.get("max_initial_handshakes_per_pair_per_min")
            if limit and sum(c for _, c in dq) > int(limit):
                self._raise("handshake_burst", {"pair": pair, "iface": ev["iface"]})

        # malformed rule
        if int(ev["malformed_count"]) > 0:
            src = ev["src_ip"]
            dq = self._mal_per_src[src]; dq.append((t, int(ev["malformed_count"])))
            self._prune(dq, 60)
            limit = self.rules.get("max_malformed_per_src_per_min")
            if limit and sum(c for _, c in dq) > int(limit):
                self._raise("malformed_spike", {"src_ip": src, "iface": ev["iface"]})

    def _raise(self, rule: str, details: dict):
        alert = {
            "time_utc": self._now().isoformat(timespec="seconds") + "Z",
            "rule": rule,
            "details": details
        }
        self.logger.write(alert)
