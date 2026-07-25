"""
Signature / rule-based detectors for live network traffic: port scans,
SYN floods, ARP spoofing, and brute-force attempts against sensitive
ports. Each alert carries an `intensity` (how far over its threshold
the observed activity is), so downstream scoring produces a real range
of threat scores instead of stamping everything as the same severity.
"""
import time
import logging

logger = logging.getLogger("sentry.signatures")

SENSITIVE_PORTS = {21, 22, 23, 3389, 445, 3306, 5432}


class SignatureEngine:
    def __init__(self, config, report_fn):
        """
        report_fn(category, message, ip_address=None, port=None,
                  intensity=1.0, meta=None) is called whenever a rule fires.
        """
        self.cfg = config
        self.report = report_fn
        self.arp_table = {}
        self.recent_alerts = {}
        self.cooldown = self.cfg.get("alert_cooldown_seconds", 30)

    def _should_alert(self, key):
        now = time.time()
        last = self.recent_alerts.get(key, 0)
        if now - last < self.cooldown:
            return False
        self.recent_alerts[key] = now
        return True

    def on_event(self, event, tracker):
        etype = event.get("type")
        if etype == "arp":
            self._check_arp_spoof(event)
        elif etype == "tcp":
            self._check_syn_flood(event, tracker)
            self._check_port_scan(event, tracker)
            self._check_brute_force(event, tracker)

    def _check_arp_spoof(self, event):
        if event.get("op") != 2:
            return
        ip, mac = event["src_ip"], event["src_mac"]
        if ip == "0.0.0.0":
            # ARP probes (duplicate address detection) use 0.0.0.0 as the
            # sender IP before a device has a real address — normal noise,
            # not spoofing.
            return
        known = self.arp_table.get(ip)
        if known and known != mac:
            if self._should_alert(f"arp:{ip}"):
                self.report(
                    category="arp_spoofing",
                    message=f"ARP spoofing suspected: {ip} claimed by {known} and now {mac}",
                    ip_address=ip, intensity=1.0,
                    meta={"old_mac": known, "new_mac": mac},
                )
        self.arp_table[ip] = mac

    def _check_syn_flood(self, event, tracker):
        flags = event.get("flags", "")
        if "S" not in flags or "A" in flags:
            return
        src = event["src_ip"]
        window = self.cfg.get("syn_flood_window_seconds", 5)
        threshold = self.cfg.get("syn_flood_threshold", 100)
        recent = tracker.recent_events_for(src, window)
        syn_count = sum(
            1 for e in recent
            if e.get("type") == "tcp" and "S" in e.get("flags", "") and "A" not in e.get("flags", "")
        )
        if syn_count >= threshold and self._should_alert(f"synflood:{src}"):
            intensity = min(syn_count / threshold, 2.0) / 2.0 + 0.5  # 0.5 - 1.3
            self.report(
                category="syn_flood",
                message=f"Possible SYN flood from {src}: {syn_count} SYNs in {window}s",
                ip_address=src, intensity=intensity,
                meta={"count": syn_count, "window": window},
            )

    def _check_port_scan(self, event, tracker):
        src = event["src_ip"]
        window = self.cfg.get("port_scan_window_seconds", 10)
        threshold = self.cfg.get("port_scan_unique_ports", 20)
        recent = tracker.recent_events_for(src, window)
        ports = {e["dst_port"] for e in recent if e.get("type") == "tcp"}
        if len(ports) >= threshold and self._should_alert(f"portscan:{src}"):
            intensity = min(len(ports) / threshold, 2.0) / 2.0 + 0.5
            self.report(
                category="port_scan",
                message=f"Possible port scan from {src}: {len(ports)} distinct ports in {window}s",
                ip_address=src, intensity=intensity,
                meta={"unique_ports": len(ports), "window": window},
            )

    def _check_brute_force(self, event, tracker):
        dport = event.get("dst_port")
        if dport not in SENSITIVE_PORTS:
            return
        src = event["src_ip"]
        window = self.cfg.get("brute_force_window_seconds", 60)
        threshold = self.cfg.get("brute_force_attempts", 15)
        recent = tracker.recent_events_for(src, window)
        attempts = [
            e for e in recent
            if e.get("dst_port") == dport and "S" in e.get("flags", "") and "A" not in e.get("flags", "")
        ]
        if len(attempts) >= threshold and self._should_alert(f"bruteforce:{src}:{dport}"):
            intensity = min(len(attempts) / threshold, 2.0) / 2.0 + 0.5
            self.report(
                category="brute_force",
                message=f"Possible brute-force against port {dport} from {src}: {len(attempts)} attempts in {window}s",
                ip_address=src, port=dport, intensity=intensity,
                meta={"attempts": len(attempts)},
            )
