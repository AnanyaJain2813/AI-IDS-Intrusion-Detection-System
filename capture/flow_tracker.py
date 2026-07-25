"""
Flow tracker — does two jobs:
  1. Keeps a per-source-IP rolling window of recent events, used by the
     signature engine for rate-based detection (port scans, SYN floods,
     brute force).
  2. Aggregates packets into full bidirectional flow records (keyed by
     the 5-tuple), so EVERY connection — not just alerts — can be
     reported and shown on the dashboard, including normal traffic.
"""
import time
import threading
from collections import defaultdict, deque

FLOW_TIMEOUT = 20  # seconds of inactivity before a flow is considered closed and reported


class Flow:
    def __init__(self, key, first_ts):
        self.key = key  # (proto, src_ip, dst_ip, src_port, dst_port)
        self.start_ts = first_ts
        self.last_ts = first_ts
        self.packet_count = 0
        self.byte_count = 0
        self.syn_count = 0

    def update(self, event):
        self.last_ts = event["ts"]
        self.packet_count += 1
        self.byte_count += event.get("len", 0)
        flags = event.get("flags", "")
        if "S" in flags and "A" not in flags:
            self.syn_count += 1

    def duration(self):
        return max(self.last_ts - self.start_ts, 1e-6)

    def summary(self):
        proto, src_ip, dst_ip, src_port, dst_port = self.key
        return {
            "proto": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration": round(self.duration(), 2),
        }


class FlowTracker:
    def __init__(self):
        self.lock = threading.Lock()
        self.src_events = defaultdict(lambda: deque(maxlen=5000))
        self.flows = {}

    @staticmethod
    def _flow_key(event):
        proto = event.get("type", "other")
        return (
            proto,
            event.get("src_ip"),
            event.get("dst_ip"),
            event.get("src_port"),
            event.get("dst_port"),
        )

    def ingest(self, event):
        if event is None or "src_ip" not in event:
            return
        with self.lock:
            self.src_events[event["src_ip"]].append(event)

            key = self._flow_key(event)
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(key, event["ts"])
                self.flows[key] = flow
            flow.update(event)

    def recent_events_for(self, src_ip, window_seconds):
        now = time.time()
        with self.lock:
            events = list(self.src_events.get(src_ip, ()))
        return [e for e in events if now - e["ts"] <= window_seconds]

    def evict_closed_flows(self, now=None):
        """Return flows that have gone quiet (no packets in FLOW_TIMEOUT
        seconds) so they can be reported as completed connections."""
        now = now or time.time()
        with self.lock:
            stale_keys = [k for k, f in self.flows.items() if now - f.last_ts > FLOW_TIMEOUT]
            closed = [self.flows.pop(k) for k in stale_keys]
        return closed
