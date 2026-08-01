"""
Live network monitor — entry point for real-time traffic detection.
Runs alongside the Flask API (backend/app.py) and POSTs every signature
alert to /api/ingest/network, so live network threats show up in the
same dashboard as log-based analysis.

Requires elevated privileges (root/Administrator) to sniff a live
interface.

Usage:
    sudo python capture/monitor.py --interface en0 --api http://127.0.0.1:5000
"""
import argparse
import logging
import threading
import time
import requests

from capture.live_capture import PacketCapture
from capture.flow_tracker import FlowTracker
from capture.signature_rules import SignatureEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
logger = logging.getLogger("sentry.monitor")

DEFAULT_CONFIG = {
    "alert_cooldown_seconds": 30,
    "syn_flood_window_seconds": 5,
    "syn_flood_threshold": 100,
    "port_scan_window_seconds": 10,
    "port_scan_unique_ports": 20,
    "brute_force_window_seconds": 60,
    "brute_force_attempts": 15,
}


def make_reporter(api_url, api_key=None):
    def report(category, message, ip_address=None, port=None, intensity=1.0, meta=None):
        payload = {
            "ts": time.time(),
            "category": category,
            "message": message,
            "ip_address": ip_address,
            "port": port,
            "intensity": intensity,
            "meta": meta or {},
        }
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            requests.post(f"{api_url}/api/ingest/network", json=payload, headers=headers, timeout=3)
        except requests.RequestException:
            logger.warning("Failed to forward alert to API at %s — is it running?", api_url)
        # Always also log locally so operators see it even if the API is down.
        logger.info("[%s] %s", category, message)
    return report


def traffic_reporter_loop(tracker, reporter, interval=5, max_per_cycle=20):
    """
    Periodically reports EVERY completed connection (not just rule
    matches) so the dashboard shows real, ordinary traffic alongside
    alerts — instead of only ever showing HIGH/CRITICAL entries.
    Capped per cycle so a busy network doesn't flood the database.
    """
    while True:
        time.sleep(interval)
        closed = tracker.evict_closed_flows()
        for flow in closed[:max_per_cycle]:
            s = flow.summary()
            if not s["dst_ip"]:
                continue  # ARP-only entries have no flow, skip
            message = (
                f"{s['proto'].upper()} {s['src_ip']} -> {s['dst_ip']}:{s['dst_port']} "
                f"— {s['packet_count']} packets, {s['byte_count']} bytes"
            )
            reporter(
                category="normal_traffic",
                message=message,
                ip_address=s["src_ip"],
                port=s["dst_port"],
                intensity=1.0,
                meta=s,
            )


def main():
    parser = argparse.ArgumentParser(description="Sentry live network monitor")
    parser.add_argument("--interface", help="Network interface to sniff on")
    parser.add_argument("--filter", dest="bpf_filter", default="ip or arp")
    parser.add_argument("--api", default="http://127.0.0.1:5000", help="Base URL of the Sentry API")
    parser.add_argument("--api-key", help="API key for authentication")
    parser.add_argument(
        "--show-all-traffic",
        action="store_true",
        help="Also report every normal connection (not just alerts), so the "
             "dashboard shows a full live traffic feed instead of only threats.",
    )
    args = parser.parse_args()

    tracker = FlowTracker()
    reporter = make_reporter(args.api, args.api_key)
    sig_engine = SignatureEngine(DEFAULT_CONFIG, reporter)
    capture = PacketCapture(interface=args.interface, bpf_filter=args.bpf_filter)

    capture_thread = threading.Thread(target=capture.start, daemon=True)
    capture_thread.start()

    if args.show_all_traffic:
        reporter_thread = threading.Thread(
            target=traffic_reporter_loop, args=(tracker, reporter), daemon=True
        )
        reporter_thread.start()
        logger.info("Full traffic logging enabled — every connection will be reported.")

    logger.info("Live network monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            event = capture.queue.get()
            tracker.ingest(event)
            sig_engine.on_event(event, tracker)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        capture.stop()


if __name__ == "__main__":
    main()
