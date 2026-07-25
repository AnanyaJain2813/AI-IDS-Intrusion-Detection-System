"""
Live packet capture — sniffs real network traffic (requires elevated
privileges) and pushes parsed packet events onto a queue for the
signature engine to inspect.
"""
import queue
import time
import logging
from scapy.all import sniff, IP, TCP, UDP, ARP

logger = logging.getLogger("sentry.capture")


class PacketCapture:
    def __init__(self, interface=None, bpf_filter=None, packet_queue=None, log_every=1000):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.queue = packet_queue or queue.Queue(maxsize=100000)
        self._stop = False
        self.packet_count = 0
        self.log_every = log_every
        self._start_time = None

    def _handle_packet(self, pkt):
        self.packet_count += 1
        if self.packet_count % self.log_every == 0:
            elapsed = time.time() - self._start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            logger.info(
                "Captured %d packets so far (%.1f pps, %.0fs elapsed)",
                self.packet_count, rate, elapsed,
            )
        try:
            event = self._parse(pkt)
            if event:
                self.queue.put_nowait(event)
        except queue.Full:
            logger.warning("Packet queue full — dropping packet")
        except Exception:
            logger.exception("Failed to parse packet")

    @staticmethod
    def _parse(pkt):
        ts = float(pkt.time)
        event = {"ts": ts, "len": len(pkt)}

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            event.update({
                "type": "arp", "op": arp.op,
                "src_ip": arp.psrc, "src_mac": arp.hwsrc, "dst_ip": arp.pdst,
            })
            return event

        if pkt.haslayer(IP):
            ip = pkt[IP]
            event.update({"src_ip": ip.src, "dst_ip": ip.dst, "proto": ip.proto})

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                event.update({
                    "type": "tcp", "src_port": int(tcp.sport),
                    "dst_port": int(tcp.dport), "flags": str(tcp.flags),
                })
                return event

            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                event.update({
                    "type": "udp", "src_port": int(udp.sport), "dst_port": int(udp.dport),
                })
                return event

            event["type"] = "ip_other"
            return event

        return None

    def start(self):
        self._start_time = time.time()
        logger.info("Starting capture on interface=%s filter=%s", self.interface, self.bpf_filter)
        sniff(
            iface=self.interface, filter=self.bpf_filter,
            prn=self._handle_packet, store=False,
            stop_filter=lambda p: self._stop,
        )

    def stop(self):
        self._stop = True
