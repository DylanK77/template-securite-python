from collections import defaultdict

from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from tp1.utils.config import logger
from tp1.utils.lib import BASE_PROTOCOLS, choose_interface, proto_name


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.packets = []
        self.protocol_counter = defaultdict(int)
        for protocol in BASE_PROTOCOLS:
            self.protocol_counter[protocol] = 0
        self.ip_packet_counter = defaultdict(int)
        self.ip_proto_counter = defaultdict(lambda: defaultdict(int))
        self.proto_suspicious = defaultdict(list)
        self.suspicious = []
        self.summary = ""

    def capture_traffic(self) -> None:
        logger.info("Capture sur %s", self.interface)
        sniff(iface=self.interface, prn=self._packet_handler, store=False)

    def analyse(self) -> None:
        self.summary = self._build_summary()

    def get_summary(self) -> str:
        return self.summary

    def get_all_protocols(self) -> dict:
        return dict(self.protocol_counter)

    def sort_network_protocols(self) -> dict:
        return dict(
            sorted(
                self.protocol_counter.items(),
                key=lambda item: item[1],
                reverse=True,
            )
        )

    def get_proto_analysis(self) -> dict:
        result = {}
        for protocol, count in self.protocol_counter.items():
            alerts = self.proto_suspicious.get(protocol, [])
            result[protocol] = {
                "count": count,
                "status": "SUSPICIOUS" if alerts else "OK",
                "alerts": alerts,
            }
        return result

    def _packet_handler(self, packet) -> None:
        self.packets.append(packet)

        if IP in packet:
            self._record_ip_packet(packet)
        elif IPv6 in packet:
            self._record_ipv6_packet(packet)
        elif ARP in packet:
            self._record_arp_packet(packet)
        else:
            self.protocol_counter["UNKNOWN"] += 1

        self._detect_sqli(packet)
        self._detect_arp_spoofing(packet)

    def _record_ip_packet(self, packet) -> None:
        ip_layer = packet[IP]
        protocol = proto_name(ip_layer.proto)
        self.protocol_counter[protocol] += 1
        self._record_endpoint(ip_layer.src, protocol)
        self._record_endpoint(ip_layer.dst, protocol)

    def _record_ipv6_packet(self, packet) -> None:
        ipv6_layer = packet[IPv6]
        protocol = proto_name(ipv6_layer.nh)
        self.protocol_counter[protocol] += 1
        self._record_endpoint(ipv6_layer.src, protocol)
        self._record_endpoint(ipv6_layer.dst, protocol)

    def _record_arp_packet(self, packet) -> None:
        arp_layer = packet[ARP]
        self.protocol_counter["ARP"] += 1
        self._record_endpoint(arp_layer.psrc, "ARP")
        self._record_endpoint(arp_layer.pdst, "ARP")

    def _record_endpoint(self, address: str, protocol: str) -> None:
        self.ip_packet_counter[address] += 1
        self.ip_proto_counter[address][protocol] += 1

    def _detect_sqli(self, packet) -> None:
        if not self._is_tcp_packet(packet):
            return

        payload = getattr(packet[TCP], "payload", b"")
        payload_text = str(payload).lower()
        signatures = ("select", "union", "' or", "\" or", " drop ", "--")
        if any(signature in payload_text for signature in signatures):
            source = packet[IP].src if IP in packet else "Unknown"
            self._add_alert("TCP", f"[TCP] SQLi detected from {source}")

    def _detect_arp_spoofing(self, packet) -> None:
        if ARP not in packet:
            return

        arp_layer = packet[ARP]
        if arp_layer.psrc == arp_layer.pdst:
            self._add_alert(
                "ARP",
                f"[ARP] ARP Spoofing from MAC {arp_layer.hwsrc} / IP {arp_layer.psrc}",
            )

    def _is_tcp_packet(self, packet) -> bool:
        return hasattr(packet, "haslayer") and packet.haslayer(TCP)

    def _add_alert(self, protocol: str, message: str) -> None:
        self.suspicious.append(message)
        self.proto_suspicious[protocol].append(message)

    def _build_summary(self) -> str:
        lines = [
            "=== IDS SUMMARY ===",
            "",
            f"Interface: {self.interface}",
            f"Total packets captured: {len(self.packets)}",
            "",
            "Protocols detected:",
        ]

        for protocol, count in self.sort_network_protocols().items():
            lines.append(f"- {protocol}: {count}")

        lines.extend(["", "Packets by IP address:"])
        for address, count in sorted(
            self.ip_packet_counter.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            details = ", ".join(
                f"{protocol}: {protocol_count}"
                for protocol, protocol_count in sorted(
                    self.ip_proto_counter[address].items()
                )
            )
            lines.append(f"- {address}: {count} ({details})")

        lines.extend(["", "Traffic analysis:"])
        if self.suspicious:
            lines.extend(self.suspicious)
        else:
            lines.append("All traffic is legitimate.")

        return "\n".join(lines) + "\n"
