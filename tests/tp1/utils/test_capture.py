from unittest.mock import MagicMock, patch

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

from src.tp1.utils.capture import Capture


def _make_tcp_packet(src="192.168.1.1", dst="192.168.1.2"):
    fake_ip = MagicMock(proto=6, src=src, dst=dst)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer in [IP, TCP]
    packet.__getitem__.side_effect = lambda layer: fake_ip if layer is IP else MagicMock()
    packet.haslayer.return_value = True
    return packet


def _make_udp_packet(src="10.0.0.1", dst="10.0.0.2"):
    fake_ip = MagicMock(proto=17, src=src, dst=dst)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer in [IP, UDP]
    packet.__getitem__.side_effect = lambda layer: fake_ip if layer is IP else MagicMock()
    packet.haslayer.return_value = False
    return packet


def _make_icmp_packet(src="172.16.0.1", dst="172.16.0.2"):
    fake_ip = MagicMock(proto=1, src=src, dst=dst)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer in [IP, ICMP]
    packet.__getitem__.side_effect = lambda layer: fake_ip if layer is IP else MagicMock()
    packet.haslayer.return_value = False
    return packet


def _make_other_ip_packet(src="192.0.2.1", dst="192.0.2.2"):
    fake_ip = MagicMock(proto=132, src=src, dst=dst)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer is IP
    packet.__getitem__.side_effect = lambda layer: fake_ip
    packet.haslayer.return_value = False
    return packet


def _make_ipv6_tcp_packet(src="fe80::1", dst="ff02::1"):
    fake_ipv6 = MagicMock(nh=6, src=src, dst=dst)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer in [IPv6, TCP]
    packet.__getitem__.side_effect = lambda layer: fake_ipv6 if layer is IPv6 else MagicMock()
    packet.haslayer.return_value = True
    return packet


def _make_sqli_packet(src="192.168.1.100", dst="192.168.1.200"):
    fake_ip = MagicMock(proto=6, src=src, dst=dst)
    fake_tcp = MagicMock(payload=b"SELECT * FROM users")
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer in [IP, TCP]
    packet.__getitem__.side_effect = lambda layer: fake_ip if layer is IP else fake_tcp
    packet.haslayer.return_value = True
    return packet


def _make_arp_spoof_packet(ip="192.168.1.50", mac="AA:BB:CC:DD:EE:FF"):
    arp = MagicMock(psrc=ip, pdst=ip, hwsrc=mac)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer is ARP
    packet.__getitem__.side_effect = lambda layer: arp
    return packet


def _make_arp_packet(src="192.168.1.10", dst="192.168.1.1", mac="AA:BB:CC:DD:EE:00"):
    arp = MagicMock(psrc=src, pdst=dst, hwsrc=mac)
    packet = MagicMock()
    packet.__contains__.side_effect = lambda layer: layer is ARP
    packet.__getitem__.side_effect = lambda layer: arp
    return packet


def _capture_with_eth0():
    return patch("src.tp1.utils.capture.choose_interface", return_value="eth0")


def test_capture_init():
    with _capture_with_eth0():
        capture = Capture()
    assert capture.interface == "eth0"
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.protocol_counter["TCP"] == 0
    assert capture.protocol_counter["UDP"] == 0
    assert capture.protocol_counter["ICMP"] == 0
    assert capture.protocol_counter["ARP"] == 0


def test_get_summary_empty():
    with _capture_with_eth0():
        capture = Capture()
    capture.summary = "Test summary"
    assert capture.get_summary() == "Test summary"


def test_capture_traffic_counts_protocols():
    with _capture_with_eth0(), patch("src.tp1.utils.capture.sniff") as mock_sniff:
        def fake_sniff(iface, prn, store):
            for _ in range(2):
                prn(_make_tcp_packet())
                prn(_make_udp_packet())
            prn(_make_icmp_packet())
            prn(_make_other_ip_packet())
            prn(_make_ipv6_tcp_packet())
            prn(_make_arp_packet())

        mock_sniff.side_effect = fake_sniff
        capture = Capture()
        capture.capture_traffic()

    mock_sniff.assert_called_once()
    assert capture.protocol_counter["TCP"] == 3
    assert capture.protocol_counter["UDP"] == 2
    assert capture.protocol_counter["ICMP"] == 1
    assert capture.protocol_counter["OTHER_132"] == 1
    assert capture.protocol_counter["ARP"] == 1

    capture.analyse()
    summary = capture.get_summary()
    assert "Interface: eth0" in summary
    assert "TCP" in summary
    assert "UDP" in summary
    assert "ICMP" in summary
    assert "OTHER_132" in summary
    assert "ARP" in summary
    assert "fe80::1" in summary
    assert "All traffic is legitimate" in summary
    assert capture.get_proto_analysis()["TCP"]["status"] == "OK"


def test_udp_only_capture_still_reports_core_protocols():
    with _capture_with_eth0(), patch("src.tp1.utils.capture.sniff") as mock_sniff:
        mock_sniff.side_effect = lambda iface, prn, store: prn(_make_udp_packet())
        capture = Capture()
        capture.capture_traffic()

    capture.analyse()
    summary = capture.get_summary()
    assert "- UDP: 1" in summary
    assert "- TCP: 0" in summary
    assert "- ICMP: 0" in summary
    assert "- ARP: 0" in summary


def test_capture_traffic_sqli_detection():
    with _capture_with_eth0(), patch("src.tp1.utils.capture.sniff") as mock_sniff:
        mock_sniff.side_effect = lambda iface, prn, store: prn(_make_sqli_packet())
        capture = Capture()
        capture.capture_traffic()

    capture.analyse()
    assert "[TCP] SQLi detected from 192.168.1.100" in capture.get_summary()
    assert capture.protocol_counter["TCP"] == 1


def test_capture_traffic_arp_spoof_detection():
    with _capture_with_eth0(), patch("src.tp1.utils.capture.sniff") as mock_sniff:
        mock_sniff.side_effect = lambda iface, prn, store: prn(_make_arp_spoof_packet())
        capture = Capture()
        capture.capture_traffic()

    capture.analyse()
    assert (
        "[ARP] ARP Spoofing from MAC AA:BB:CC:DD:EE:FF / IP 192.168.1.50"
        in capture.get_summary()
    )
    assert capture.protocol_counter["ARP"] == 1
