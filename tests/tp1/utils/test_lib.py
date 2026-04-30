from unittest.mock import patch

from src.tp1.utils.lib import BASE_PROTOCOLS, choose_interface, hello_world, proto_name


def test_when_hello_world_then_return_hello_world():
    assert hello_world() == "hello world"


def test_when_choose_interface_then_return_user_choice():
    with patch("builtins.input", return_value="wlan0"):
        assert choose_interface() == "wlan0"

    with patch("builtins.input", return_value=""):
        assert choose_interface() == "eth0"


def test_proto_name_tcp_udp():
    assert proto_name(1) == "ICMP"
    assert proto_name(6) == "TCP"
    assert proto_name(17) == "UDP"
    assert proto_name("ARP") == "ARP"
    assert proto_name(999) == "OTHER_999"
    assert proto_name(None) == "UNKNOWN"


def test_base_protocols_are_declared():
    assert BASE_PROTOCOLS == ("TCP", "UDP", "ICMP", "ARP")
