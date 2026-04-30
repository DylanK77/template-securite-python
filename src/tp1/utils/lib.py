PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

BASE_PROTOCOLS = ("TCP", "UDP", "ICMP", "ARP")


def hello_world() -> str:
    return "hello world"


def choose_interface() -> str:
    try:
        value = input("Choix interface (default eth0): ").strip()
    except Exception:
        return "eth0"
    return value or "eth0"


def proto_name(proto) -> str:
    if proto == "ARP":
        return "ARP"
    try:
        protocol_number = int(proto)
    except (TypeError, ValueError):
        return "UNKNOWN"

    return PROTO_MAP.get(protocol_number, f"OTHER_{protocol_number}")
