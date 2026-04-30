import base64
import binascii
import re

from src.tp4.utils.morse import check_morse, translate_morse


def looks_like_hex(text: str) -> bool:
    cleaned = text.strip()
    return len(cleaned) > 0 and len(cleaned) % 2 == 0 and bool(
        re.fullmatch(r"[0-9a-fA-F]+", cleaned)
    )


def hex_to_text(text: str) -> str:
    try:
        raw = binascii.unhexlify(text.strip())
    except (binascii.Error, ValueError):
        return text.strip()
    return raw.decode("utf-8", errors="ignore")


def looks_like_base64(text: str) -> bool:
    cleaned = text.strip()
    if len(cleaned) < 8 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cleaned):
        return False
    try:
        b64_to_text(cleaned)
    except (binascii.Error, ValueError):
        return False
    return True


def b64_to_text(text: str) -> str:
    cleaned = text.strip()
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    raw = base64.b64decode(padded, validate=True)
    return raw.decode("utf-8", errors="ignore")


def auto_decode(text: str) -> str:
    cleaned = text.strip()
    if check_morse(cleaned):
        return translate_morse(cleaned)
    if looks_like_hex(cleaned):
        return hex_to_text(cleaned)
    if looks_like_base64(cleaned):
        return b64_to_text(cleaned)
    return cleaned
