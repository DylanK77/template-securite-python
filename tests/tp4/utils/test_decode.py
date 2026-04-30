import logging
import src.tp4.utils.decode as decode

logger = logging.getLogger(__name__)


def test_hex_to_text_sos():
    # Vérifie le décodage hex de "736f73" en "sos"
    result = decode.hex_to_text("736f73")
    logger.info(f"hex_to_text = {result}")
    assert result == "sos"


def test_looks_like_hex_valid():
    # Vérifie que looks_like_hex accepte un hex valide
    assert decode.looks_like_hex("736f73") is True


def test_looks_like_hex_invalid():
    # Vérifie que looks_like_hex rejette une chaîne non hex
    assert decode.looks_like_hex("hello") is False
    assert decode.looks_like_hex("736f7") is False  # longueur impaire


def test_b64_to_text_sos():
    # Vérifie le décodage base64 de "c29z" en "sos"
    result = decode.b64_to_text("c29z")
    logger.info(f"b64_to_text = {result}")
    assert result == "sos"


def test_looks_like_base64_valid():
    # Vérifie que looks_like_base64 accepte une chaîne base64 valide
    assert decode.looks_like_base64("c29zYWFh") is True


def test_looks_like_base64_too_short():
    # Vérifie que looks_like_base64 rejette les chaînes trop courtes
    assert decode.looks_like_base64("abc") is False


def test_auto_decode_morse():
    # Vérifie que auto_decode détecte et traduit le morse
    assert decode.auto_decode("... --- ...") == "sos"


def test_auto_decode_hex():
    # Vérifie que auto_decode détecte et traduit le hex
    assert decode.auto_decode("736f73") == "sos"


def test_auto_decode_base64():
    # Vérifie que auto_decode détecte et traduit le base64
    assert decode.auto_decode("aGVsbG8h") == "hello!"
