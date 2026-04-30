# test_parser.py
import logging
import pytest
from src.tp2.utils.parser import ShellcodeParser, load_shellcode

logger = logging.getLogger(__name__)


def test_shellcode_parser_hex_escape():
    # Vérifie que ShellcodeParser parse le format \xHH
    result = ShellcodeParser().load(r"\x41\x42\x43")
    logger.info(f"hex escape = {result}")
    assert result == b"ABC"


def test_shellcode_parser_raw_hex():
    # Vérifie que ShellcodeParser parse le hex brut
    result = ShellcodeParser().load("414243")
    logger.info(f"raw hex = {result}")
    assert result == b"ABC"


def test_shellcode_parser_invalid_raises():
    # Vérifie qu'un format invalide lève une ValueError
    with pytest.raises(ValueError):
        ShellcodeParser().load("ZZZZ")


def test_shellcode_parser_odd_length_raises():
    # Vérifie qu'un hex de longueur impaire lève une ValueError
    with pytest.raises(ValueError):
        ShellcodeParser().load("414")


def test_load_shellcode_shortcut():
    # Vérifie que la fonction utilitaire load_shellcode fonctionne
    assert load_shellcode(r"\x90") == b"\x90"
