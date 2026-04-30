# test_analyse.py
import logging
from unittest.mock import patch
from src.tp2.utils.analyse import (
    StringExtractor,
    PylibEmuAnalyzer,
    CapstoneAnalyzer,
    LLMAnalyzer,
)

logger = logging.getLogger(__name__)


def test_string_extractor_finds_ascii():
    # Vérifie que StringExtractor extrait les chaînes ASCII lisibles
    extractor = StringExtractor(min_len=4)
    result = extractor.get_shellcode_strings(b"\x00hello\x00world\x00")
    logger.info(f"strings = {result}")
    assert "hello" in result
    assert "world" in result


def test_string_extractor_ignores_short():
    # Vérifie que les séquences trop courtes sont ignorées
    extractor = StringExtractor(min_len=4)
    result = extractor.get_shellcode_strings(b"\x00ab\x00")
    assert result == []


def test_pylibemu_analyzer_unavailable():
    # Vérifie le message d'erreur si pylibemu est absent
    with patch.dict("sys.modules", {"pylibemu": None}):
        result = PylibEmuAnalyzer().get_pylibemu_analysis(b"\x90\x90")
    logger.info(f"pylibemu absent = {result}")
    assert "pylibemu" in result


def test_capstone_analyzer_unavailable():
    # Vérifie le message d'erreur si capstone est absent
    with patch.dict("sys.modules", {"capstone": None}):
        result = CapstoneAnalyzer().get_capstone_analysis(b"\x90\x90")
    logger.info(f"capstone absent = {result}")
    assert "capstone" in result


def test_llm_analyzer_heuristic_cmd_exe():
    # Vérifie que l'heuristique détecte cmd.exe
    with patch("src.tp2.utils.analyse.LLM_KEY", ""):
        result = LLMAnalyzer().get_llm_analysis(b"", ["cmd.exe /c whoami"], "", "")
    assert "cmd.exe" in result


def test_llm_analyzer_heuristic_ws2_32():
    # Vérifie que l'heuristique détecte ws2_32
    with patch("src.tp2.utils.analyse.LLM_KEY", ""):
        result = LLMAnalyzer().get_llm_analysis(b"", ["ws2_32.dll"], "", "")
    assert "ws2_32" in result


def test_llm_analyzer_no_hints():
    # Vérifie le message par défaut si aucun indice
    with patch("src.tp2.utils.analyse.LLM_KEY", ""):
        result = LLMAnalyzer().get_llm_analysis(b"", [], "", "")
    assert "Aucun indice" in result
