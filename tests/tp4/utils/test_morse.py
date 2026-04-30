import logging
import src.tp4.utils.morse as morse

logger = logging.getLogger(__name__)


def test_translate_morse_sos():
    # Vérifie le décodage de "... --- ..." en "sos"
    result = morse.translate_morse("... --- ...")
    logger.info(f"translate_morse SOS = {result}")
    assert result == "sos"


def test_translate_morse_hello():
    # Vérifie le décodage de HELLO en morse
    result = morse.translate_morse(".... . .-.. .-.. ---")
    logger.info(f"translate_morse HELLO = {result}")
    assert result == "hello"


def test_check_morse_valid():
    # Vérifie que check_morse reconnaît une chaîne morse valide
    assert morse.check_morse("... --- ...") is True
    assert morse.check_morse(".-") is True


def test_check_morse_invalid():
    # Vérifie que check_morse rejette une chaîne non morse
    assert morse.check_morse("hello") is False
    assert morse.check_morse("736f73") is False
