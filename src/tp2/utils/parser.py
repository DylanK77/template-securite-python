# parser.py
import re
from src.tp2.utils.config import logger


class ShellcodeParser:
    """Parse un fichier texte contenant un shellcode en bytes."""

    # Tente de parser un shellcode au format \xHH
    def _parse_hex_escape(self, text: str) -> bytes | None:
        matches = re.findall(r"\\x([0-9a-fA-F]{2})", text)
        if not matches:
            return None
        return bytes(int(b, 16) for b in matches)

    # Tente de parser un shellcode en hex brut (sans préfixe \x)
    def _parse_raw_hex(self, text: str) -> bytes:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
        if len(cleaned) < 2 or len(cleaned) % 2 != 0:
            raise ValueError("Hex brut invalide : longueur impaire ou vide.")
        return bytes.fromhex(cleaned)

    # Détecte le format et retourne les bytes du shellcode
    def load(self, raw_text: str) -> bytes:
        stripped = raw_text.strip()
        logger.debug("Détection du format shellcode...")
        if "\\x" in stripped:
            result = self._parse_hex_escape(stripped)
            if result is not None:
                logger.debug(f"Format \\xHH détecté — {len(result)} octets")
                return result
            raise ValueError("Format \\xHH détecté mais aucun octet valide trouvé.")
        result = self._parse_raw_hex(stripped)
        logger.debug(f"Format hex brut détecté — {len(result)} octets")
        return result


# Fonction utilitaire pour usage direct sans instancier la classe
def load_shellcode(raw_text: str) -> bytes:
    return ShellcodeParser().load(raw_text)