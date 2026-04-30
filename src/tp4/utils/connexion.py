import logging
import unicodedata

from pwn import context, remote

from src.tp4.utils.decode import auto_decode

context.log_level = "error"

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

HOST = "31.220.95.27"
PORT = 13337

STOP_WORDS = ("trop lent", "non oust")
SUCCESS_WORDS = ("flag",)
READ_TIMEOUT_SECONDS = 5
MAX_EMPTY_READS = 3


def has_failed(text: str) -> bool:
    normalized = _normalize(text)
    return any(word in normalized for word in STOP_WORDS)


def has_succeeded(text: str) -> bool:
    normalized = _normalize(text)
    return any(word in normalized for word in SUCCESS_WORDS)


def extract_payload(text: str) -> str | None:
    normalized = _normalize(text)
    marker = "a decoder:"
    if marker not in normalized:
        return None
    marker_index = normalized.index(marker)
    original_index = marker_index + len(marker)
    return text[original_index:].strip()


def handle_line(io, text: str) -> bool:
    logger.info("recv: %s", text)

    if has_failed(text):
        logger.warning("Serveur a signale un echec, arret.")
        return False

    if has_succeeded(text):
        logger.info("Message final: %s", text)
        return False

    payload = extract_payload(text)
    if payload is None:
        return True

    answer = auto_decode(payload)
    logger.info("send: %s", answer)
    io.sendline(answer.encode())
    return True


def start_session(io) -> None:
    empty_reads = 0
    try:
        while True:
            raw_line = io.recvline(timeout=READ_TIMEOUT_SECONDS)
            if not raw_line:
                empty_reads += 1
                if empty_reads >= MAX_EMPTY_READS:
                    logger.warning("Aucune donnee recue, arret de la session.")
                    break
                continue
            empty_reads = 0
            if not handle_line(io, raw_line.decode(errors="ignore").strip()):
                break
    except EOFError:
        logger.info("Connexion fermee par le serveur")
    finally:
        io.close()


def launch() -> None:
    logger.info("Connexion a %s:%s", HOST, PORT)
    start_session(remote(HOST, PORT))


def _normalize(text: str) -> str:
    lowered = text.lower()
    without_accents = unicodedata.normalize("NFKD", lowered)
    return "".join(char for char in without_accents if not unicodedata.combining(char))
