"""
session.py — TP3
Gestion de la session HTTP pour résoudre un challenge captcha.

Cycle d'utilisation (cf. main.py) :
    session = Session(url)
    session.prepare_request()   # GET page + capture + solve captcha
    session.submit_request()    # POST formulaire
    while not session.process_response():
        session.prepare_request()
        session.submit_request()
    flag = session.get_flag()
"""

import os
import re
import logging
import requests
from html import unescape

from src.tp3.utils.captcha import Captcha

logger = logging.getLogger("TP3")

# ---------------------------------------------------------------------------
# Patterns de détection dans la réponse
# ---------------------------------------------------------------------------

_FLAG_PATTERNS = [
    re.compile(r"FLAG\{([^}]+)\}", re.IGNORECASE),
    re.compile(r"(FLAG-[A-Za-z0-9_-]+\{[^}]+\})", re.IGNORECASE),
    re.compile(r"(F\s*L\s*A\s*G\s*-\s*[A-Za-z0-9_-]+\s*\{\s*[^}]+?\s*\})", re.IGNORECASE),
    re.compile(r"ESGI\{([^}]+)\}", re.IGNORECASE),
    re.compile(r"CTF\{([^}]+)\}", re.IGNORECASE),
    re.compile(r'class=["\'"]flag["\'"][^>]*>\s*([^<]+)\s*<', re.IGNORECASE),
    re.compile(r'class=["\'"]alert-success[^"\']*["\'"][^>]*>\s*([^<]+)\s*<', re.IGNORECASE),
    re.compile(r"class=[\"'][^\"']*(?:success|valid)[^\"']*[\"'][^>]*>\s*([^<]+)\s*<", re.IGNORECASE),
    re.compile(r"flag\s*[=:]\s*([A-Za-z0-9_\-]{6,})", re.IGNORECASE),
]

_WRONG_FLAG_PATTERNS = [
    re.compile(r"incorrect\s+flag", re.IGNORECASE),
    re.compile(r"wrong\s+flag", re.IGNORECASE),
    re.compile(r"invalid\s+flag", re.IGNORECASE),
]

_CAPTCHA_ERROR_PATTERNS = [
    re.compile(r"incorrect\s+captcha", re.IGNORECASE),
    re.compile(r"captcha\s+incorrect", re.IGNORECASE),
    re.compile(r"invalid\s+captcha", re.IGNORECASE),
    re.compile(r"wrong\s+captcha", re.IGNORECASE),
    re.compile(r"captcha.*(?:fail|error|ko)", re.IGNORECASE),
    re.compile(r"undefined\s+array\s+key\s+[\"']code[\"']", re.IGNORECASE),
]

_ERROR_PATTERNS = [
    *_WRONG_FLAG_PATTERNS,
    *_CAPTCHA_ERROR_PATTERNS,
    re.compile(r"erreur", re.IGNORECASE),
    re.compile(r"mauvais", re.IGNORECASE),
    re.compile(r"try again", re.IGNORECASE),
]

_HELP_TEXT_PATTERNS = [
    re.compile(r"flag\s+is\s+an\s+integer\s+between", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    """
    Gère un cycle complet GET → résolution captcha → POST → validation.

    Attributs publics :
        url           -- URL du challenge
        captcha_value -- réponse au captcha (remplie par prepare_request)
        flag_value    -- valeur du token caché du formulaire
        valid_flag    -- flag obtenu après succès (rempli par process_response)
    """

    def __init__(self, url: str, flag_value: str = ""):
        self.url: str = url
        self.captcha_value: str = ""
        self.flag_value: str = flag_value
        self.valid_flag: str = ""
        self.last_result: str = ""
        self.response_text: str = ""
        self._initial_body: str = ""

        self._http = requests.Session()
        self._response: requests.Response | None = None
        self._form_fields: dict = {}
        self._form_action: str = url
        self._form_method: str = "post"
        # FIX: on retient le nom réel du champ captcha détecté côté serveur
        self._captcha_field_name: str = "captcha"
        self._captcha_img_src: str = ""
        self._form_initialized: bool = False

        if _needs_magic_word_header(self.url):
            self._http.headers.update({"Magic-Word": _magic_word_header_value()})
        if _needs_trackflaw_user_agent(self.url):
            self._http.headers.update({"User-Agent": "Trackflaw"})

    # ------------------------------------------------------------------
    # prepare_request — GET + parse + solve captcha
    # ------------------------------------------------------------------

    def prepare_request(self) -> None:
        """
        1. Crée un Captcha avec la session HTTP partagée
        2. capture() : GET la page, extrait le formulaire et l'image
        3. solve()   : résout le captcha (mock ou saisie manuelle)
        4. Stocke captcha_value, flag_value et les champs du formulaire
        """
        captcha = Captcha(self.url, http_session=self._http)
        if not self._form_initialized:
            captcha.capture()
            self._initial_body = captcha.page_body
            self._form_fields = dict(captcha.form_fields)
            self._form_action = captcha.form_action or self.url
            self._form_method = captcha.form_method
            self._captcha_field_name = captcha.captcha_field_name
            self._captcha_img_src = captcha.captcha_img_src
            self._form_initialized = True
        else:
            captcha.download_captcha_image(self._captcha_img_src)

        if _uses_no_captcha_bypass(self.url):
            self.captcha_value = ""
            logger.info("[solve] pas de captcha pour ce challenge")
        elif _uses_empty_captcha_bypass(self.url):
            self.captcha_value = ""
            logger.info("[solve] bypass captcha vide pour ce challenge")
        else:
            captcha.solve()
            self.captcha_value = captcha.get_value()

        if not self.flag_value:
            self.flag_value = (
                self._form_fields.get("flag")
                or self._form_fields.get("token")
                or self._form_fields.get("csrf_token")
                or next(iter(self._form_fields.values()), "")
            )

        logger.debug(
            f"[prepare] captcha_value={self.captcha_value!r} "
            f"captcha_field={self._captcha_field_name!r} "
            f"flag_value={self.flag_value!r}"
        )
        logger.debug(f"[prepare] form_fields={self._form_fields}")
        logger.debug(f"[prepare] form_action={self._form_action!r} method={self._form_method!r}")

    # ------------------------------------------------------------------
    # submit_request — POST le formulaire
    # ------------------------------------------------------------------

    def submit_request(self) -> None:
        """
        Envoie le formulaire avec :
          - tous les champs cachés extraits lors du GET
          - la valeur résolue du captcha sous le bon nom de champ

        FIX: utilise self._captcha_field_name au lieu de "captcha" hardcodé.
        """
        if (
            not self.captcha_value
            and not _uses_empty_captcha_bypass(self.url)
            and not _uses_no_captcha_bypass(self.url)
        ):
            logger.warning("[submit] captcha_value vide — prepare_request() appelé ?")

        data = dict(self._form_fields)
        if "flag" in data or self.flag_value:
            data["flag"] = self.flag_value
        # FIX: nom de champ dynamique au lieu de "captcha" hardcodé
        data[self._captcha_field_name] = self.captcha_value
        if _needs_code_alias(self.url):
            # Challenge 2 lit aussi "code" côté serveur, même si le HTML public
            # expose seulement le champ "captcha".
            data["code"] = self.captcha_value
        data["submit"] = ""

        headers = {
            "Referer": self.url,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if _needs_magic_word_header(self.url):
            headers["Magic-Word"] = _magic_word_header_value()
        if _needs_trackflaw_user_agent(self.url):
            headers["User-Agent"] = "Trackflaw"

        logger.debug(f"[submit] {self._form_method.upper()} {self._form_action}")
        logger.debug(f"[submit] data envoyée: {data}")

        try:
            if self._form_method == "post":
                self._response = self._http.post(
                    self._form_action, data=data, headers=headers, timeout=15
                )
            else:
                self._response = self._http.get(
                    self._form_action, params=data, headers=headers, timeout=15
                )
        except requests.exceptions.RequestException as exc:
            logger.error(f"[submit] Erreur réseau : {exc}")
            self._response = None
            return

        logger.debug(
            f"[submit] réponse: status={self._response.status_code} "
            f"taille={len(self._response.text)} | cookies={dict(self._http.cookies)}"
        )

        if os.getenv("DEBUG", "0") == "1":
            logger.debug(f"[submit] corps (500c): {self._response.text[:500]}")

    # ------------------------------------------------------------------
    # process_response — analyse la réponse
    # ------------------------------------------------------------------

    def process_response(self) -> bool:
        """
        Analyse la réponse HTTP.

        Retourne True  si le flag a été trouvé (fin du challenge).
        Retourne False si le captcha est incorrect ou la réponse ambiguë.
        """
        if self._response is None:
            logger.warning("[process] Pas de réponse disponible.")
            self.last_result = "no_response"
            return False

        body = self._response.text
        logger.debug(f"[process] status={self._response.status_code} taille={len(body)}")

        # --- Chercher le flag ---
        for pattern in _FLAG_PATTERNS:
            m = pattern.search(body)
            if m:
                self.valid_flag = _normalize_flag_match(m.group(1) if m.lastindex else m.group(0))
                self.last_result = "success"
                logger.info(f"[process] ✓ Flag trouvé : {self.valid_flag}")
                return True

        # --- Mauvais flag, captcha accepté ---
        for pattern in _WRONG_FLAG_PATTERNS:
            if pattern.search(body):
                self.last_result = "wrong_flag"
                logger.info("[process] ✗ Flag incorrect, passage au flag suivant...")
                return False

        if _looks_like_captcha3_wrong_flag(body):
            self.last_result = "wrong_flag"
            logger.info("[process] ✗ Flag incorrect, passage au flag suivant...")
            return False

        # --- Mauvais captcha, même flag à retenter ---
        for pattern in _CAPTCHA_ERROR_PATTERNS:
            if pattern.search(body):
                self.last_result = "wrong_captcha"
                logger.info("[process] ✗ Captcha invalide, même flag à retenter...")
                return False

        if _looks_like_trackflaw_wrong_flag(body):
            self.last_result = "wrong_flag"
            logger.info("[process] ✗ Flag incorrect, passage au flag suivant...")
            return False

        # --- Chercher un message d'erreur ---
        for pattern in _ERROR_PATTERNS:
            if pattern.search(body):
                self.last_result = "error"
                logger.info("[process] ✗ Réponse incorrecte, nouvelle tentative...")
                return False

        # --- Cas ambigu ---
        message = _extract_visible_message(body)
        if message and not _is_help_text(message):
            self.valid_flag = message
            self.response_text = body
            self.last_result = "success"
            logger.info("[process] ✓ Réponse sans erreur détectée : %s", self.valid_flag)
            return True

        self.last_result = "unknown"
        self.response_text = body
        logger.warning("[process] Réponse ambiguë — ni succès ni erreur détectés.")
        logger.debug(f"[process] corps (500c): {body[:500]}")
        return False

    # ------------------------------------------------------------------
    # get_flag
    # ------------------------------------------------------------------

    def get_flag(self) -> str:
        """Retourne le flag validé (après process_response() == True)."""
        return self.valid_flag


def _extract_visible_message(body: str) -> str:
    """Extrait un court message visible depuis une réponse HTML."""
    candidates = re.findall(
        r"<p[^>]*class=[\"'][^\"']*(?:success|valid|info|alert)[^\"']*[\"'][^>]*>(.*?)</p>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not candidates:
        candidates = re.findall(r"<p[^>]*>(.*?)</p>", body, flags=re.IGNORECASE | re.DOTALL)
    for candidate in candidates:
        text = re.sub(r"<[^>]+>", " ", candidate)
        text = " ".join(unescape(text).split())
        if text and not any(pattern.search(text) for pattern in _ERROR_PATTERNS):
            return text
    return ""


def _is_help_text(text: str) -> bool:
    return any(pattern.search(text) for pattern in _HELP_TEXT_PATTERNS)


def _needs_code_alias(url: str) -> bool:
    return "/captcha2/" in url


def _needs_magic_word_header(url: str) -> bool:
    return "/captcha4/" in url or "/captcha5/" in url


def _magic_word_header_value() -> str:
    return os.getenv("TP3_MAGIC_WORD", "N0_t1m3_to_Sl33p")


def _needs_trackflaw_user_agent(url: str) -> bool:
    return "/captcha5/" in url


def _uses_empty_captcha_bypass(url: str) -> bool:
    return "/captcha2/" in url


def _uses_no_captcha_bypass(url: str) -> bool:
    return "/captcha4/" in url or "/captcha5/" in url


def _looks_like_captcha3_wrong_flag(body: str) -> bool:
    return "<!-- Ok -->" in body


def _normalize_flag_match(value: str) -> str:
    flag = " ".join(value.split())
    spaced = re.search(
        r"F\s*L\s*A\s*G\s*-\s*([A-Za-z0-9_-]+)\s*\{\s*([^}]+?)\s*\}",
        flag,
        flags=re.IGNORECASE,
    )
    if spaced:
        return f"FLAG-{spaced.group(1)}{{{spaced.group(2).strip()}}}"
    return flag


def _looks_like_trackflaw_wrong_flag(body: str) -> bool:
    """Challenge 2 renvoie un marqueur hexadécimal court quand le flag est faux."""
    return bool(
        re.search(
            r">\s*[0-9a-f]{6}\s*</div>\s*</body>",
            body,
            flags=re.IGNORECASE,
        )
    )
