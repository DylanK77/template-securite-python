"""
captcha.py — TP3
Gestion de la capture et de la résolution du captcha.

Modes disponibles (variable d'environnement CAPTCHA_MODE) :
  - "ocr"     : lit l'image avec pytesseract (défaut)
  - "manual"  : affiche l'image et demande une saisie console
  - "mock"    : utilise MOCK_CAPTCHA_VALUE sans interaction (tests)
"""

import mimetypes
import os
import re
import subprocess
import tempfile
import logging
from html.parser import HTMLParser
from urllib.parse import urljoin

logger = logging.getLogger("TP3")

# Noms de champs captcha connus — exclus de form_fields et utilisés pour le POST
CAPTCHA_FIELD_NAMES = {"captcha", "captcha_value", "answer", "code"}


# ---------------------------------------------------------------------------
# Parser HTML minimal — extrait formulaire + image captcha
# ---------------------------------------------------------------------------

class _FormParser(HTMLParser):
    """Extrait action/method du <form>, les <input> et l'image captcha."""

    def __init__(self):
        super().__init__()
        self.inputs: dict[str, str] = {}
        self.form_action: str = ""
        self.form_method: str = "post"
        self.captcha_img_src: str = ""
        # Nom réel du champ captcha trouvé dans le formulaire (ex: "answer")
        self.captcha_field_name: str = "captcha"

    def handle_starttag(self, tag: str, attrs: list) -> None:
        d = dict(attrs)
        if tag == "form":
            self.form_action = d.get("action", "")
            self.form_method = d.get("method", "post").lower()
        elif tag == "input":
            name = d.get("name", "")
            if name:
                self.inputs[name] = d.get("value", "")
                # Détecter le nom réel du champ captcha
                if name.lower() in CAPTCHA_FIELD_NAMES:
                    self.captcha_field_name = name
        elif tag == "img":
            src = d.get("src", "")
            alt = d.get("alt", "").lower()
            cls = d.get("class", "").lower()
            if "captcha" in src.lower() or "captcha" in alt or "captcha" in cls:
                self.captcha_img_src = src


# ---------------------------------------------------------------------------
# Classe principale
# ---------------------------------------------------------------------------

class Captcha:
    """
    Représente un captcha d'une page web.

    Attributs publics :
        url               -- URL de la page contenant le captcha
        image             -- chemin local vers l'image téléchargée
        value             -- réponse saisie ou simulée
        form_fields       -- champs cachés du formulaire (hors champ captcha)
        form_action       -- action du formulaire
        form_method       -- méthode HTTP du formulaire
        captcha_field_name -- nom réel du champ captcha dans le formulaire
    """

    def __init__(self, url: str, http_session=None):
        self.url: str = url
        self.image: str = ""
        self.value: str = ""
        self.form_fields: dict = {}
        self.form_action: str = ""
        self.form_method: str = "post"
        self.captcha_field_name: str = "captcha"
        self.captcha_img_src: str = ""
        self.page_body: str = ""
        self._http = http_session

    # ------------------------------------------------------------------
    # capture()
    # ------------------------------------------------------------------

    def capture(self) -> None:
        """
        GET la page, parse le HTML pour extraire les champs du formulaire
        et l'URL de l'image captcha. Télécharge l'image localement.
        Sans session HTTP (tests) : retourne immédiatement.
        """
        if self._http is None:
            logger.debug("capture() — pas de session HTTP, mode passif.")
            return

        logger.debug(f"[capture] GET {self.url}")
        resp = self._http.get(self.url, timeout=10)
        resp.raise_for_status()
        self.page_body = resp.text
        logger.debug(
            f"[capture] status={resp.status_code} | cookies={dict(self._http.cookies)}"
        )

        parser = _FormParser()
        parser.feed(self.page_body)

        self.form_fields = {
            k: v for k, v in parser.inputs.items()
            if k.lower() not in CAPTCHA_FIELD_NAMES
        }
        self.form_action = urljoin(self.url, parser.form_action or self.url)
        self.form_method = parser.form_method
        self.captcha_field_name = parser.captcha_field_name
        self.captcha_img_src = parser.captcha_img_src

        logger.debug(f"[capture] form_action={self.form_action!r} method={self.form_method!r}")
        logger.debug(f"[capture] hidden fields={self.form_fields}")
        logger.debug(f"[capture] captcha field name={self.captcha_field_name!r}")
        logger.debug(f"[capture] captcha img src={parser.captcha_img_src!r}")

        if self.captcha_img_src:
            self.download_captcha_image(self.captcha_img_src)
        else:
            logger.warning("[capture] Aucune image captcha détectée dans le HTML.")

    def download_captcha_image(self, src: str) -> None:
        """Télécharge l'image captcha dans un fichier temporaire.

        FIX: Priorité à Content-Type HTTP pour l'extension,
        fallback sur l'URL (sans les paramètres), puis magic bytes.
        Évite le bug de l'extension .php quand l'URL contient un token.
        """
        img_url = urljoin(self.url, src)
        logger.debug(f"[capture] téléchargement image: {img_url}")

        img_resp = self._http.get(img_url, timeout=10, stream=True)
        img_resp.raise_for_status()

        # 1. Priorité : Content-Type (le plus fiable)
        content_type = img_resp.headers.get("Content-Type", "").split(";")[0].strip()
        logger.debug(f"[capture] Content-Type reçu: {content_type!r}")

        ext = None
        if content_type and content_type.startswith("image/"):
            ext = mimetypes.guess_extension(content_type)
            # mimetypes peut renvoyer .jpe — on normalise
            if ext in (".jpe", ".jpeg"):
                ext = ".jpg"

        # 2. Fallback : extension de l'URL (sans query string)
        if not ext:
            url_path = src.split("?")[0]
            url_ext = os.path.splitext(url_path)[1].lower()
            if url_ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
                ext = url_ext
                logger.debug(f"[capture] extension depuis URL: {ext}")

        content = img_resp.content

        # 3. Fallback : magic bytes
        if not ext:
            ext = self._guess_ext_from_magic(content)
            if ext:
                logger.debug(f"[capture] extension depuis magic bytes: {ext}")

        if not ext:
            ext = ".bin"
            logger.warning("[capture] Type d'image inconnu, fallback .bin")

        tmp = tempfile.NamedTemporaryFile(
            suffix=ext, delete=False, prefix="captcha_tp3_"
        )
        tmp.write(content)
        tmp.close()
        self.image = tmp.name
        logger.info(f"[capture] image sauvegardée : {self.image}")

    @staticmethod
    def _guess_ext_from_magic(content: bytes) -> str | None:
        """Identifie le format d'image via les magic bytes."""
        if content[:8] == b"\x89PNG\r\n\x1a\n":
            return ".png"
        if content[:3] == b"\xff\xd8\xff":
            return ".jpg"
        if content[:6] in (b"GIF87a", b"GIF89a"):
            return ".gif"
        if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
            return ".webp"
        return None

    # ------------------------------------------------------------------
    # solve()
    # ------------------------------------------------------------------

    def solve(self) -> None:
        """
        Résout le captcha.

        CAPTCHA_MODE=ocr    → OCR local avec PIL + pytesseract
        CAPTCHA_MODE=mock   → valeur issue de MOCK_CAPTCHA_VALUE (défaut "FIXME")
        CAPTCHA_MODE=manual → ouvre l'image, attend une saisie console
        """
        mode = os.getenv("CAPTCHA_MODE", "ocr").lower()

        if mode == "mock":
            self.value = os.getenv("MOCK_CAPTCHA_VALUE", "FIXME")
            logger.debug(f"[solve] mode MOCK — valeur: {self.value!r}")
            return

        if mode == "ocr":
            self.value = self._solve_with_ocr()
            logger.info(f"[solve] OCR captcha: {self.value!r}")
            return

        # Mode manuel
        if self.image and os.path.exists(self.image):
            self._open_image(self.image)
            logger.info(f"[solve] image captcha : {self.image}")
        else:
            logger.warning("[solve] Aucune image locale disponible.")

        self.value = input(">>> Saisir la valeur du captcha : ").strip()
        logger.debug(f"[solve] valeur saisie: {self.value!r}")

    def _solve_with_ocr(self) -> str:
        """Lit l'image captcha avec pytesseract et nettoie le résultat."""
        if not self.image or not os.path.exists(self.image):
            logger.warning("[solve] OCR impossible: aucune image locale.")
            return ""

        try:
            from PIL import Image
            import pytesseract
        except ImportError as exc:
            logger.error("[solve] Installer Pillow et pytesseract pour le mode OCR.")
            raise RuntimeError("Pillow et pytesseract sont requis pour le TP3") from exc

        tesseract_cmd = os.getenv("TESSERACT_CMD", "")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd

        with Image.open(self.image) as image:
            prepared = self._prepare_image_for_ocr(image)
            raw_value = pytesseract.image_to_string(
                prepared,
                config=(
                    "--psm 7 "
                    "-c tessedit_char_whitelist=0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                ),
            )

        value = clean_ocr_result(raw_value)
        if not value:
            logger.warning(f"[solve] OCR vide ou illisible depuis: {raw_value!r}")
        return value

    @staticmethod
    def _prepare_image_for_ocr(image):
        """Prépare simplement l'image pour aider Tesseract."""
        from PIL import ImageOps

        gray = ImageOps.grayscale(image)
        scaled = gray.resize((gray.width * 2, gray.height * 2))
        return scaled.point(lambda px: 255 if px > 150 else 0)

    def _open_image(self, path: str) -> None:
        """Ouvre l'image avec le viewer système (non-bloquant, best-effort).

        FIX: Popen au lieu de call — ne bloque pas le script.
        """
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore
            else:
                viewer = "open" if os.uname().sysname == "Darwin" else "xdg-open"
                subprocess.Popen(
                    [viewer, path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                logger.debug(f"[solve] image ouverte avec '{viewer}' (non-bloquant)")
        except Exception as exc:
            logger.debug(f"[solve] Impossible d'ouvrir l'image: {exc}")

    # ------------------------------------------------------------------
    # Accesseur
    # ------------------------------------------------------------------

    def get_value(self) -> str:
        """Retourne la valeur du captcha (après solve())."""
        return self.value


def clean_ocr_result(value: str) -> str:
    """Nettoie une sortie OCR courte pour un CAPTCHA alphanumérique."""
    normalized = value.strip()
    normalized = normalized.translate(str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1"}))
    return "".join(re.findall(r"[A-Za-z0-9]+", normalized))
