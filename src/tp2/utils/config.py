# config.py
import os
from src.config import logging

logger = logging.getLogger("TP2")

# Seuil minimal de caractères pour qu'une séquence soit retenue comme chaîne
EXTRACT_MIN_CHARS = 4

# Offset mémoire utilisé comme base lors du désassemblage
DISASM_OFFSET = 0x1000

# Paramètres OpenAI récupérés depuis l'environnement
LLM_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
