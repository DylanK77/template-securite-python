# analyse.py
from __future__ import annotations
import re
import textwrap
from typing import List
from src.tp2.utils.config import EXTRACT_MIN_CHARS, DISASM_OFFSET, LLM_KEY, LLM_MODEL, logger


class StringExtractor:
    """Extrait les chaînes ASCII lisibles d'un shellcode."""

    def __init__(self, min_len: int = EXTRACT_MIN_CHARS):
        self.min_len = min_len

    # Recherche les séquences ASCII imprimables dans les bytes du shellcode
    def get_shellcode_strings(self, payload: bytes) -> List[str]:
        needle = rb"[ -~]{" + str(self.min_len).encode() + rb",}"
        results = [m.group(0).decode("ascii", errors="ignore")
                   for m in re.finditer(needle, payload)]
        logger.debug(f"Strings extraites : {results}")
        return results


class PylibEmuAnalyzer:
    """Émule le shellcode avec pylibemu et retourne le profil d'appels API."""

    # Lance l'émulateur et retourne la sortie de profil
    def get_pylibemu_analysis(self, payload: bytes) -> str:
        try:
            import pylibemu  # type: ignore
        except Exception as err:
            return f"[pylibemu] module absent: {err}"
        return self._run(payload)

    # Exécute concrètement l'émulation
    def _run(self, payload: bytes) -> str:
        try:
            import pylibemu  # type: ignore
            emu = pylibemu.Emulator()
            offset = max(0, emu.shellcode_getpc_test(payload))
            emu.prepare(payload, offset)
            emu.test()
            profile = getattr(emu, "emu_profile_output", "")
            return str(profile) if profile else "[pylibemu] aucun appel API tracé"
        except Exception as err:
            return f"[pylibemu] échec: {err}"


class CapstoneAnalyzer:
    """Désassemble le shellcode x86 32 bits avec Capstone."""

    def __init__(self, base: int = DISASM_OFFSET):
        self.base = base

    # Désassemble et formate les instructions
    def get_capstone_analysis(self, payload: bytes) -> str:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # type: ignore
        except Exception as err:
            return f"[capstone] module absent: {err}"
        return self._format(payload)

    # Itère sur les instructions et construit la sortie
    def _format(self, payload: bytes) -> str:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # type: ignore
            engine = Cs(CS_ARCH_X86, CS_MODE_32)
            rows = [
                f"0x{i.address:08x}:  {i.mnemonic:<10} {i.op_str}"
                for i in engine.disasm(payload, self.base)
            ]
            return "\n".join(rows) if rows else "[capstone] aucune instruction produite"
        except Exception as err:
            return f"[capstone] échec: {err}"


class LLMAnalyzer:
    """Analyse le shellcode via LLM ou heuristique si pas de clé API."""

    # Délègue au LLM ou au fallback selon la disponibilité de la clé
    def get_llm_analysis(self, payload: bytes, strings: List[str], emu_out: str, disasm_out: str) -> str:
        if not LLM_KEY:
            return self._heuristic(strings, emu_out)
        return self._call_openai(strings, emu_out, disasm_out)

    # Analyse heuristique sans appel réseau — combine strings et sortie pylibemu
    def _heuristic(self, strings: List[str], emu_out: str = "") -> str:
        # On combine les strings ET la sortie pylibemu pour plus d'indices
        all_text = " ".join(strings) + " " + emu_out.lower()
        lowered = all_text.lower()
        findings = []
        if "cmd.exe" in lowered:
            findings.append("Exécution de commandes détectée (cmd.exe).")
        if "ws2_32" in lowered:
            findings.append("Activité réseau probable (ws2_32).")
        if "winexec" in lowered:
            findings.append("Appel WinExec identifié.")
        if "urlmon" in lowered:
            findings.append("Téléchargement de fichier détecté (urlmon.dll).")
        if "urldownloadtofile" in lowered:
            findings.append("Appel URLDownloadToFile — downloader probable.")
        if ".exe" in lowered:
            findings.append("Chemin vers un exécutable détecté.")
        if "loadlibrary" in lowered:
            findings.append("Chargement dynamique de DLL (LoadLibrary).")
        if "net user" in lowered:
            findings.append("Création d'utilisateur Windows (net user).")
        if "localgroup" in lowered:
            findings.append("Ajout au groupe Administrateurs détecté.")
        if "virtualalloc" in lowered:
            findings.append("Allocation mémoire dynamique (VirtualAlloc).")
        if "recv" in lowered or "connect" in lowered:
            findings.append("Connexion réseau entrante/sortante détectée.")
        body = "\n".join(f"  • {f}" for f in findings) if findings else "  • Aucun indice significatif"
        return f"[analyse heuristique]\n{body}"

    # Envoie le contexte à OpenAI et retourne l'explication
    def _call_openai(self, strings: List[str], emu_out: str, disasm_out: str) -> str:
        try:
            from openai import OpenAI  # type: ignore
            client = OpenAI()
            prompt = textwrap.dedent(f"""
                Tu es un expert en analyse de shellcode.
                Décris ce que fait ce shellcode :
                - Objectif principal
                - Étapes d'exécution
                - IOCs (chaînes, IP, ports)
                - Niveau de dangerosité
                - Incertitudes éventuelles

                strings  : {strings}
                pylibemu : {emu_out[:2000]}
                capstone : {disasm_out[:2000]}
            """).strip()
            reply = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
            )
            return reply.choices[0].message.content.strip()
        except Exception as err:
            return f"[LLM] requête échouée: {err}"


# Fonctions utilitaires pour usage direct sans instancier les classes
def get_shellcode_strings(payload: bytes) -> List[str]:
    return StringExtractor().get_shellcode_strings(payload)

def get_pylibemu_analysis(payload: bytes) -> str:
    return PylibEmuAnalyzer().get_pylibemu_analysis(payload)

def get_capstone_analysis(payload: bytes) -> str:
    return CapstoneAnalyzer().get_capstone_analysis(payload)

def get_llm_analysis(payload: bytes, strings: List[str], emu_out: str, disasm_out: str) -> str:
    return LLMAnalyzer().get_llm_analysis(payload, strings, emu_out, disasm_out)