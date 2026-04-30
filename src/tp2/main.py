# main.py
import os
import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.parser import load_shellcode
from tp2.utils.analyse import (
    get_shellcode_strings,
    get_pylibemu_analysis,
    get_capstone_analysis,
    get_llm_analysis,
)


# Construit le parser CLI et retourne le chemin du fichier shellcode
def build_cli() -> str:
    cli = argparse.ArgumentParser(description="Analyseur de shellcode - TP2")
    cli.add_argument("-f", "--file", required=True, help="Fichier shellcode à analyser")
    return cli.parse_args().file


# Affiche une section avec son titre et son contenu
def print_section(title: str, content: str) -> None:
    logger.info(f"\n{'='*10} {title} {'='*10}")
    logger.info(content if content else "(vide)")


# Orchestre l'analyse complète et affiche les résultats section par section
def run_analysis(shellcode: bytes) -> None:
    strings = get_shellcode_strings(shellcode)
    emu_out = get_pylibemu_analysis(shellcode)
    disasm_out = get_capstone_analysis(shellcode)
    llm_out = get_llm_analysis(shellcode, strings, emu_out, disasm_out)

    print_section("STRINGS", "\n".join(strings) if strings else "(aucune)")
    print_section("PYLIBEMU", emu_out)
    print_section("CAPSTONE", disasm_out)
    print_section("LLM", llm_out)


# Point d'entrée principal
def main() -> int:
    filepath = build_cli()
    raw_text = Path(filepath).read_text(encoding="utf-8", errors="ignore")
    shellcode = load_shellcode(raw_text)
    logger.info(f"Shellcode chargé : {len(shellcode)} octets")
    run_analysis(shellcode)
    logger.info("Analyse complète.")
    return 0


if __name__ == "__main__":
    logger.info(f"Key openai value : {os.getenv('OPENAI_KEY')}")
    raise SystemExit(main())
