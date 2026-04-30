#!/usr/bin/env python3
import logging

from src.tp4.utils.connexion import launch

logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("Démarrage du programme")
    launch()


if __name__ == "__main__":
    main()
