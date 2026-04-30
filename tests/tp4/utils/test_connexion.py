import logging
import src.tp4.utils.connexion as connexion

logger = logging.getLogger(__name__)


class FakeRemote:
    # Simule une connexion distante vide
    def recvline(self, timeout=2):
        return b""

    def sendline(self, data):
        pass

    def close(self):
        pass


def test_connects_to_expected_host(monkeypatch):
    # Vérifie que launch() se connecte au bon host
    called = {}

    def fake_remote(host, port):
        called["host"] = host
        called["port"] = port
        return FakeRemote()

    monkeypatch.setattr(connexion, "remote", fake_remote)
    connexion.launch()

    assert called["host"] == "31.220.95.27"
    assert called["port"] == 13337


def test_has_failed_detects_stop_words():
    # Vérifie que has_failed retourne True sur les mots d'échec
    assert connexion.has_failed("trop lent !")
    assert connexion.has_failed("non oust")
    assert not connexion.has_failed("tout va bien")


def test_has_succeeded_detects_success_words():
    # Seul un vrai flag doit arreter la session.
    assert connexion.has_succeeded("FLAG{abc}")
    assert not connexion.has_succeeded("GG bien joué")
    assert not connexion.has_succeeded(
        "A décoder: a2x2bWJtY2FzYndkbHBqaXByOGgxcHhqODFmeDBjbzQ="
    )
    assert not connexion.has_succeeded("essaie encore")


def test_extract_payload_returns_blob():
    # Vérifie que extract_payload extrait correctement la donnée après ":"
    result = connexion.extract_payload("A décoder: 736f73")
    logger.info(f"extract_payload = {result}")
    assert result == "736f73"


def test_extract_payload_returns_none_if_no_keyword():
    # Vérifie que extract_payload retourne None si pas de "a décoder:"
    assert connexion.extract_payload("Bienvenue sur le serveur") is None


def test_start_session_waits_after_empty_read():
    class DelayedRemote:
        def __init__(self):
            self.lines = [b"", b"FLAG{tp4_ok}\n"]
            self.closed = False

        def recvline(self, timeout=2):
            return self.lines.pop(0) if self.lines else b""

        def close(self):
            self.closed = True

    remote = DelayedRemote()

    connexion.start_session(remote)

    assert remote.closed is True
