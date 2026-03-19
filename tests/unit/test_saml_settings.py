import os
import logging

import pytest

from saml.settings import _load_sp_cert, vault_saml


def test_load_sp_cert_from_file(tmp_path, monkeypatch):
    # Create a temporary cert file and point env var to it
    cert_file = tmp_path / "test_cert.pem"
    cert_file.write_text("FILE_CERT_CONTENT\n")
    monkeypatch.setenv("SAML_SP_CERT_PATH", str(cert_file))
    # Ensure vault_saml does not interfere
    monkeypatch.setattr("saml.settings.vault_saml", {})
    result = _load_sp_cert()
    assert result == "FILE_CERT_CONTENT"


def test_load_sp_cert_from_vault(monkeypatch):
    # Remove env var so default file path triggers FileNotFoundError
    monkeypatch.delenv("SAML_SP_CERT_PATH", raising=False)
    # Provide vault_saml with in-memory PEM content
    fake_pem = "-----BEGIN FAKE CERT-----\nDATA\n-----END FAKE CERT-----"
    monkeypatch.setattr("saml.settings.vault_saml", {"cert_file": fake_pem})
    result = _load_sp_cert()
    assert result == fake_pem.strip()


def test_load_sp_cert_no_source(monkeypatch, caplog):
    # Neither file nor vault provides cert
    monkeypatch.delenv("SAML_SP_CERT_PATH", raising=False)
    monkeypatch.setattr("saml.settings.vault_saml", {})
    caplog.set_level(logging.WARNING)
    result = _load_sp_cert()
    assert result == ""
    assert "SP cert not found" in caplog.text


def test_load_sp_cert_file_error_then_vault(monkeypatch, tmp_path):
    # Env var points to unreadable location -> fallback to vault
    bad_path = tmp_path / "nonexistent.pem"
    monkeypatch.setenv("SAML_SP_CERT_PATH", str(bad_path))
    fake_pem = "-----BEGIN ANOTHER CERT-----DATA"
    monkeypatch.setattr("saml.settings.vault_saml", {"cert_file": fake_pem})
    result = _load_sp_cert()
    assert result == fake_pem.strip()
