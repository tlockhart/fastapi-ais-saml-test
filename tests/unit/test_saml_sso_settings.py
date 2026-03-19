import copy

import pytest

from utils.saml.sso.settings import get_configs
import utils.saml.sso.settings as sso_settings


def teardown_function(function):
    # Clean up any attributes we set on saml_settings_source or saml_advanced_settings
    for module in (sso_settings.saml_settings_source, sso_settings.saml_advanced_settings):
        if hasattr(module, "SOURCE_CONFIG"):
            delattr(module, "SOURCE_CONFIG")
        if hasattr(module, "ADVANCED_CONFIG"):
            delattr(module, "ADVANCED_CONFIG")


def test_get_configs_no_base_or_advanced():
    # Neither SOURCE_CONFIG nor ADVANCED_CONFIG set => empty result
    result = get_configs()
    assert result == {}


def test_get_configs_base_only(monkeypatch):
    base = {"key": 1}
    monkeypatch.setattr(sso_settings.saml_settings_source, "SOURCE_CONFIG", base, raising=False)
    # ADVANCED_CONFIG unset
    result = get_configs()
    assert result == base
    # Ensure a fresh copy, not the original dict
    assert result is not base


def test_get_configs_with_advanced_merge(monkeypatch):
    base = {"a": 1, "nested": {"x": 1}}
    advanced = {"nested": {"y": 2}, "new": 3}
    monkeypatch.setattr(sso_settings.saml_settings_source, "SOURCE_CONFIG", base, raising=False)
    monkeypatch.setattr(sso_settings.saml_advanced_settings, "ADVANCED_CONFIG", advanced, raising=False)

    result = get_configs()
    # Original base remains unchanged
    assert base == {"a": 1, "nested": {"x": 1}}
    # Merged output contains nested and new keys from advanced settings
    assert result == {"a": 1, "nested": {"x": 1, "y": 2}, "new": 3}


def test_get_configs_advanced_not_dict(monkeypatch):
    base = {"foo": "bar"}
    monkeypatch.setattr(sso_settings.saml_settings_source, "SOURCE_CONFIG", base, raising=False)
    monkeypatch.setattr(sso_settings.saml_advanced_settings, "ADVANCED_CONFIG", ["not", "dict"], raising=False)
    result = get_configs()
    assert result == base
