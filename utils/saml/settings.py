from copy import deepcopy

from saml import settings as saml_settings_source
from saml import advanced_settings as saml_advanced_settings

from utils.dict_utils import _deep_merge


def get_configs() -> dict:
    """
    Load base SAML settings and apply any advanced overrides.
    """
    source_settings = getattr(saml_settings_source, "SOURCE_CONFIG", {})
    result = deepcopy(source_settings)
    advanced_settings = getattr(saml_advanced_settings, "ADVANCED_CONFIG", None)
    if isinstance(advanced_settings, dict):
        _deep_merge(result, advanced_settings)
    return result
