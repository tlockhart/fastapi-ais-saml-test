import logging
import os

from dependencies.vault_saml import get_saml_config
from utils.saml.sso.settings import _load_idp_settings_from_metadata, _load_sp_cert

sp_domain = os.environ.get("SP_DOMAIN", "localhost:8088")

logger = logging.getLogger(__name__)

# Try fetching SAML certs from Vault at import time


_IDP_METADATA_SETTINGS = _load_idp_settings_from_metadata()

SOURCE_CONFIG = {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": f"https://{sp_domain}/metadata/",
        "assertionConsumerService": {
            "url": f"https://{sp_domain}/?acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "singleLogoutService": {
            "url": f"https://{sp_domain}/?sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": _load_sp_cert(vault_saml),
        "privateKey": vault_saml.get("key_file", "").strip(),
    },
    "idp": _IDP_METADATA_SETTINGS
    or {
        "entityId": os.environ.get(
            "SAML_IDP_ENTITY_ID",
            "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>",
        ),
        "singleSignOnService": {
            "url": os.environ.get(
                "SAML_IDP_SSO_URL",
                "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>",
            ),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "singleLogoutService": {
            "url": os.environ.get(
                "SAML_IDP_SLO_URL",
                "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>",
            ),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": os.environ.get("SAML_IDP_CERT", "<onelogin_connector_cert>"),
    },
}
