import logging
import os

from onelogin.saml2.idp_metadata import OneLogin_Saml2_IdPMetadataParser

sp_domain = os.environ.get("SP_DOMAIN", "localhost:8088")

logger = logging.getLogger(__name__)

def _load_idp_settings_from_metadata() -> dict:
    metadata_url = os.environ.get("SAML_IDP_METADATA_URL")
    if not metadata_url:
        return {}
    validate_cert_env = os.environ.get("SAML_IDP_METADATA_VALIDATE_CERT", "true").lower()
    validate_cert = validate_cert_env not in ("0", "false", "no")
    try:
        metadata = OneLogin_Saml2_IdPMetadataParser.parse_remote(metadata_url, validate_cert)
        return metadata.get("idp", {}) if isinstance(metadata, dict) else {}
    except Exception as exc:  # pragma: no cover - best-effort metadata fetch
        logger.warning("Failed to parse IdP metadata from %s: %s", metadata_url, exc)
        return {}


_IDP_METADATA_SETTINGS = _load_idp_settings_from_metadata()

SAML_CONFIG = {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": f"https://{sp_domain}/metadata/",
        "assertionConsumerService": {
            "url": f"https://{sp_domain}/?acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": f"https://{sp_domain}/?sls",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": "",
        "privateKey": ""
    },
    "idp": _IDP_METADATA_SETTINGS or {
        "entityId": os.environ.get("SAML_IDP_ENTITY_ID", "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>"),
        "singleSignOnService": {
            "url": os.environ.get("SAML_IDP_SSO_URL", "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": os.environ.get("SAML_IDP_SLO_URL", "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": os.environ.get("SAML_IDP_CERT", "<onelogin_connector_cert>")
    }
}
