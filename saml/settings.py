import logging
import os

from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

logger = logging.getLogger(__name__)

def _load_idp_settings_from_metadata() -> dict:
    """
    Parse remote IdP metadata and extract its settings.
    Returns an empty dict if SAML_IDP_METADATA_URL is not set or fetch fails.
    """
    metadata_url = os.environ.get("SAML_IDP_METADATA_URL")
    if not metadata_url:
        return {}
    validate_cert_env = os.environ.get("SAML_IDP_METADATA_VALIDATE_CERT", "true").lower()
    validate_cert = validate_cert_env not in ("0", "false", "no")

    try:
        metadata = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            metadata_url, validate_cert, timeout=5
        )
        return metadata.get("idp", {}) if isinstance(metadata, dict) else {}
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to parse IdP metadata from %s: %s", metadata_url, exc)
        return {}

def _load_sp_cert(vault_config: dict) -> str:
    """
    Load the SP public certificate from disk or fall back to Vault-provided PEM.

    Args:
        vault_config: dict with optional 'cert_file' containing PEM text.

    Returns:
        The certificate PEM string (trimmed) or empty string if not found.
    """
    cert_path = os.environ.get("SAML_SP_CERT_PATH", "saml/certs/public.pem")
    try:
        with open(cert_path, "r", encoding="utf-8") as pem:
            return pem.read().strip()
    except FileNotFoundError:
        logger.warning("SP cert not found at %s", cert_path)
        # Fallback to in-memory Vault cert
        cert_mem = vault_config.get("cert_file")
        if isinstance(cert_mem, str) and "-----BEGIN" in cert_mem:
            return cert_mem.strip()
        return ""
