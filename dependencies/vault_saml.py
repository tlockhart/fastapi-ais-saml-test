"""
VaultSAML module: initializes a Vault client and fetches SP signing key and certificate for SAML.
"""
import os

from hvac import Client
from dotenv import load_dotenv

def validate_vault_env() -> None:
    """
    Ensure all required environment variables for Vault authentication are set.

    Raises:
        RuntimeError: if any required Vault environment variable is missing.
    """
    required_env_vars = [
        "vault_url",
        "vault_namespace",
        "vault_role_id",
        "vault_secret_id",
    ]

    missing = [var for var in required_env_vars if not os.getenv(var)]
    if missing:
        raise RuntimeError(f"Missing required Vault environment variables: {', '.join(missing)}")

def get_vault_client() -> Client:
    """
    Initialize and authenticate an hvac Vault Client using AppRole.

    Loads any overrides from vault.env, then uses required env vars for login.

    Returns:
        Client: authenticated hvac Vault client.

    Raises:
        RuntimeError: if authentication fails.
    """
    validate_vault_env()
    # Load additional Vault settings from file if present
    load_dotenv("vault.env")
    print(" Initializing Vault client...")
    print("   VAULT_URL       =", os.getenv("vault_url"))
    print("   VAULT_NAMESPACE =", os.getenv("vault_namespace"))

    client = Client(
        url=os.getenv("vault_url"),
        namespace=os.getenv("vault_namespace"),
        verify=True,
    )

    # Authenticate using AppRole credentials
    client.auth.approle.login(
        role_id=os.getenv("vault_role_id"),
        secret_id=os.getenv("vault_secret_id"),
    )

    if not client.is_authenticated():
        raise RuntimeError("❌ Vault authentication failed")

    print(" Vault authentication successful")
    return client

def get_saml_config() -> dict:
    """
    Fetch SAML SP private key and public certificate PEM contents from Vault.

    Returns:
        dict: mapping with keys 'key_file' and 'cert_file' containing in-memory PEM strings.
    """
    client = get_vault_client()

    print(" Fetching SAML secrets from Vault...")
    # Read the latest version of the SAML path under KV v2
    secret_data = client.secrets.kv.v2.read_secret_version(
        mount_point="secret",
        path="hostmaster-dev/saml",
    )["data"]["data"]

    # Extract PEM contents for SP private key and public cert
    saml_certs = {
        "key_file": secret_data["private.key"],
        "cert_file": secret_data["public.pem"],
    }

    return saml_certs
