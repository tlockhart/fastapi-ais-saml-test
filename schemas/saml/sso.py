from typing import Any, Dict
from pydantic import BaseModel


class SAMLRequest(BaseModel):
    """
    Pydantic model for OneLogin python3-saml request parameters.
    """
    http_host: str
    server_port: str
    script_name: str
    get_data: Dict[str, Any]
    post_data: Dict[str, Any]
    https: str
