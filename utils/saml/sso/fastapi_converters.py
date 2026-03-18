from fastapi import Request
from schemas.saml.sso import SAMLRequest


async def prepare_fastapi_request_for_onelogin(request: Request, debug: bool = False) -> SAMLRequest:
    """
    Convert FastAPI Request to the python3-saml expected dict wrapped in SAMLRequest.
    Uses headers for proxy-safe host and scheme resolution.
    """
    # Host and scheme from headers (proxy-safe), fallback to request.url
    host = request.headers.get("host") or request.url.netloc
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)

    # Port inference: use URL port or default by scheme
    port = request.url.port or (443 if scheme == "https" else 80)

    # Query params
    get_data = dict(request.query_params)
    # Form data for POST
    post_data = {}
    if request.method.upper() == "POST":
        form = await request.form()
        post_data = dict(form)

    saml_request = SAMLRequest(
        http_host=host,
        server_port=str(port),
        script_name=request.url.path,
        get_data=get_data,
        post_data=post_data,
        https="on" if scheme == "https" else "off",
    )

    if debug:
        safe = {
            "http_host": saml_request.http_host,
            "server_port": saml_request.server_port,
            "script_name": saml_request.script_name,
            "https": saml_request.https,
            "get_keys": list(saml_request.get_data.keys()),
            "post_keys": list(saml_request.post_data.keys()),
        }
        print(safe)

    return saml_request
