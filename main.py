import logging

from fastapi import FastAPI, Request, Form, HTTPException
from typing import Optional
from starlette.responses import RedirectResponse, Response

# Load python3-saml onelogin toolkit
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from utils.saml.auth import build_authenticated_redirect_response, resolve_saml_subject
from utils.saml.sso.fastapi_converters import prepare_fastapi_request_for_onelogin
from utils.saml.settings import get_configs

# Logger used by the assertion consumer handler
logger = logging.getLogger(__name__)
app = FastAPI()
# Enable Debug True for simple logging
DEBUG = True

@app.get("/")
async def root():
  """Return a simple heartbeat message for the root path."""
  return { "message": "Hello World" }

@app.post("/test")
async def test(request: Request, p1: Optional[str] = Form(None), p2: Optional[str] = Form(None)):
  """Echo the converted FastAPI request so tooling can inspect prepared SAML data."""
  req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  return req

@app.get('/api/saml/login')
async def saml_login(request: Request):
  """Build an AuthNRequest, ask the IdP for authentication, and redirect the browser."""
  saml_req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  saml_settings = get_configs()
  auth = OneLogin_Saml2_Auth(saml_req.dict(), saml_settings)

  # Create AuthnRequest and route to the IdP, via Redirect
  callback_url = auth.login()
  response = RedirectResponse(url=callback_url)
  return response

  
@app.post('/api/saml/acs')
async def saml_acs(request: Request):
  """Assertion consumer endpoint that processes IdP responses and issues HM_JWT."""
  req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  saml_settings = get_configs()
  auth = OneLogin_Saml2_Auth(req, saml_settings)
  auth.process_response()
  errors = auth.get_errors()
  if errors:
    logger.error("Error when processing SAML Response: %s %s", ", ".join(errors), auth.get_last_error_reason())
    return "Error in callback"

  if not auth.is_authenticated():
    logger.warning("Unauthenticated SAML response")
    raise HTTPException(status_code=401, detail="SAML response did not authenticate the user")

  username = resolve_saml_subject(auth)
  return build_authenticated_redirect_response(username)

@app.get('/api/saml/metadata')
async def saml_metadata():
  """Serve the SP metadata document so IdPs can fetch the SP’s configuration."""
  raw_settings = get_configs()
  saml_settings = OneLogin_Saml2_Settings(raw_settings)
  metadata = saml_settings.get_sp_metadata()
  errors = saml_settings.validate_metadata(metadata)
  if len(errors) == 0:
    return Response(content=metadata, media_type="text/xml")
  else:
    return "Error found on Metadata: %s" % (', '.join(errors))
  
@app.get('/api/saml/ls')
async def saml_logout(request: Request):
  """Clear any session/cookie state and redirect the user back to the root."""
  try:
    response = RedirectResponse(url="/", status_code=302) 
    response.delete_cookie(key="HM_JWT", path="/")
    if hasattr(request, "session"):
      request.session.clear()
    return response
  except Exception as e:
    print(e)
    raise HTTPException(status_code=500, detail=f"Logout error: {str(e)}")
    return
