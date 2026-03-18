
from fastapi import FastAPI, Request, Form, HTTPException
from typing import Optional
from starlette.responses import RedirectResponse, Response

# Load python3-saml onelogin toolkit
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from utils.saml.sso.fastapi_converters import prepare_fastapi_request_for_onelogin
from utils.saml.settings import get_configs

app = FastAPI()
# Enable Debug True for simple logging
DEBUG = True

@app.get("/")
async def root():
  return { "message": "Hello World" }

@app.post("/test")
async def test(request: Request, p1: Optional[str] = Form(None), p2: Optional[str] = Form(None)):
  req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  return req

@app.get('/api/saml/login')
async def saml_login(request: Request):
  saml_req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  saml_settings = get_configs()
  auth = OneLogin_Saml2_Auth(saml_req.dict(), saml_settings)
  # saml_settings = auth.get_settings()
  # metadata = saml_settings.get_sp_metadata()
  # errors = saml_settings.validate_metadata(metadata)
  # if len(errors) == 0:
  #   print(metadata)
  # else:
  #   print("Error found on Metadata: %s" % (', '.join(errors)))
  callback_url = auth.login()
  response = RedirectResponse(url=callback_url)
  return response

@app.post('/api/saml/callback')
async def saml_login_callback(request: Request):
  req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  saml_settings = get_configs()
  auth = OneLogin_Saml2_Auth(req, saml_settings)
  auth.process_response() # Process IdP response
  errors = auth.get_errors() # This method receives an array with the errors
  if len(errors) == 0:
    if not auth.is_authenticated(): # This check if the response was ok and the user data retrieved or not (user authenticated)
      return "user Not authenticated"
    else:
      return "User authenticated"
  else:
    print("Error when processing SAML Response: %s %s" % (', '.join(errors), auth.get_last_error_reason()))
    return "Error in callback"
  
"""
Added: Additional Routes
"""
@app.post('/api/saml/acs')
async def saml_acs(request: Request):
  req = await prepare_fastapi_request_for_onelogin(request, DEBUG)
  saml_settings = get_configs()
  auth = OneLogin_Saml2_Auth(req, saml_settings)
  auth.process_response() # Process IdP response
  errors = auth.get_errors() # This method receives an array with the errors
  if len(errors) == 0:
    if not auth.is_authenticated(): # This check if the response was ok and the user data retrieved or not (user authenticated)
      return "user Not authenticated"
    else:
      return "User authenticated"
  else:
    print("Error when processing SAML Response: %s %s" % (', '.join(errors), auth.get_last_error_reason()))
    return "Error in callback"
  
@app.get('/api/saml/metadata')
async def saml_metadata():
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
