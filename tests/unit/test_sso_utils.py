import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from utils.saml.sso.fastapi_converters import prepare_fastapi_request_for_onelogin

app = FastAPI()


@app.api_route("/test", methods=["GET", "POST"])
async def test_endpoint(request: Request):
    saml_req = await prepare_fastapi_request_for_onelogin(request)
    return saml_req.dict()

client = TestClient(app)


def test_prepare_get_defaults():
    response = client.get("/test?foo=bar")
    assert response.status_code == 200
    data = response.json()
    assert data["http_host"] == "testserver"
    assert data["server_port"] == "80"
    assert data["script_name"] == "/test"
    assert data["get_data"] == {"foo": "bar"}
    assert data["post_data"] == {}
    assert data["https"] == "off"


def test_prepare_post_with_headers():
    headers = {"host": "example.com", "x-forwarded-proto": "https"}
    response = client.post("/test?foo=bar", data={"saml": "resp"}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["http_host"] == "example.com"
    assert data["server_port"] == "443"
    assert data["script_name"] == "/test"
    assert data["get_data"] == {"foo": "bar"}
    assert data["post_data"] == {"saml": "resp"}
    assert data["https"] == "on"
