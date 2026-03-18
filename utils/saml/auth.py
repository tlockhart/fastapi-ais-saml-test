"""JWT and SAML helper utilities for issuing HM_JWT cookies."""

import datetime as dt
import json
import os
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

import jwt
from fastapi import HTTPException, status
from fastapi.responses import RedirectResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth

JWT_SECRET_KEY = os.environ.get("HM_JWT_SECRET_KEY", "change-me")
JWT_ALGORITHM = os.environ.get("HM_JWT_ALGORITHM", "HS256")
JWT_EXPIRATION_MINUTES = int(os.environ.get("HM_JWT_EXPIRATION_MINUTES", "30"))
JWT_REDIRECT_URL = os.environ.get("HM_JWT_REDIRECT_URL", "/dashboard")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development").lower()


def _normalize_attributes(attrs: Mapping[str, Sequence[str]]) -> Dict[str, Sequence[str]]:
    return {key.lower(): value for key, value in attrs.items()}


def resolve_saml_subject(
    auth: OneLogin_Saml2_Auth,
    attribute_candidates: Iterable[str] = ("username", "user", "email", "mail"),
) -> str:
    """Return the NameID or first-supported attribute claimed in the SAML assertion."""

    nameid = auth.get_nameid()
    if nameid:
        return nameid

    attributes = _normalize_attributes(auth.get_attributes())
    for candidate in attribute_candidates:
        values = attributes.get(candidate)
        if values:
            # use the first value and ensure it is a string
            value = values[0]
            if value:
                return value

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="No user identifier found in SAML assertion",
    )


def create_access_token(data: Dict[str, Any], expires_delta: Optional[dt.timedelta] = None) -> str:
    """Return a JWT containing `data` and an expiration timestamp."""

    to_encode: Dict[str, Any] = data.copy()
    now = dt.datetime.utcnow()
    expire = now + (expires_delta or dt.timedelta(minutes=JWT_EXPIRATION_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def set_jwt_cookie(response: RedirectResponse, token: str, expires_delta: dt.timedelta) -> None:
    """Attach the HM_JWT cookie to the redirect response."""

    secure_flag = ENVIRONMENT == "production"
    response.set_cookie(
        key="HM_JWT",
        value=token,
        httponly=True,
        secure=secure_flag,
        samesite="Lax",
        max_age=int(expires_delta.total_seconds()),
        path="/",
    )


def build_authenticated_redirect_response(
    username: str, redirect_url: Optional[str] = None
) -> RedirectResponse:
    """Create a redirect response that sets HM_JWT and returns minimal JSON for non-browser clients."""

    expires_delta = dt.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    token = create_access_token({"sub": username}, expires_delta=expires_delta)
    payload = {"access_token": token, "token_type": "bearer", "username": username}
    response = RedirectResponse(
        url=redirect_url or JWT_REDIRECT_URL,
        status_code=status.HTTP_302_FOUND,
    )
    set_jwt_cookie(response, token, expires_delta)
    response.headers["Content-Type"] = "application/json"
    response.body = json.dumps(payload).encode("utf-8")
    return response
