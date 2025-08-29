from __future__ import annotations

from typing import Dict, Optional

import httpx


def build_auth_headers(
    auth_type: Optional[str] = None,
    auth_token: Optional[str] = None,
    oauth_token_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    scope: Optional[str] = None,
) -> Dict[str, str]:
    if not auth_type:
        return {}
    if auth_type == "bearer":
        if not auth_token:
            raise ValueError("--auth-token required for auth_type=bearer")
        return {"Authorization": f"Bearer {auth_token}"}
    if auth_type == "oauth2-client-credentials":
        if not (oauth_token_url and client_id and client_secret):
            raise ValueError("--token-url, --client-id, --client-secret required for oauth2-client-credentials")
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if scope:
            data["scope"] = scope
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(oauth_token_url, data=data)
            resp.raise_for_status()
            tok = resp.json().get("access_token")
            if not tok:
                raise RuntimeError("No access_token in OAuth2 response")
            return {"Authorization": f"Bearer {tok}"}
    raise ValueError(f"Unsupported auth_type: {auth_type}")


