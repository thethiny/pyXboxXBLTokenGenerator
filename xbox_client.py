"""
Xbox Live Authentication Client

Generic Xbox Live auth client that produces XBL3.0 tokens for any relying party.
No external Xbox libraries needed — only httpx and cryptography.

Multi-stage API (for backends/Flask):
    client = XboxAuthClient()
    auth_start = client.start_auth()                 # → redirect user to auth_start.auth_url
    client.finish_auth(authorization_code, auth_start)  # → user returns with code
    header = client.get_xbl3_header("rp://api.wbagora.com/")

Interactive helper (opens browser, handles callback):
    client = XboxAuthClient()
    client.authenticate_interactive()
    header = client.get_xbl3_header("rp://api.wbagora.com/")

Token refresh (no user interaction):
    client = XboxAuthClient()
    new_rt = client.refresh(refresh_token)
    header = client.get_xbl3_header("rp://api.wbagora.com/")
"""

import base64
import hashlib
import json
import secrets
import struct
import time
import uuid
import webbrowser
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.backends import default_backend


class AuthMethod(str, Enum):
    STANDARD = "standard"
    SISU = "sisu"


@dataclass
class AuthStartResult:
    """Returned by start_auth(). Contains everything needed to resume the flow."""
    auth_url: str
    state: str
    redirect_uri: str
    _internal: dict


# ============================================================
# ProofKey (EC P-256 Sisu Signing)
# ============================================================

class _ProofKey:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def get_jwk(self) -> dict:
        pub = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC", "alg": "ES256", "crv": "P-256", "use": "sig",
            "x": base64.urlsafe_b64encode(pub.x.to_bytes(32, "big")).rstrip(b"=").decode(),
            "y": base64.urlsafe_b64encode(pub.y.to_bytes(32, "big")).rstrip(b"=").decode(),
        }

    def sign(self, method: str, url: str, body: str) -> str:
        filetime = (int(time.time()) + 11644473600) * 10000000
        parsed = urlparse(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        data = b"".join([
            struct.pack(">I", 1), b"\x00", struct.pack(">Q", filetime), b"\x00",
            method.upper().encode() + b"\x00", path.encode() + b"\x00",
            b"\x00", body.encode() + b"\x00",
        ])
        der_sig = self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        header = struct.pack(">I", 1) + struct.pack(">Q", filetime) + r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64.b64encode(header).decode()

    def signed_headers(self, url: str, body: str) -> dict:
        return {
            "Signature": self.sign("POST", url, body),
            "Content-Type": "application/json",
            "x-xbl-contract-version": "1",
        }


# ============================================================
# Xbox Auth Client
# ============================================================

class XboxAuthClient:
    """
    Xbox Live authentication client (synchronous).

    Args:
        method: AuthMethod.STANDARD (default) or AuthMethod.SISU
        token_file: Path to cache refresh tokens (None to disable)
        port: Localhost port for interactive Standard OAuth callback
        client_id: Override the default Azure AD client ID (Standard only)
    """

    _STD_CLIENT_ID = "388ea51c-0b25-4029-aae2-17df49d23905"
    _STD_SCOPES = "Xboxlive.signin Xboxlive.offline_access"
    _SISU_APP_ID = "000000004c20a908"
    _SISU_REDIRECT = f"ms-xal-{_SISU_APP_ID}://auth"

    def __init__(
        self,
        method: AuthMethod = AuthMethod.STANDARD,
        token_file: Optional[Path] = None,
        port: int = 8080,
        client_id: Optional[str] = None,
    ):
        self.method = method
        self.token_file = token_file
        self.port = port
        self._client_id = client_id or self._STD_CLIENT_ID

        self._user_token: Optional[str] = None
        self._proof_key: Optional[_ProofKey] = None
        self._gamertag: Optional[str] = None
        self._xuid: Optional[str] = None

    @property
    def gamertag(self) -> Optional[str]:
        return self._gamertag

    @property
    def xuid(self) -> Optional[str]:
        return self._xuid

    @property
    def is_authenticated(self) -> bool:
        return self._user_token is not None

    # ============================================================
    # Multi-stage API (no browser, no I/O)
    # ============================================================

    def start_auth(self, redirect_uri: Optional[str] = None) -> AuthStartResult:
        """
        Stage 1: Start the auth flow.
        Returns an AuthStartResult with the URL to send the user to.
        """
        if self.method == AuthMethod.STANDARD:
            return self._start_standard(redirect_uri)
        else:
            return self._start_sisu()

    def finish_auth(self, authorization_code: str, auth_start: AuthStartResult) -> None:
        """
        Stage 2: Complete the auth flow with the authorization code from the callback.
        """
        if self.method == AuthMethod.STANDARD:
            self._finish_standard(authorization_code, auth_start)
        else:
            self._finish_sisu(authorization_code, auth_start)

    def refresh(self, refresh_token: str) -> str:
        """
        Refresh auth using a stored refresh token. No user interaction.
        Returns the new refresh token (save it for next time).
        """
        if self.method == AuthMethod.STANDARD:
            return self._refresh_standard(refresh_token)
        else:
            return self._refresh_sisu(refresh_token)

    # ============================================================
    # Interactive helper (opens browser, handles callback)
    # ============================================================

    def authenticate_interactive(self) -> None:
        """
        Convenience method: full auth with browser + localhost callback (Standard)
        or browser + paste-URL (Sisu). Handles token caching automatically.
        """
        # Try cached refresh first
        if self.token_file and self.token_file.exists():
            try:
                saved = json.loads(self.token_file.read_text())
                rt = saved.get("refresh_token") or saved.get("sisu_refresh_token")
                if rt:
                    new_rt = self.refresh(rt)
                    self._save_tokens(new_rt)
                    print(f"[+] Refreshed session for {self._gamertag}")
                    return
            except Exception:
                print("[*] Cached tokens expired, logging in...")

        # Fresh login
        auth_start = self.start_auth()

        print("[*] Opening browser for login...")
        webbrowser.open(auth_start.auth_url)

        if self.method == AuthMethod.STANDARD:
            code = self._localhost_callback()
        else:
            print("  After login, paste the redirect URL:")
            redirect_result = input("  > ").strip()
            params = parse_qs(urlparse(redirect_result).query)
            if "code" not in params:
                raise ValueError(f"No 'code' parameter in URL: {redirect_result}")
            code = params["code"][0]

        self.finish_auth(code, auth_start)

        # Save refresh token
        rt = auth_start._internal.get("refresh_token")
        if rt:
            self._save_tokens(rt)

        print(f"[+] Logged in as {self._gamertag}")

    # ============================================================
    # Token retrieval (post-auth)
    # ============================================================

    def get_xbl3_header(self, relying_party: str) -> str:
        """Get XBL3.0 authorization header for the given relying party."""
        if not self._user_token:
            raise RuntimeError("Not authenticated. Call start_auth/finish_auth or authenticate_interactive first.")
        xsts = self._request_xsts(relying_party, self._user_token)
        uhs = xsts["DisplayClaims"]["xui"][0]["uhs"]
        return f"XBL3.0 x={uhs};{xsts['Token']}"

    def get_xsts_token(self, relying_party: str) -> dict:
        """Get raw XSTS response dict for the given relying party."""
        if not self._user_token:
            raise RuntimeError("Not authenticated. Call start_auth/finish_auth or authenticate_interactive first.")
        return self._request_xsts(relying_party, self._user_token)

    # ============================================================
    # Standard OAuth — internals
    # ============================================================

    def _start_standard(self, redirect_uri: Optional[str] = None) -> AuthStartResult:
        redir = redirect_uri or f"http://localhost:{self.port}/auth/callback"
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": redir,
            "scope": self._STD_SCOPES,
            "state": state,
        }
        auth_url = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?{urlencode(params)}"
        return AuthStartResult(
            auth_url=auth_url,
            state=state,
            redirect_uri=redir,
            _internal={"redirect_uri": redir},
        )

    def _finish_standard(self, code: str, auth_start: AuthStartResult) -> None:
        redir = auth_start._internal["redirect_uri"]
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": self._client_id,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redir,
                    "scope": self._STD_SCOPES,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            oauth = resp.json()
            auth_start._internal["refresh_token"] = oauth.get("refresh_token")
            self._get_xbox_user_token(client, oauth["access_token"], prefix="d")

    def _refresh_standard(self, refresh_token: str) -> str:
        redir = f"http://localhost:{self.port}/auth/callback"
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": self._client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "scope": self._STD_SCOPES,
                    "redirect_uri": redir,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            oauth = resp.json()
            new_rt: str = oauth.get("refresh_token", refresh_token)
            self._get_xbox_user_token(client, oauth["access_token"], prefix="d")
            return new_rt

    # ============================================================
    # Sisu/XAL — internals
    # ============================================================

    def _start_sisu(self) -> AuthStartResult:
        self._proof_key = _ProofKey()
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        state = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()

        with httpx.Client(timeout=30) as client:
            device_token = self._get_device_token(client)

            url = "https://sisu.xboxlive.com/authenticate"
            body = json.dumps({
                "AppId": self._SISU_APP_ID,
                "TitleId": "1730755212",
                "RedirectUri": self._SISU_REDIRECT,
                "DeviceToken": device_token,
                "Sandbox": "RETAIL", "TokenType": "code",
                "Offers": ["service::user.auth.xboxlive.com::MBI_SSL"],
                "Query": {
                    "display": "android_phone",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                },
            })
            resp = client.post(url, content=body, headers=self._proof_key.signed_headers(url, body))
            resp.raise_for_status()

        session_id = resp.headers.get("x-sessionid")
        redirect_url = resp.json()["MsaOauthRedirect"]

        return AuthStartResult(
            auth_url=redirect_url,
            state=state,
            redirect_uri=self._SISU_REDIRECT,
            _internal={
                "code_verifier": code_verifier,
                "device_token": device_token,
                "session_id": session_id,
            },
        )

    def _finish_sisu(self, code: str, auth_start: AuthStartResult) -> None:
        internal = auth_start._internal
        with httpx.Client(timeout=30) as client:
            resp = client.post("https://login.live.com/oauth20_token.srf", data={
                "client_id": self._SISU_APP_ID,
                "code": code,
                "code_verifier": internal["code_verifier"],
                "grant_type": "authorization_code",
                "redirect_uri": self._SISU_REDIRECT,
                "scope": "service::user.auth.xboxlive.com::MBI_SSL",
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp.raise_for_status()
            tokens = resp.json()
            msa_token = tokens["access_token"]
            internal["refresh_token"] = tokens.get("refresh_token")

            sisu = self._sisu_authorize(
                client, msa_token, internal["device_token"], internal.get("session_id"),
            )
            self._user_token = sisu["UserToken"]["Token"]
            claims = sisu["AuthorizationToken"]["DisplayClaims"]["xui"][0]
            self._gamertag = claims.get("gtg")
            self._xuid = claims.get("xid")

    def _refresh_sisu(self, refresh_token: str) -> str:
        self._proof_key = _ProofKey()
        with httpx.Client(timeout=30) as client:
            resp = client.post("https://login.live.com/oauth20_token.srf", data={
                "client_id": self._SISU_APP_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "service::user.auth.xboxlive.com::MBI_SSL",
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp.raise_for_status()
            tokens = resp.json()
            new_rt: str = tokens.get("refresh_token", refresh_token)
            msa_token = tokens["access_token"]

            device_token = self._get_device_token(client)
            sisu = self._sisu_authorize(client, msa_token, device_token)
            self._user_token = sisu["UserToken"]["Token"]
            claims = sisu["AuthorizationToken"]["DisplayClaims"]["xui"][0]
            self._gamertag = claims.get("gtg")
            self._xuid = claims.get("xid")
            return new_rt

    # ============================================================
    # Shared helpers
    # ============================================================

    def _get_xbox_user_token(self, client: httpx.Client, access_token: str, prefix: str = "d") -> None:
        resp = client.post(
            "https://user.auth.xboxlive.com/user/authenticate",
            json={
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": f"{prefix}={access_token}",
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
            },
            headers={"Content-Type": "application/json", "x-xbl-contract-version": "1"},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Xbox user auth failed ({resp.status_code}): {resp.text[:300]}")
        data = resp.json()
        user_token: str = data["Token"]
        self._user_token = user_token

        xsts = self._request_xsts("http://xboxlive.com", user_token, client=client)
        claims = xsts["DisplayClaims"]["xui"][0]
        self._gamertag = claims.get("gtg")
        self._xuid = claims.get("xid")

    def _get_device_token(self, client: httpx.Client) -> str:
        if not self._proof_key:
            raise RuntimeError("Proof key not initialized")
        url = "https://device.auth.xboxlive.com/device/authenticate"
        device_id = "{" + str(uuid.uuid4()) + "}"
        body = json.dumps({
            "Properties": {
                "AuthMethod": "ProofOfPossession", "Id": device_id,
                "DeviceType": "Android", "SerialNumber": device_id,
                "Version": "15.0", "ProofKey": self._proof_key.get_jwk(),
            },
            "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT",
        })
        resp = client.post(url, content=body, headers=self._proof_key.signed_headers(url, body))
        resp.raise_for_status()
        return resp.json()["Token"]

    def _sisu_authorize(
        self, client: httpx.Client, msa_token: str,
        device_token: str, session_id: Optional[str] = None,
    ) -> dict:
        if not self._proof_key:
            raise RuntimeError("Proof key not initialized")
        url = "https://sisu.xboxlive.com/authorize"
        body = json.dumps({
            "AccessToken": f"t={msa_token}", "AppId": self._SISU_APP_ID,
            "DeviceToken": device_token, "Sandbox": "RETAIL",
            "SiteName": "user.auth.xboxlive.com",
            "UseModernGamertag": True, "ProofKey": self._proof_key.get_jwk(),
            **({"SessionId": session_id} if session_id else {}),
        })
        resp = client.post(url, content=body, headers=self._proof_key.signed_headers(url, body))
        if resp.status_code != 200:
            raise RuntimeError(f"Sisu authorize failed ({resp.status_code}): {resp.text[:300]}")
        return resp.json()

    def _request_xsts(self, rp: str, user_token: str, client: Optional[httpx.Client] = None) -> dict:
        def _do(c: httpx.Client) -> dict:
            resp = c.post(
                "https://xsts.auth.xboxlive.com/xsts/authorize",
                json={
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
                    "RelyingParty": rp,
                    "TokenType": "JWT",
                },
                headers={"Content-Type": "application/json", "x-xbl-contract-version": "1"},
            )
            if resp.status_code != 200:
                raise RuntimeError(f"XSTS failed ({resp.status_code}) RP={rp}: {resp.text[:300]}")
            return resp.json()

        if client:
            return _do(client)
        with httpx.Client(timeout=30) as c:
            return _do(c)

    def _localhost_callback(self) -> str:
        code = None

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                nonlocal code
                params = parse_qs(urlparse(self.path).query)
                if "code" in params:
                    code = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<h2>Authenticated! You can close this tab.</h2>")
                else:
                    self.send_response(400)
                    self.end_headers()
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002, N802
                pass

        server = HTTPServer(("localhost", self.port), Handler)
        server.timeout = 120
        while code is None:
            server.handle_request()
        server.server_close()
        return code

    def _save_tokens(self, refresh_token: str) -> None:
        if self.token_file:
            key = "sisu_refresh_token" if self.method == AuthMethod.SISU else "refresh_token"
            self.token_file.write_text(json.dumps({key: refresh_token}, indent=2))
