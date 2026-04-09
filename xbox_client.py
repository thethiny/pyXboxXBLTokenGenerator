"""
Xbox Live Authentication Client (Stateless)

All methods are class methods — no instance state. Auth state flows in and out
via dataclasses, so multiple users can authenticate concurrently.

Multi-stage flow (Flask backend):
    # Stage 1: Start auth
    auth_start = XboxAuth.start_auth(redirect_uri="https://myapp.com/callback")
    # → store auth_start, send user to auth_start.auth_url

    # Stage 2: User returns with code
    auth_session = XboxAuth.finish_auth(code, auth_start)
    # → store auth_session (contains user_token, gamertag, xuid, refresh_token)

    # Stage 3: Get XBL3.0 header for any RP
    header = XboxAuth.get_xbl3_header(auth_session, "rp://api.minecraftservices.com/")

    # Later: refresh without user interaction
    auth_session = XboxAuth.refresh(auth_session.refresh_token)

Interactive (CLI):
    auth_session = XboxAuth.authenticate_interactive()
    header = XboxAuth.get_xbl3_header(auth_session, "rp://api.minecraftservices.com/")
"""

import base64
import hashlib
import json
import secrets
import struct
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
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
    """Returned by start_auth(). Store this and pass to finish_auth()."""
    auth_url: str
    state: str
    redirect_uri: str
    method: AuthMethod
    _internal: dict = field(repr=False)


@dataclass
class DeviceCodeState:
    """Returned by start_device_code(). Contains everything needed to display to user and poll."""
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int
    message: str
    client_id: str


@dataclass
class XboxAuthSession:
    """Authenticated session. Pass to get_xbl3_header() / get_xsts_token()."""
    user_token: str
    gamertag: Optional[str]
    xuid: Optional[str]
    refresh_token: Optional[str]
    method: AuthMethod

    def to_dict(self) -> dict:
        """Serialize for storage (e.g. Flask session, database)."""
        return {
            "user_token": self.user_token,
            "gamertag": self.gamertag,
            "xuid": self.xuid,
            "refresh_token": self.refresh_token,
            "method": self.method.value,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "XboxAuthSession":
        """Deserialize from storage."""
        return cls(
            user_token=data["user_token"],
            gamertag=data.get("gamertag"),
            xuid=data.get("xuid"),
            refresh_token=data.get("refresh_token"),
            method=AuthMethod(data.get("method", "standard")),
        )


# ============================================================
# Internal config (never exposed to the user)
# ============================================================

@dataclass(frozen=True)
class _XboxClientConfig:
    client_id: str = "388ea51c-0b25-4029-aae2-17df49d23905" # Xbox Live Client ID
    scopes: str = "Xboxlive.signin Xboxlive.offline_access" # Xbox Live API scopes
    sisu_app_id: str = "000000004c20a908" # Minecraft
    sisu_redirect_uri: Optional[str] = None  # defaults to ms-xal-{sisu_app_id}://auth
    title_id: str = "1730755212" # Minecraft
    device_type: str = "Android"
    device_version: str = "15.0"
    sandbox: str = "RETAIL"
    sisu_display: str = "android_phone"
    sisu_scope: str = "service::user.auth.xboxlive.com::MBI_SSL" # Xbox Live API scope

    @property
    def effective_sisu_redirect(self) -> str:
        return self.sisu_redirect_uri or f"ms-xal-{self.sisu_app_id}://auth"

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "scopes": self.scopes,
            "sisu_app_id": self.sisu_app_id,
            "sisu_redirect_uri": self.sisu_redirect_uri,
            "title_id": self.title_id,
            "device_type": self.device_type,
            "device_version": self.device_version,
            "sandbox": self.sandbox,
            "sisu_display": self.sisu_display,
            "sisu_scope": self.sisu_scope,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "_XboxClientConfig":
        return cls(**{k: v for k, v in data.items() if v is not None})

    @classmethod
    def build(
        cls,
        *,
        client_id: Optional[str] = None,
        scopes: Optional[str] = None,
        sisu_app_id: Optional[str] = None,
        sisu_redirect_uri: Optional[str] = None,
        title_id: Optional[str] = None,
        device_type: Optional[str] = None,
        device_version: Optional[str] = None,
        sandbox: Optional[str] = None,
        sisu_display: Optional[str] = None,
        sisu_scope: Optional[str] = None,
    ) -> "_XboxClientConfig":
        kwargs = {k: v for k, v in {
            "client_id": client_id, "scopes": scopes,
            "sisu_app_id": sisu_app_id, "sisu_redirect_uri": sisu_redirect_uri,
            "title_id": title_id, "device_type": device_type,
            "device_version": device_version, "sandbox": sandbox,
            "sisu_display": sisu_display, "sisu_scope": sisu_scope,
        }.items() if v is not None}
        return cls(**kwargs)


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
# Xbox Auth (stateless class methods)
# ============================================================

class XboxAuth:
    """
    Xbox Live authentication — all class methods, no instance state.
    Auth state is passed in/out via AuthStartResult and XboxAuthSession.
    """

    _DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
    _DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
    _DEVICE_CODE_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

    # ============================================================
    # Multi-stage API
    # ============================================================

    @classmethod
    def start_auth(
        cls,
        method: AuthMethod = AuthMethod.STANDARD,
        redirect_uri: Optional[str] = None,
        port: int = 8080,
        *,
        client_id: Optional[str] = None,
        scopes: Optional[str] = None,
        sisu_app_id: Optional[str] = None,
        sisu_redirect_uri: Optional[str] = None,
        title_id: Optional[str] = None,
        device_type: Optional[str] = None,
        device_version: Optional[str] = None,
        sandbox: Optional[str] = None,
        sisu_display: Optional[str] = None,
        sisu_scope: Optional[str] = None,
    ) -> AuthStartResult:
        """
        Stage 1: Start auth. Returns AuthStartResult with the URL to send the user to.

        Args:
            method: STANDARD (localhost/custom callback) or SISU (paste-URL)
            redirect_uri: Custom callback URL (Standard only). Defaults to localhost:{port}.
            port: Localhost port if redirect_uri not specified (Standard only).
            client_id: Azure AD client ID (Standard) or override default.
            scopes: OAuth scopes (Standard only).
            sisu_app_id: Sisu/XAL application ID.
            sisu_redirect_uri: Sisu redirect URI. Defaults to ms-xal-{sisu_app_id}://auth.
            title_id: Xbox title ID for Sisu auth.
            device_type: Device type for device token (e.g. "Android", "Win32").
            device_version: OS version for device token.
            sandbox: Xbox sandbox ID (e.g. "RETAIL").
            sisu_display: Display mode for Sisu auth query.
            sisu_scope: OAuth scope for Sisu flow.
        """
        config = _XboxClientConfig.build(
            client_id=client_id, scopes=scopes, sisu_app_id=sisu_app_id,
            sisu_redirect_uri=sisu_redirect_uri, title_id=title_id,
            device_type=device_type, device_version=device_version,
            sandbox=sandbox, sisu_display=sisu_display, sisu_scope=sisu_scope,
        )
        if method == AuthMethod.STANDARD:
            return cls._start_standard(redirect_uri, port, config)
        else:
            return cls._start_sisu(config)

    @classmethod
    def finish_auth(cls, authorization_code: str, auth_start: AuthStartResult) -> XboxAuthSession:
        """
        Stage 2: Complete auth with the authorization code.
        Returns an XboxAuthSession with user_token, gamertag, refresh_token, etc.
        """
        if auth_start.method == AuthMethod.STANDARD:
            return cls._finish_standard(authorization_code, auth_start)
        else:
            return cls._finish_sisu(authorization_code, auth_start)

    @classmethod
    def refresh(
        cls,
        refresh_token: str,
        method: AuthMethod = AuthMethod.STANDARD,
        port: int = 8080,
        *,
        client_id: Optional[str] = None,
        scopes: Optional[str] = None,
        sisu_app_id: Optional[str] = None,
        device_type: Optional[str] = None,
        device_version: Optional[str] = None,
        sandbox: Optional[str] = None,
        sisu_scope: Optional[str] = None,
    ) -> XboxAuthSession:
        """
        Refresh auth using a stored refresh token. No user interaction.
        Returns a new XboxAuthSession (with a new refresh_token — save it).
        """
        config = _XboxClientConfig.build(
            client_id=client_id, scopes=scopes, sisu_app_id=sisu_app_id,
            device_type=device_type, device_version=device_version,
            sandbox=sandbox, sisu_scope=sisu_scope,
        )
        if method == AuthMethod.STANDARD:
            return cls._refresh_standard(refresh_token, port, config)
        else:
            return cls._refresh_sisu(refresh_token, config)

    # ============================================================
    # Device Code Flow (RFC 8628)
    # ============================================================

    @classmethod
    def start_device_code(
        cls,
        client_id: str,
        *,
        scopes: Optional[str] = None,
    ) -> DeviceCodeState:
        """
        Request a new device code from Microsoft.
        The user visits verification_uri and types user_code to sign in.

        Args:
            client_id: Azure AD client ID. Must be a public client with device code enabled.
            scopes: OAuth scopes. Defaults to "Xboxlive.signin Xboxlive.offline_access".
        """
        config = _XboxClientConfig.build(scopes=scopes)
        resp = httpx.post(
            cls._DEVICE_CODE_URL,
            data={"client_id": client_id, "scope": config.scopes},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        return DeviceCodeState(
            device_code=data["device_code"],
            user_code=data["user_code"],
            verification_uri=data["verification_uri"],
            expires_in=data["expires_in"],
            interval=data["interval"],
            message=data["message"],
            client_id=client_id,
        )

    @classmethod
    def poll_device_code(
        cls,
        device_code: str,
        client_id: str,
        *,
        sandbox: Optional[str] = None,
    ) -> dict:
        """
        Single non-blocking poll for device code approval.

        Args:
            device_code: from start_device_code()
            client_id: must match the one used in start_device_code()
            sandbox: Xbox sandbox ID for XSTS token request.

        Returns:
            {"status": "ok", "session": XboxAuthSession}
            {"status": "pending"}
            {"status": "pending", "slow_down": True}
            {"status": "error", "error": "..."}
        """
        config = _XboxClientConfig.build(sandbox=sandbox)
        resp = httpx.post(
            cls._DEVICE_CODE_TOKEN_URL,
            data={
                "grant_type": cls._DEVICE_CODE_GRANT_TYPE,
                "client_id": client_id,
                "device_code": device_code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        data = resp.json()

        if "access_token" in data:
            try:
                with httpx.Client(timeout=30) as client:
                    session = cls._build_session_from_access_token(
                        client, data["access_token"], "d",
                        data.get("refresh_token"), AuthMethod.STANDARD, config,
                    )
                return {"status": "ok", "session": session}
            except Exception as e:
                return {"status": "error", "error": f"Xbox token exchange failed: {e}"}

        error = data.get("error", "")
        description = data.get("error_description", "")
        if error == "authorization_pending":
            return {"status": "pending"}
        elif error == "slow_down":
            return {"status": "pending", "slow_down": True}
        elif error == "authorization_declined":
            return {"status": "error", "error": "User declined the sign-in request."}
        elif error == "expired_token":
            return {"status": "error", "error": "Device code expired. Please try again."}
        else:
            return {"status": "error", "error": f"{error}: {description}"}

    @classmethod
    def await_device_code(
        cls,
        device_code: str,
        client_id: str,
        expires_in: int = 900,
        interval: int = 5,
        *,
        sandbox: Optional[str] = None,
    ) -> XboxAuthSession:
        """
        Blocking helper: polls until user approves or code expires.

        Args:
            device_code: from start_device_code()
            client_id: must match the one used in start_device_code()
            expires_in: seconds until expiry (from start_device_code())
            interval: seconds between polls (from start_device_code())
            sandbox: Xbox sandbox ID for XSTS token request.
        """
        deadline = time.time() + expires_in
        while time.time() < deadline:
            result = cls.poll_device_code(device_code, client_id, sandbox=sandbox)
            if result["status"] == "ok":
                return result["session"]
            elif result.get("slow_down"):
                interval += 5
            elif result["status"] == "error":
                raise RuntimeError(result["error"])
            time.sleep(interval)
        raise RuntimeError("Device code expired before user approved.")

    # ============================================================
    # Token retrieval
    # ============================================================

    @classmethod
    def get_xbl3_header(cls, session: XboxAuthSession, relying_party: str, *, sandbox: Optional[str] = None) -> str:
        """Get XBL3.0 authorization header for the given relying party."""
        xsts = cls._request_xsts(relying_party, session.user_token, sandbox=sandbox or _XboxClientConfig().sandbox)
        uhs = xsts["DisplayClaims"]["xui"][0]["uhs"]
        return f"XBL3.0 x={uhs};{xsts['Token']}"

    @classmethod
    def get_xsts_token(cls, session: XboxAuthSession, relying_party: str, *, sandbox: Optional[str] = None) -> dict:
        """Get raw XSTS response dict for the given relying party."""
        return cls._request_xsts(relying_party, session.user_token, sandbox=sandbox or _XboxClientConfig().sandbox)

    # ============================================================
    # Interactive helper
    # ============================================================

    @classmethod
    def authenticate_interactive(
        cls,
        method: AuthMethod = AuthMethod.STANDARD,
        port: int = 8080,
        *,
        client_id: Optional[str] = None,
        scopes: Optional[str] = None,
        sisu_app_id: Optional[str] = None,
        sisu_redirect_uri: Optional[str] = None,
        title_id: Optional[str] = None,
        device_type: Optional[str] = None,
        device_version: Optional[str] = None,
        sandbox: Optional[str] = None,
        sisu_display: Optional[str] = None,
        sisu_scope: Optional[str] = None,
        token_file: Optional[Path] = None,
    ) -> XboxAuthSession:
        """
        Convenience: full auth with browser + auto callback (Standard)
        or browser + paste-URL (Sisu). Handles token caching if token_file is set.
        """
        config_kwargs = dict(
            client_id=client_id, scopes=scopes, sisu_app_id=sisu_app_id,
            sisu_redirect_uri=sisu_redirect_uri, title_id=title_id,
            device_type=device_type, device_version=device_version,
            sandbox=sandbox, sisu_display=sisu_display, sisu_scope=sisu_scope,
        )

        # Try cached refresh first
        if token_file and token_file.exists():
            try:
                saved = json.loads(token_file.read_text())
                rt = saved.get("refresh_token") or saved.get("sisu_refresh_token")
                if rt:
                    session = cls.refresh(rt, method=method, port=port, **config_kwargs)
                    cls._save_tokens(token_file, session)
                    print(f"[+] Refreshed session for {session.gamertag}")
                    return session
            except Exception:
                print("[*] Cached tokens expired, logging in...")

        auth_start = cls.start_auth(method=method, port=port, **config_kwargs)

        print("[*] Opening browser for login...")
        webbrowser.open(auth_start.auth_url)

        if method == AuthMethod.STANDARD:
            code = cls._localhost_callback(port)
        else:
            print("  After login, paste the redirect URL:")
            redirect_result = input("  > ").strip()
            params = parse_qs(urlparse(redirect_result).query)
            if "code" not in params:
                raise ValueError(f"No 'code' parameter in URL: {redirect_result}")
            code = params["code"][0]

        session = cls.finish_auth(code, auth_start)

        if token_file:
            cls._save_tokens(token_file, session)

        print(f"[+] Logged in as {session.gamertag}")
        return session

    # ============================================================
    # Standard OAuth — internals
    # ============================================================

    @classmethod
    def _start_standard(cls, redirect_uri: Optional[str], port: int, config: _XboxClientConfig) -> AuthStartResult:
        redir = redirect_uri or f"http://localhost:{port}/auth/callback"
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": redir,
            "scope": config.scopes,
            "state": state,
        }
        auth_url = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?{urlencode(params)}"
        return AuthStartResult(
            auth_url=auth_url,
            state=state,
            redirect_uri=redir,
            method=AuthMethod.STANDARD,
            _internal={"config": config.to_dict(), "redirect_uri": redir},
        )

    @classmethod
    def _finish_standard(cls, code: str, auth_start: AuthStartResult) -> XboxAuthSession:
        config = _XboxClientConfig.from_dict(auth_start._internal["config"])
        redir = auth_start._internal["redirect_uri"]
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": config.client_id,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redir,
                    "scope": config.scopes,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            oauth = resp.json()
            return cls._build_session_from_access_token(
                client, oauth["access_token"], "d",
                oauth.get("refresh_token"), AuthMethod.STANDARD, config,
            )

    @classmethod
    def _refresh_standard(cls, refresh_token: str, port: int, config: _XboxClientConfig) -> XboxAuthSession:
        redir = f"http://localhost:{port}/auth/callback"
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": config.client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "scope": config.scopes,
                    "redirect_uri": redir,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            oauth = resp.json()
            return cls._build_session_from_access_token(
                client, oauth["access_token"], "d",
                oauth.get("refresh_token", refresh_token), AuthMethod.STANDARD, config,
            )

    # ============================================================
    # Sisu/XAL — internals
    # ============================================================

    @classmethod
    def _start_sisu(cls, config: _XboxClientConfig) -> AuthStartResult:
        proof_key = _ProofKey()
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        state = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()

        with httpx.Client(timeout=30) as client:
            device_token = cls._get_device_token(client, proof_key, config)
            url = "https://sisu.xboxlive.com/authenticate"
            body = json.dumps({
                "AppId": config.sisu_app_id,
                "TitleId": config.title_id,
                "RedirectUri": config.effective_sisu_redirect,
                "DeviceToken": device_token,
                "Sandbox": config.sandbox, "TokenType": "code",
                "Offers": [config.sisu_scope],
                "Query": {
                    "display": config.sisu_display,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    "state": state,
                },
            })
            resp = client.post(url, content=body, headers=proof_key.signed_headers(url, body))
            resp.raise_for_status()

        session_id = resp.headers.get("x-sessionid")
        redirect_url = resp.json()["MsaOauthRedirect"]

        # Serialize proof key for finish_auth
        priv_num = proof_key.private_key.private_numbers()
        pk_data = {
            "d": base64.urlsafe_b64encode(priv_num.private_value.to_bytes(32, "big")).rstrip(b"=").decode(),
            "x": base64.urlsafe_b64encode(priv_num.public_numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
            "y": base64.urlsafe_b64encode(priv_num.public_numbers.y.to_bytes(32, "big")).rstrip(b"=").decode(),
        }

        return AuthStartResult(
            auth_url=redirect_url,
            state=state,
            redirect_uri=config.effective_sisu_redirect,
            method=AuthMethod.SISU,
            _internal={
                "config": config.to_dict(),
                "code_verifier": code_verifier,
                "device_token": device_token,
                "session_id": session_id,
                "proof_key": pk_data,
            },
        )

    @classmethod
    def _finish_sisu(cls, code: str, auth_start: AuthStartResult) -> XboxAuthSession:
        internal = auth_start._internal
        config = _XboxClientConfig.from_dict(internal["config"])
        proof_key = cls._restore_proof_key(internal["proof_key"])

        with httpx.Client(timeout=30) as client:
            resp = client.post("https://login.live.com/oauth20_token.srf", data={
                "client_id": config.sisu_app_id,
                "code": code,
                "code_verifier": internal["code_verifier"],
                "grant_type": "authorization_code",
                "redirect_uri": config.effective_sisu_redirect,
                "scope": config.sisu_scope,
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp.raise_for_status()
            tokens = resp.json()
            msa_token = tokens["access_token"]
            refresh_token = tokens.get("refresh_token")

            sisu = cls._sisu_authorize(
                client, proof_key, msa_token,
                internal["device_token"], config, internal.get("session_id"),
            )
            user_token = sisu["UserToken"]["Token"]
            claims = sisu["AuthorizationToken"]["DisplayClaims"]["xui"][0]
            return XboxAuthSession(
                user_token=user_token,
                gamertag=claims.get("gtg"),
                xuid=claims.get("xid"),
                refresh_token=refresh_token,
                method=AuthMethod.SISU,
            )

    @classmethod
    def _refresh_sisu(cls, refresh_token: str, config: _XboxClientConfig) -> XboxAuthSession:
        proof_key = _ProofKey()
        with httpx.Client(timeout=30) as client:
            resp = client.post("https://login.live.com/oauth20_token.srf", data={
                "client_id": config.sisu_app_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": config.sisu_scope,
            }, headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp.raise_for_status()
            tokens = resp.json()
            new_rt: str = tokens.get("refresh_token", refresh_token)
            msa_token = tokens["access_token"]

            device_token = cls._get_device_token(client, proof_key, config)
            sisu = cls._sisu_authorize(client, proof_key, msa_token, device_token, config)
            user_token = sisu["UserToken"]["Token"]
            claims = sisu["AuthorizationToken"]["DisplayClaims"]["xui"][0]
            return XboxAuthSession(
                user_token=user_token,
                gamertag=claims.get("gtg"),
                xuid=claims.get("xid"),
                refresh_token=new_rt,
                method=AuthMethod.SISU,
            )

    # ============================================================
    # Shared helpers
    # ============================================================

    @classmethod
    def _build_session_from_access_token(
        cls, client: httpx.Client, access_token: str, prefix: str,
        refresh_token: Optional[str], method: AuthMethod,
        config: Optional[_XboxClientConfig] = None,
    ) -> XboxAuthSession:
        """Exchange an MSA/Azure AD access token for an Xbox user token + profile info."""
        cfg = config or _XboxClientConfig()
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
        user_token: str = resp.json()["Token"]

        # Get profile info via default XSTS
        xsts = cls._request_xsts("http://xboxlive.com", user_token, sandbox=cfg.sandbox, client=client)
        claims = xsts["DisplayClaims"]["xui"][0]

        return XboxAuthSession(
            user_token=user_token,
            gamertag=claims.get("gtg"),
            xuid=claims.get("xid"),
            refresh_token=refresh_token,
            method=method,
        )

    @classmethod
    def _get_device_token(cls, client: httpx.Client, proof_key: _ProofKey,
                          config: Optional[_XboxClientConfig] = None) -> str:
        cfg = config or _XboxClientConfig()
        url = "https://device.auth.xboxlive.com/device/authenticate"
        device_id = "{" + str(uuid.uuid4()) + "}"
        body = json.dumps({
            "Properties": {
                "AuthMethod": "ProofOfPossession", "Id": device_id,
                "DeviceType": cfg.device_type, "SerialNumber": device_id,
                "Version": cfg.device_version, "ProofKey": proof_key.get_jwk(),
            },
            "RelyingParty": "http://auth.xboxlive.com", "TokenType": "JWT",
        })
        resp = client.post(url, content=body, headers=proof_key.signed_headers(url, body))
        resp.raise_for_status()
        return resp.json()["Token"]

    @classmethod
    def _sisu_authorize(
        cls, client: httpx.Client, proof_key: _ProofKey, msa_token: str,
        device_token: str, config: Optional[_XboxClientConfig] = None,
        session_id: Optional[str] = None,
    ) -> dict:
        cfg = config or _XboxClientConfig()
        url = "https://sisu.xboxlive.com/authorize"
        body = json.dumps({
            "AccessToken": f"t={msa_token}", "AppId": cfg.sisu_app_id,
            "DeviceToken": device_token, "Sandbox": cfg.sandbox,
            "SiteName": "user.auth.xboxlive.com",
            "UseModernGamertag": True, "ProofKey": proof_key.get_jwk(),
            **({"SessionId": session_id} if session_id else {}),
        })
        resp = client.post(url, content=body, headers=proof_key.signed_headers(url, body))
        if resp.status_code != 200:
            raise RuntimeError(f"Sisu authorize failed ({resp.status_code}): {resp.text[:300]}")
        return resp.json()

    @classmethod
    def _restore_proof_key(cls, pk_data: dict) -> _ProofKey:
        """Restore a _ProofKey from serialized _internal data."""
        def _b64(s: str) -> int:
            return int.from_bytes(base64.urlsafe_b64decode(s + "==="), "big")
        pub = ec.EllipticCurvePublicNumbers(_b64(pk_data["x"]), _b64(pk_data["y"]), ec.SECP256R1())
        priv = ec.EllipticCurvePrivateNumbers(_b64(pk_data["d"]), pub)
        pk = _ProofKey.__new__(_ProofKey)
        pk.private_key = priv.private_key(default_backend())
        return pk

    @classmethod
    def _request_xsts(cls, rp: str, user_token: str, sandbox: str = "RETAIL",
                      client: Optional[httpx.Client] = None) -> dict:
        def _do(c: httpx.Client) -> dict:
            resp = c.post(
                "https://xsts.auth.xboxlive.com/xsts/authorize",
                json={
                    "Properties": {"SandboxId": sandbox, "UserTokens": [user_token]},
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

    @classmethod
    def _localhost_callback(cls, port: int) -> str:
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

        server = HTTPServer(("localhost", port), Handler)
        server.timeout = 120
        while code is None:
            server.handle_request()
        server.server_close()
        return code

    @classmethod
    def _save_tokens(cls, token_file: Path, session: XboxAuthSession) -> None:
        if session.refresh_token:
            key = "sisu_refresh_token" if session.method == AuthMethod.SISU else "refresh_token"
            token_file.write_text(json.dumps({key: session.refresh_token}, indent=2))
