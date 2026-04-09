# pyXboxAuth

A lightweight, stateless Python client for Xbox Live authentication. Generates XBL3.0 tokens for any relying party — no official Xbox SDK or third-party Xbox libraries needed.

Built on `httpx` and `cryptography` only. All methods are stateless class methods — no instance state, safe for concurrent multi-user backends.

In order to create your own Microsoft App to enable your own auth flow, please refer to [this documentation](/make_your_own_client.md) for steps.

## Features

- **Stateless**: All auth state flows in/out via serializable dataclasses — safe for multi-user backends
- **Multi-stage API**: Decoupled from browser/UI — integrate into Flask, FastAPI, or any backend
- **Interactive helper**: One-line auth with browser + auto-capture for CLI tools
- **Three auth methods**: Standard OAuth (localhost callback), Sisu/XAL (Xbox Android app flow), and Device Code (RFC 8628 — code on screen, sign in from any device)
- **Token refresh**: Reuse refresh tokens across sessions without re-login
- **Any relying party**: Request XSTS tokens for any Xbox partner service
- **Serializable sessions**: `XboxAuthSession.to_dict()` / `.from_dict()` for database storage

## Setup

```bash
pip install httpx cryptography
```

Python 3.9+

## Quick Start

### Interactive (CLI)

```python
from xbox_client import XboxAuth

session = XboxAuth.authenticate_interactive()  # opens browser, handles callback
header = XboxAuth.get_xbl3_header(session, "rp://api.minecraftservices.com/")

print(header)           # XBL3.0 x=<userhash>;<token>
print(session.gamertag)  # e.g. "thethiny"
```

### With token caching

```python
from pathlib import Path
from xbox_client import XboxAuth

session = XboxAuth.authenticate_interactive(token_file=Path("tokens.json"))
# First run: browser login
# Subsequent runs: auto-refresh, no login

header = XboxAuth.get_xbl3_header(session, "rp://api.minecraftservices.com/")
```

## Auth Methods

### Standard OAuth (default)

Uses the OpenXbox Azure AD app with a localhost callback. The browser opens, the user logs in, and the callback is captured automatically.

```python
session = XboxAuth.authenticate_interactive()  # defaults to Standard
```

### Sisu/XAL

Uses the Xbox Android app's Sisu authentication flow with EC P-256 request signing. The user pastes the redirect URL after login.

```python
from xbox_client import XboxAuth, AuthMethod

session = XboxAuth.authenticate_interactive(method=AuthMethod.SISU)
```

### Device Code (RFC 8628)

The user sees a short code and a URL (`microsoft.com/link`), signs in on any device (phone, another PC, etc.), and the backend polls for completion. No browser redirect or callback needed — ideal for headless servers, TV apps, and web backends where the user authenticates on a separate device.

```python
from xbox_client import XboxAuth

# Start — get the code to show the user
state = XboxAuth.start_device_code(client_id="your-client-id")
print(f"Go to {state.verification_uri} and enter: {state.user_code}")

# Blocking wait (polls automatically)
session = XboxAuth.await_device_code(
    state.device_code, state.client_id,
    state.expires_in, state.interval,
)
header = XboxAuth.get_xbl3_header(session, "rp://api.minecraftservices.com/")
```

Or poll manually for non-blocking usage:

```python
import time

state = XboxAuth.start_device_code(client_id="your-client-id")
# Show state.user_code + state.verification_uri to user

while True:
    result = XboxAuth.poll_device_code(state.device_code, state.client_id)
    if result["status"] == "ok":
        session = result["session"]
        break
    elif result["status"] == "pending":
        time.sleep(state.interval)
    else:
        raise Exception(result["error"])

header = XboxAuth.get_xbl3_header(session, "rp://api.minecraftservices.com/")
```

## Multi-Stage Flow (Backend Integration)

The auth flow is split into stateless stages. All state is carried in serializable objects.

### Stage 1: Start auth — get the URL

```python
auth_start = XboxAuth.start_auth(redirect_uri="https://myapp.com/callback")
# auth_start.auth_url    → send user here
# auth_start.state       → store in session for CSRF / lookup
# auth_start._internal   → store in session, needed for stage 2
```

### Stage 2: User returns with code — complete auth

```python
session = XboxAuth.finish_auth(authorization_code, auth_start)
# session.user_token     → Xbox user token
# session.gamertag       → "thethiny"
# session.xuid           → "2533274903962178"
# session.refresh_token  → save for later
# session.to_dict()      → serialize for DB storage
```

### Stage 3: Get XBL3.0 header

```python
header = XboxAuth.get_xbl3_header(session, "rp://api.minecraftservices.com/")
```

### Token refresh (no user interaction)

```python
new_session = XboxAuth.refresh(stored_refresh_token)
# save new_session.refresh_token for next time
header = XboxAuth.get_xbl3_header(new_session, "rp://api.minecraftservices.com/")
```

### Session serialization

```python
# Save
data = session.to_dict()  # plain dict, JSON-serializable
db.save(user_id, data)

# Restore
data = db.load(user_id)
session = XboxAuthSession.from_dict(data)
```

### Flask Example

```python
from flask import Flask, redirect, request, session, jsonify
from xbox_client import XboxAuth, XboxAuthSession, AuthStartResult, AuthMethod

app = Flask(__name__)
app.secret_key = "your-secret-key"

RELYING_PARTY = "rp://api.minecraftservices.com/"

@app.get("/login")
def login():
    auth_start = XboxAuth.start_auth(
        redirect_uri=request.url_root.rstrip("/") + "/callback"
    )
    # Store flow state in session (all fields are JSON-serializable)
    session["auth_state"] = auth_start.state
    session["auth_redirect_uri"] = auth_start.redirect_uri
    session["auth_method"] = auth_start.method.value
    session["auth_internal"] = auth_start._internal
    return redirect(auth_start.auth_url)

@app.get("/callback")
def callback():
    code = request.args["code"]

    # Rebuild auth_start from session
    auth_start = AuthStartResult(
        auth_url="",
        state=session.pop("auth_state"),
        redirect_uri=session.pop("auth_redirect_uri"),
        method=AuthMethod(session.pop("auth_method")),
        _internal=session.pop("auth_internal"),
    )

    xbox_session = XboxAuth.finish_auth(code, auth_start)

    # Store session for later use
    session["xbox"] = xbox_session.to_dict()

    return jsonify({
        "gamertag": xbox_session.gamertag,
        "xuid": xbox_session.xuid,
    })

@app.get("/token")
def get_token():
    xbox_session = XboxAuthSession.from_dict(session["xbox"])
    header = XboxAuth.get_xbl3_header(xbox_session, RELYING_PARTY)
    return jsonify({"authorization": header})

@app.get("/refresh")
def refresh_route():
    xbox_data = session.get("xbox")
    if not xbox_data:
        return redirect("/login")

    old_session = XboxAuthSession.from_dict(xbox_data)
    if not old_session.refresh_token:
        return redirect("/login")

    try:
        new_session = XboxAuth.refresh(old_session.refresh_token)
        session["xbox"] = new_session.to_dict()
        header = XboxAuth.get_xbl3_header(new_session, RELYING_PARTY)
        return jsonify({"gamertag": new_session.gamertag, "authorization": header})
    except Exception:
        return redirect("/login")
```

### Flask Example (Device Code)

```python
from flask import Flask, jsonify, request
from xbox_client import XboxAuth
import uuid

app = Flask(__name__)
sessions = {}

RELYING_PARTY = "rp://api.minecraftservices.com/"

@app.post("/xbox/device/start")
def device_start():
    state = XboxAuth.start_device_code(client_id="your-client-id")
    sid = str(uuid.uuid4())
    sessions[sid] = {
        "device_code": state.device_code,
        "client_id": state.client_id,
    }
    return jsonify(
        session_id=sid,
        user_code=state.user_code,
        verification_uri=state.verification_uri,
        interval=state.interval,
        expires_in=state.expires_in,
    )

@app.post("/xbox/device/poll")
def device_poll():
    data = request.get_json()
    session = sessions.get(data["session_id"])
    if not session:
        return jsonify(status="error", error="Invalid session"), 400

    result = XboxAuth.poll_device_code(session["device_code"], session["client_id"])

    if result["status"] == "ok":
        sessions.pop(data["session_id"], None)
        header = XboxAuth.get_xbl3_header(result["session"], RELYING_PARTY)
        return jsonify(status="ok", token=header, gamertag=result["session"].gamertag)

    return jsonify(result)
```

## Configuration

All config parameters are keyword-only (after `*`) with sensible defaults. Pass only what you need to override — unspecified values use the built-in defaults.

```python
XboxAuth.start_auth(
    method=AuthMethod.STANDARD,         # or AuthMethod.SISU
    redirect_uri="https://...",         # custom callback URL (Standard only)
    port=8080,                          # localhost port if no redirect_uri (Standard only)
    *,
    client_id="...",                    # Azure AD client ID
    scopes="...",                       # OAuth scopes
    sisu_app_id="...",                  # Sisu/XAL application ID
    sisu_redirect_uri="...",            # Sisu redirect URI
    title_id="...",                     # Xbox title ID (Sisu only)
    device_type="Win32",                # Device type for device token (Sisu only)
    device_version="10.0",              # OS version for device token (Sisu only)
    sandbox="RETAIL",                   # Xbox sandbox ID
    sisu_display="android_phone",       # Display mode for Sisu auth
    sisu_scope="...",                   # OAuth scope for Sisu flow
)

XboxAuth.authenticate_interactive(
    method=AuthMethod.STANDARD,
    port=8080,
    *,
    client_id="...",                    # same config kwargs as start_auth
    token_file=Path("tokens.json"),     # None to disable caching
)

XboxAuth.start_device_code(
    client_id="...",                    # required — must be a public client with device code enabled
    *,
    scopes="...",                       # OAuth scopes (optional override)
)
```

## API Reference

### `XboxAuth` (class methods)

| Method | Description |
|--------|-------------|
| `start_auth(method, redirect_uri, port, *, client_id, scopes, ...)` | Stage 1: returns `AuthStartResult` with the auth URL |
| `finish_auth(code, auth_start)` | Stage 2: returns `XboxAuthSession` (config read from `auth_start`) |
| `refresh(refresh_token, method, port, *, client_id, scopes, ...)` | Refresh without user interaction, returns `XboxAuthSession` |
| `authenticate_interactive(method, port, *, client_id, ..., token_file)` | Convenience: full auth with browser, returns `XboxAuthSession` |
| `start_device_code(client_id, *, scopes)` | Start device code flow, returns `DeviceCodeState` |
| `poll_device_code(device_code, client_id, *, sandbox)` | Single non-blocking poll, returns status dict with `XboxAuthSession` on success |
| `await_device_code(device_code, client_id, expires_in, interval, *, sandbox)` | Blocking poll until approved, returns `XboxAuthSession` |
| `get_xbl3_header(session, relying_party, *, sandbox)` | Returns `XBL3.0 x=<uhs>;<token>` header string |
| `get_xsts_token(session, relying_party, *, sandbox)` | Returns raw XSTS response dict |

### `XboxAuthSession`

Authenticated session state. Serializable for storage.

| Field | Type | Description |
|-------|------|-------------|
| `user_token` | `str` | Xbox user token |
| `gamertag` | `str \| None` | Xbox gamertag |
| `xuid` | `str \| None` | Xbox User ID |
| `refresh_token` | `str \| None` | OAuth refresh token (save for later) |
| `method` | `AuthMethod` | Which auth method was used |

| Method | Description |
|--------|-------------|
| `to_dict()` | Serialize to a plain dict |
| `from_dict(data)` | Deserialize from a dict |

### `AuthStartResult`

Returned by `start_auth()`. Pass to `finish_auth()`.

| Field | Type | Description |
|-------|------|-------------|
| `auth_url` | `str` | URL to redirect the user to |
| `state` | `str` | CSRF state parameter (use as session key) |
| `redirect_uri` | `str` | Where the user will be redirected after login |
| `method` | `AuthMethod` | Which auth method is being used |
| `_internal` | `dict` | Internal flow state (store in session, pass back to `finish_auth`) |

### `DeviceCodeState`

Returned by `start_device_code()`. Show `user_code` and `verification_uri` to the user, use `device_code` and `client_id` for polling.

| Field | Type | Description |
|-------|------|-------------|
| `device_code` | `str` | Opaque code for polling (don't show to user) |
| `user_code` | `str` | Short code for the user to type (e.g. "B6N9D34T") |
| `verification_uri` | `str` | URL the user visits (`https://www.microsoft.com/link`) |
| `expires_in` | `int` | Seconds until the code expires |
| `interval` | `int` | Minimum seconds between poll attempts |
| `message` | `str` | Human-readable instruction from Microsoft |
| `client_id` | `str` | Client ID used (pass back to poll/await) |
