# pyXboxAuth

A lightweight, stateless Python client for Xbox Live authentication. Generates XBL3.0 tokens for any relying party — no official Xbox SDK or third-party Xbox libraries needed.

Built on `httpx` and `cryptography` only. All methods are stateless class methods — no instance state, safe for concurrent multi-user backends.

In order to create your own Microsoft App to enable your own auth flow, please refer to [this documentation](/make_your_own_client.md) for steps.

## Features

- **Stateless**: All auth state flows in/out via serializable dataclasses — safe for multi-user backends
- **Multi-stage API**: Decoupled from browser/UI — integrate into Flask, FastAPI, or any backend
- **Interactive helper**: One-line auth with browser + auto-capture for CLI tools
- **Two auth methods**: Standard OAuth (localhost callback) and Sisu/XAL (Xbox Android app flow)
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

## Configuration

```python
XboxAuth.start_auth(
    method=AuthMethod.STANDARD,     # or AuthMethod.SISU
    redirect_uri="https://...",     # custom callback URL (Standard only)
    client_id="...",                # override Azure AD client ID (Standard only)
    port=8080,                      # localhost port if no redirect_uri (Standard only)
)

XboxAuth.authenticate_interactive(
    method=AuthMethod.STANDARD,
    port=8080,
    token_file=Path("tokens.json"),  # None to disable caching
)
```

## API Reference

### `XboxAuth` (class methods)

| Method | Description |
|--------|-------------|
| `start_auth(method, redirect_uri, client_id, port)` | Stage 1: returns `AuthStartResult` with the auth URL |
| `finish_auth(code, auth_start)` | Stage 2: returns `XboxAuthSession` |
| `refresh(refresh_token, method, client_id, port)` | Refresh without user interaction, returns `XboxAuthSession` |
| `authenticate_interactive(method, port, token_file)` | Convenience: full auth with browser, returns `XboxAuthSession` |
| `get_xbl3_header(session, relying_party)` | Returns `XBL3.0 x=<uhs>;<token>` header string |
| `get_xsts_token(session, relying_party)` | Returns raw XSTS response dict |

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
