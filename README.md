# pyXboxAuth

A lightweight Python client for Xbox Live authentication. Generates XBL3.0 tokens for any relying party — no official Xbox SDK or third-party Xbox libraries needed.

Built on `httpx` and `cryptography` only.

## Features

- **Two auth methods**: Standard OAuth (localhost callback) and Sisu/XAL (Xbox Android app flow)
- **Multi-stage API**: Decoupled from browser/UI — integrate into Flask, FastAPI, or any backend
- **Interactive helper**: One-line auth with browser + auto-capture for CLI tools
- **Token refresh**: Reuse refresh tokens across sessions without re-login
- **Any relying party**: Request XSTS tokens for any Xbox partner service

## Setup

```bash
pip install httpx cryptography
```

Python 3.9+

## Quick Start

### Interactive (CLI)

```python
import asyncio
from xbox_client import XboxAuthClient

async def main():
    client = XboxAuthClient()
    await client.authenticate_interactive()  # opens browser, handles callback

    header = await client.get_xbl3_header("rp://api.minecraftservices.com/ ")
    print(header)  # XBL3.0 x=<userhash>;<token>
    print(client.gamertag)  # e.g. "thethiny"

asyncio.run(main())
```

### With token caching

```python
from pathlib import Path
from xbox_client import XboxAuthClient

client = XboxAuthClient(token_file=Path("tokens.json"))
await client.authenticate_interactive()  # first run: browser login
                                          # subsequent runs: auto-refresh, no login

header = await client.get_xbl3_header("rp://api.minecraftservices.com/ ")
```

## Auth Methods

### Standard OAuth (default)

Uses the OpenXbox Azure AD app with a localhost callback. The browser opens, the user logs in, and the callback is captured automatically.

```python
client = XboxAuthClient()  # defaults to AuthMethod.STANDARD
```

**Pros**: Simplest flow, auto-captured callback, no URL pasting.
**Cons**: Requires a free localhost port.

### Sisu/XAL

Uses the Xbox Android app's Sisu authentication flow with EC P-256 request signing. The user pastes the redirect URL after login.

```python
from xbox_client import XboxAuthClient, AuthMethod

client = XboxAuthClient(method=AuthMethod.SISU)
```

**Pros**: Doesn't need localhost, works in restricted environments.
**Cons**: User must manually paste the redirect URL (interactive), or the redirect goes to a `ms-xal-*://` custom scheme (non-interactive).

## Non-Interactive / Backend Integration

The auth flow is split into two stages so you can integrate it into any web framework.

### Stage 1: Get the auth URL

```python
auth_start = await client.start_auth(redirect_uri="https://myapp.com/callback")
# auth_start.auth_url   → send user here
# auth_start.state      → store in session for CSRF validation
# auth_start object     → store in session, needed for stage 2
```

### Stage 2: Complete auth with the callback code

```python
await client.finish_auth(authorization_code, auth_start)
# client is now authenticated
header = await client.get_xbl3_header("rp://api.minecraftservices.com/ ")
```

### Token refresh (no user interaction)

```python
new_refresh_token = await client.refresh(stored_refresh_token)
# save new_refresh_token for next time
header = await client.get_xbl3_header("rp://api.minecraftservices.com/ ")
```

### Flask Example

```python
from flask import Flask, redirect, request, session, jsonify
from xbox_client import XboxAuthClient
import asyncio

app = Flask(__name__)
app.secret_key = "your-secret-key"

RELYINGPARTY = "rp://api.minecraftservices.com/ "

def run_async(coro):
    return asyncio.run(coro)

@app.get("/login")
def login():
    client = XboxAuthClient()
    auth_start = run_async(client.start_auth(
        redirect_uri=request.url_root.rstrip("/") + "/callback"
    ))
    # Store flow state in session
    session["auth_state"] = auth_start.state
    session["auth_redirect_uri"] = auth_start.redirect_uri
    session["auth_internal"] = auth_start._internal
    return redirect(auth_start.auth_url)

@app.get("/callback")
def callback():
    from xbox_client import AuthStartResult

    code = request.args["code"]

    # Rebuild auth_start from session
    auth_start = AuthStartResult(
        auth_url="",  # not needed for finish
        state=session.pop("auth_state"),
        redirect_uri=session.pop("auth_redirect_uri"),
        _internal=session.pop("auth_internal"),
    )

    client = XboxAuthClient()
    run_async(client.finish_auth(code, auth_start))

    header = run_async(client.get_xbl3_header(RELYINGPARTY))

    # Save refresh token for later
    refresh_token = auth_start._internal.get("refresh_token")
    if refresh_token:
        session["xbox_refresh_token"] = refresh_token

    return jsonify({
        "gamertag": client.gamertag,
        "xuid": client.xuid,
        "auth_header": header,
    })

@app.get("/refresh")
def refresh_route():
    rt = session.get("xbox_refresh_token")
    if not rt:
        return redirect("/login")

    client = XboxAuthClient()
    try:
        new_rt = run_async(client.refresh(rt))
        session["xbox_refresh_token"] = new_rt
        header = run_async(client.get_xbl3_header(RELYINGPARTY))
        return jsonify({
            "gamertag": client.gamertag,
            "auth_header": header,
        })
    except Exception:
        return redirect("/login")
```

## Configuration

```python
XboxAuthClient(
    method=AuthMethod.STANDARD,  # or AuthMethod.SISU
    token_file=Path("tokens.json"),  # None to disable caching
    port=8080,  # localhost port for Standard OAuth callback
    client_id="...",  # override the default Azure AD client ID
)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `method` | `STANDARD` | Auth method: `AuthMethod.STANDARD` or `AuthMethod.SISU` |
| `token_file` | `None` | Path to cache refresh tokens. `None` = no persistence. |
| `port` | `8080` | Localhost port for the OAuth callback (Standard only) |
| `client_id` | OpenXbox app | Override the Azure AD client ID (Standard only) |

## API Reference

### `XboxAuthClient`

| Method | Description |
|--------|-------------|
| `start_auth(redirect_uri?)` | Stage 1: returns `AuthStartResult` with the auth URL |
| `finish_auth(code, auth_start)` | Stage 2: completes auth with the authorization code |
| `refresh(refresh_token)` | Refresh auth without user interaction. Returns new refresh token. |
| `authenticate_interactive()` | Convenience: full auth with browser + callback/paste |
| `get_xbl3_header(relying_party)` | Returns `XBL3.0 x=<uhs>;<token>` header string |
| `get_xsts_token(relying_party)` | Returns raw XSTS response dict |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `gamertag` | `str \| None` | Xbox gamertag after auth |
| `xuid` | `str \| None` | Xbox User ID after auth |
| `is_authenticated` | `bool` | Whether auth has completed |

### `AuthStartResult`

Returned by `start_auth()`. Pass it back to `finish_auth()`.

| Field | Type | Description |
|-------|------|-------------|
| `auth_url` | `str` | URL to redirect the user to |
| `state` | `str` | CSRF state parameter |
| `redirect_uri` | `str` | Where the user will be redirected after login |
