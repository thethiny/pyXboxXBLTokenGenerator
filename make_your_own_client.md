# Creating Your Own Microsoft Azure App for Xbox Authentication

This guide walks you through registering an Azure AD application that supports both **OAuth redirect login** (popup/callback) and **Device Code login** (code on screen, sign in from any device) for Xbox Live.

## Step 1: Register the App

1. Go to [Azure Portal - App Registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click **New registration**
3. Fill in:
   - **Name**: Whatever you want (e.g. "My Xbox App")
   - **Supported account types**: **Personal Microsoft accounts only** (Xbox Live requires personal accounts)
   - **Redirect URI**: Leave blank for now
4. Click **Register**
5. Copy the **Application (client) ID** from the Overview page — this is your `client_id`

## Step 2: Enable Device Code Flow

### Old Flow
1. In the left sidebar, click **Authentication**
2. Under **Advanced settings**, set **Allow public client flows** to **Yes**
3. Click **Save**

### New Flow
1. In the left sidebar, click **Authentication (Preview)**
2. Go to **Settings**, enable **Allow public client flows**.
3. Click **Save**

This enables the OAuth 2.0 Device Authorization Grant (RFC 8628), which allows users to authenticate by entering a code at `microsoft.com/link`.

## Step 3: Add Redirect URI (for OAuth Popup Flow)

Still on the **Authentication** page:

### Old Flow
1. Click **Add a platform**
2. Choose **Mobile and desktop applications**
3. Under **Custom redirect URIs**, add: `http://localhost` (or your own callback, don't enter any port info)
4. Click **Configure**

### New Flow
1. Click on **Redirect URI configuration**
2. Click on **Add Redirect URI**
3. Select **Mobile and desktop applications**
4. In the custom box at the end of the list enter: `http://localhost` (or your own callback, don't enter any port info)

Using `http://localhost` with the Mobile/Desktop platform type is a special case defined in RFC 8252 — Microsoft treats it as a wildcard that matches any port, but not any path (e.g. `http://localhost:8080`, `http://localhost:5000`, etc.). This means your app will work regardless of what port your local server runs on as long as the resource matches.

## Step 4: Add Xbox Live Permissions (Old Flow only)

1. In the left sidebar, click **API permissions**
2. Click **Add a permission**
3. Select **Microsoft APIs** tab
4. Scroll down and select **Xbox Live**
5. Check:
   - `XboxLive.signin`
   - `XboxLive.offline_access`
6. Click **Add permissions**

No admin consent is needed for personal Microsoft accounts.

## Done

Your app now supports:

- **OAuth redirect flow**: User clicks a button, signs in via Microsoft popup, callback captures the code. Uses the `http://localhost` redirect URI.
- **Device code flow**: Backend requests a device code, user visits `microsoft.com/link` and types the code. No redirect URI needed.

Both flows produce a Microsoft access token with Xbox Live scopes, which can be exchanged for Xbox user tokens and XSTS tokens.

## Usage

Pass the client ID in your code. The code differentiates between _Standard Client ID_ and _Device Code Client ID_ in case you want to use different apps, but one can be used for both given the right permissions.

```python
# OAuth flow
auth_start = XboxAuth.start_auth(client_id="your-client-id-here")

# Device code flow
state = XboxAuth.start_device_code(client_id="your-client-id-here")
```

## FAQ

**Does this cost money?**
No. Azure AD app registrations are completely free. No subscription, no credit card, no per-request charges.

**How many apps can I register?**
Up to 250 per personal Microsoft account.

**Why can't I use the same client ID for both flows?**
You can! That's the whole point of this guide. A single app registration with "Allow public client flows" enabled and a `http://localhost` redirect URI supports both OAuth redirect and device code flows.

**Why "Personal Microsoft accounts only"?**
Xbox Live only works with personal Microsoft accounts (the ones ending in @outlook.com, @hotmail.com, etc. or linked to a gamertag). Azure AD / work accounts don't have Xbox Live access.

**Why "Mobile and desktop" and not "Web" for the redirect URI?**
The "Mobile and desktop" platform with `http://localhost` gives you the RFC 8252 wildcard behavior — any port, any path. The "Web" platform requires an exact URI match, so you'd need to register every possible port.

**The first login shows a consent prompt — is that normal?**
Yes. The first time a user signs in with your app, Microsoft asks them to consent to the Xbox Live permissions. After that, it's remembered and won't prompt again. The OAuth redirect flow may fail on this first consent — just retry and it works.
_Note: The first time a user consents you might receive an error 400, this will not happen on the 2nd run_

**What is the polling rate recommended and how long does the user have to consent?**
The deadline and polling rate will be returned to you in the request itself by Microsoft. As of now, Microsoft recommends 5 seconds per poll for allows the user 900s (15m) to sign in.
