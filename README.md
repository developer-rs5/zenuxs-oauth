# 🔐 Zenuxs OAuth – Lightweight OAuth 2.0 + PKCE Client (Updated for v1.0.8)

A lightweight OAuth 2.0 + PKCE client for integrating **Zenuxs Accounts** into browser apps and SPAs.

Supports:
- OAuth 2.0 Authorization Code + PKCE  
- Redirect Login  
- Popup Login  
- Auto Token Refresh  
- Built-in Callback Handler (v1.0.8)  
- Token Storage  
- Event Emitters  

---

# 🚀 Load the Library

```html
<script src="https://unpkg.com/zenuxs-oauth@1.0.8/dist/zenux-oauth.min.js"></script>
```

---

# 🧩 Create ZenuxOAuth Instance

```js
const oauth = new ZenuxOAuth({
    clientId: "YOUR_CLIENT_ID",
    authServer: "https://api.auth.zenuxs.in",
    redirectUri: "https://your-app.com/callback.html",
    scopes: "openid profile email",
    storage: "sessionStorage",
    autoRefresh: true,
    debug: true
});
```

### Package handles:
- PKCE generation  
- OAuth URL building  
- Token (access + refresh) storage  
- Auto token refreshing  
- State + security validation  
- Debug logs  

---

# 🔐 1. Login (Redirect)

```js
oauth.login();
```

---

# 🪟 2. Login (Popup Flow)

```js
const tokens = await oauth.login({ popup: true });
```

Popup flow:
- Opens Zenuxs login in popup  
- Waits for auth code  
- Exchanges tokens  
- Returns tokens immediately  
- No page reload  

---

# 🧲 3. OAuth Callback Handler (NEW in v1.0.8)

Add **callback.html**:

```html
<script src="https://unpkg.com/zenuxs-oauth@1.0.8/dist/zenux-oauth.min.js"></script>
<script>
    if (window.zenuxOAuthCallback) {
        console.log("Callback auto-initialized");
    } else {
        window.zenuxOAuthCallback = new ZenuxOAuthCallbackHandler({
            debug: true,
            autoClose: true,
            autoCloseDelay: 1000,
            homeUrl: "/home.html",
            storagePrefix: "zenux_oauth_",
            successMessage: "Authentication successful! Redirecting...",
            errorMessage: "Authentication failed."
        });
    }
</script>
```

Auto-handles when:
- URL contains `code=`  
- OR file contains `callback`  

---

# 👤 4. Get User Info

```js
const user = await oauth.getUserInfo();
```

---

# 🔓 5. Check Authentication

```js
oauth.isAuthenticated();
```

---

# 📦 6. Read Session State

```js
oauth.getSessionState();
```

---

# 🔁 7. Refresh Token

### Manual:
```js
await oauth.refreshTokens();
```

### Automatic:
```js
autoRefresh: true
```

Events fired:
- `tokenRefresh`

---

# 🚪 8. Logout

```js
await oauth.logout({ revokeTokens: false });
```

---

# 📡 9. Event Listeners

```js
oauth.on("error", err => {});
oauth.on("tokenRefresh", tokens => {});
oauth.on("stateChange", state => {});
```

---

# 🧪 Full Working Example (Updated for v1.0.8)

## callback.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Callback</title>
</head>
<body>
    <div id="zenux-oauth-callback-container"></div>

    <script src="https://unpkg.com/zenuxs-oauth@1.0.8/dist/zenux-oauth.min.js"></script>
    <script>
        if (window.zenuxOAuthCallback) {
            console.log("Callback handler initialized automatically");
        } else {
            window.zenuxOAuthCallback = new ZenuxOAuthCallbackHandler({
                debug: true,
                autoClose: true,
                autoCloseDelay: 1000,
                homeUrl: "/test.html",
                storagePrefix: "zenux_oauth_",
                successMessage: "Authentication successful! Redirecting...",
                errorMessage: "Authentication failed. Please try again."
            });
        }
    </script>
</body>
</html>
```

---

## test.html (Test UI)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZenuxOAuth Test</title>
</head>
<body>
    <h1>ZenuxOAuth Test</h1>

    <h2>Initialize</h2>
    <input type="text" id="clientId" placeholder="Client ID" value="5fa601a20c69ab01"><br>
    <input type="text" id="authServer" placeholder="Auth Server" value="https://api.auth.zenuxs.in"><br>
    <button onclick="init()">Initialize</button>

    <hr>

    <h2>Login</h2>
    <button onclick="login()">Login (Redirect)</button>
    <button onclick="loginPopup()">Login (Popup)</button>

    <hr>

    <h2>Tokens</h2>
    <button onclick="getTokens()">Get Tokens</button>
    <button onclick="refreshTokens()">Refresh Tokens</button>

    <hr>

    <h2>User</h2>
    <button onclick="getUserInfo()">Get User Info</button>

    <hr>

    <h2>Logout</h2>
    <button onclick="logout()">Logout</button>

    <hr>

    <h2>Output</h2>
    <pre id="output"></pre>

    <script src="https://unpkg.com/zenuxs-oauth@1.0.8/dist/zenux-oauth.min.js"></script>
    <script>
        let oauth = null;

        function log(msg, data) {
            document.getElementById('output').textContent =
                msg + (data ? '\n' + JSON.stringify(data, null, 2) : '');
        }

        function init() {
            oauth = new ZenuxOAuth({
                clientId: document.getElementById('clientId').value,
                authServer: document.getElementById('authServer').value,
                redirectUri: window.location.origin + '/callback.html',
                debug: true
            });
            log('Initialized');
        }

        function login() {
            oauth.login();
        }

        async function loginPopup() {
            try {
                const tokens = await oauth.login({ popup: true });
                log('Login success', tokens);
            } catch (e) {
                log('Error: ' + e.message);
            }
        }

        function getTokens() {
            log('Tokens', oauth.getTokens());
        }

        async function refreshTokens() {
            try {
                const tokens = await oauth.refreshTokens();
                log('Refreshed', tokens);
            } catch (e) {
                log('Error: ' + e.message);
            }
        }

        async function getUserInfo() {
            try {
                const info = await oauth.getUserInfo();
                log('User Info', info);
            } catch (e) {
                log('Error: ' + e.message);
            }
        }

        async function logout() {
            await oauth.logout();
            log('Logged out');
        }
    </script>
</body>
</html>
```

---

# 🧠 Summary

| Feature | Supported |
|--------|-----------|
| PKCE | ✅ |
| Redirect Login | ✅ |
| Popup Login | ✅ |
| Auto Token Refresh | ✅ |
| Callback Handler | ✅ |
| Token Storage | ✅ |
| User Info | ✅ |
| Event Emitters | ✅ |
| State Validation | ✅ |
| Logout | ✅ |

---

MIT © Zenuxs Team
