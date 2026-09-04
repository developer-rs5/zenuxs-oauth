# Zenuxs OAuth

Universal OAuth 2.0 + PKCE client for Zenuxs auth.

It works in browsers, Node.js, React, Next.js, React Native, and hybrid apps with one small API:

```js
const oauth = new ZenuxOAuth({ clientId: 'your-client-id' });
```

Everything else is optional.

## Highlights

- Minimal setup: only `clientId` is required
- Auto-detects `fetch` in browser and modern Node runtimes
- Auto-detects a usable storage adapter
- Frontend modes: `ui`, `popup`, `redirect`, `manual`
- `redirect` is the default mode in browsers
- `redirect` is the default mode on the backend
- Embedded UI supports `light`, `dark`, and `auto` themes
- Social providers can fall back from embedded mode to popup or full page
- Same-page callback handling works automatically
- Manual flow is still available when you want full control
- Built-in token refresh, user info, logout, and authenticated fetch
- **`<zenuxs-auth>` custom element** for tag-based auth UI (works in plain HTML, React, Next.js, and any framework)

## Installation

```bash
npm install zenuxs-oauth
```

Browser CDN:

```html
<script src="https://unpkg.com/zenuxs-oauth@7/dist/zenux-oauth.min.js"></script>
```

## Quick Start

### `<zenuxs-auth>` Tag (Recommended)

The simplest way to add authentication. Drop the tag anywhere in your HTML — it renders a persistent, inline login UI:

```html
<script src="https://unpkg.com/zenuxs-oauth@7/dist/zenux-oauth.min.js"></script>

<zenuxs-auth
  client-id="your-client-id"
  redirect-uri="https://your-app.com/callback"
  scope="openid profile email"
  theme="dark"
  height="540px"
></zenuxs-auth>

<script>
  document.querySelector('zenuxs-auth').addEventListener('success', (e) => {
    console.log('Logged in!', e.detail);
  });
</script>
```

#### Tag Attributes

| Attribute | Default | Description |
| --- | --- | --- |
| `client-id` | (required) | OAuth client ID |
| `redirect-uri` | current page | OAuth redirect URI |
| `scope` | `openid profile email` | Requested scopes |
| `auth-server` | `https://api.auth.zenuxs.in` | Auth server URL |
| `theme` | `auto` | `auto`, `light`, or `dark` |
| `height` | `540px` | Height of the auth UI |
| `width` | `100%` | Width of the auth UI |
| `redirect-url` | `/` | Where to navigate after auth success |
| `redirect-delay` | `1` | Seconds to wait before redirect (default 1s) |
| `auto-redirect` | `true` | Auto redirect after success (default: true, set `false` to disable) |

#### Tag Events

| Event | Detail | Description |
| --- | --- | --- |
| `success` | `{ access_token, id_token, ... }` | Fired on successful authentication |
| `error` | `{ message, code, ... }` | Fired on authentication error |
| `redirect` | `{ targetUrl, delay, result }` | Fired before auto-redirect |

> **Note:** `<zenux-auth>` still works as a backward-compatible alias for `<zenuxs-auth>`.

---

### React

```jsx
import 'zenuxs-oauth'; // registers <zenuxs-auth> custom element

function LoginPage() {
  const authRef = React.useRef(null);

  React.useEffect(() => {
    const el = authRef.current;
    if (!el) return;

    const onSuccess = (e) => {
      console.log('Authenticated!', e.detail);
      // e.detail has access_token, id_token, etc.
    };

    const onError = (e) => {
      console.error('Auth error:', e.detail);
    };

    el.addEventListener('success', onSuccess);
    el.addEventListener('error', onError);
    return () => {
      el.removeEventListener('success', onSuccess);
      el.removeEventListener('error', onError);
    };
  }, []);

  return (
    <zenuxs-auth
      ref={authRef}
      client-id="your-client-id"
      redirect-uri="http://localhost:3000/callback"
      scope="openid profile email"
      theme="dark"
      height="540px"
    />
  );
}
```

### Next.js (App Router)

```jsx
'use client';
import { useEffect, useRef } from 'react';

export default function LoginPage() {
  const authRef = useRef(null);

  useEffect(() => {
    // Dynamic import so the custom element only registers in the browser
    import('zenuxs-oauth');

    const el = authRef.current;
    if (!el) return;

    const onSuccess = (e) => {
      console.log('Authenticated!', e.detail);
    };

    el.addEventListener('success', onSuccess);
    return () => el.removeEventListener('success', onSuccess);
  }, []);

  return (
    <zenuxs-auth
      ref={authRef}
      client-id="your-client-id"
      redirect-uri="http://localhost:3000/callback"
      scope="openid profile email"
      theme="dark"
      height="540px"
    />
  );
}
```

### Next.js (Pages Router)

```jsx
import dynamic from 'next/dynamic';
import { useEffect, useRef } from 'react';

// Prevent SSR of the auth component
function ZenuxsLogin() {
  const authRef = useRef(null);

  useEffect(() => {
    require('zenuxs-oauth');

    const el = authRef.current;
    if (!el) return;

    const onSuccess = (e) => {
      console.log('Authenticated!', e.detail);
    };

    el.addEventListener('success', onSuccess);
    return () => el.removeEventListener('success', onSuccess);
  }, []);

  return (
    <zenuxs-auth
      ref={authRef}
      client-id="your-client-id"
      redirect-uri="http://localhost:3000/callback"
      scope="openid profile email"
      theme="dark"
      height="540px"
    />
  );
}

export default dynamic(() => Promise.resolve(ZenuxsLogin), { ssr: false });
```

---

### Browser, JavaScript API (Default UI mode)

```html
<button id="login">Continue with Zenuxs</button>

<script src="https://unpkg.com/zenuxs-oauth@7/dist/zenux-oauth.min.js"></script>
<script>
const oauth = new ZenuxOAuth({
  clientId: 'your-client-id',
  theme: 'auto'
});

  oauth.on('login', (tokens) => {
    console.log('Logged in', tokens);
  });

  oauth.on('error', (error) => {
    console.error('OAuth error', error);
  });

  window.addEventListener('load', async () => {
    await oauth.init();
  });

  document.getElementById('login').addEventListener('click', async () => {
    await oauth.login();
  });
</script>
```

### Browser modes

```js
const oauth = new ZenuxOAuth({ clientId: 'your-client-id' });

await oauth.login();                    // default browser mode: ui
await oauth.login({ mode: 'ui' });      // embedded bottom-sheet auth
await oauth.login({ mode: 'popup' });   // popup window
await oauth.login({ mode: 'redirect' });// full-page redirect

const authData = await oauth.login({ mode: 'manual' });
console.log(authData.url);
```

Mode aliases:

- `inui`
- `iframe`

Both map to `ui`.

### Theme and smoother embedded UI

```js
const oauth = new ZenuxOAuth({
  clientId: 'your-client-id',
  theme: 'dark',
  uiTitle: 'Continue with Zenuxs',
  uiDescription: 'Secure sign in in a bottom sheet.',
  uiFallbackMode: 'popup'
});
```

Theme options:

- `auto`
- `light`
- `dark`

The embedded `ui` mode now:

- opens as a bottom sheet instead of a plain centered iframe box
- shows a loading screen while auth is starting and while the callback is finishing
- asks for confirmation before closing with the `X` button
- can move to popup or full-page redirect when embedded provider login does not work

### Social provider fallback

Some providers such as Google, Discord, and GitHub often do not behave well inside iframes.

The SDK now helps in two ways:

1. If you directly request one of those providers, `ui` mode is promoted to `popup` automatically.
2. If embedded auth returns to your page without usable callback params, the SDK can move the flow to popup or full page.

Example:

```js
await oauth.login({
  mode: 'ui',
  provider: 'google',
  uiFallbackMode: 'popup'
});
```

### Node.js, same route (with non-public clientSecret)

For confidential server-side clients, pass `clientSecret` (kept secure on your backend, never exposed in browsers):

```js
const express = require('express');
const session = require('express-session');
const ZenuxOAuth = require('zenuxs-oauth');

const app = express();

app.use(session({
  secret: 'replace-me',
  resave: false,
  saveUninitialized: false
}));

// Confidential backend client: uses both clientId and non-public clientSecret
const oauth = new ZenuxOAuth({
  clientId: process.env.ZENUX_CLIENT_ID,
  clientSecret: process.env.ZENUX_CLIENT_SECRET
});

app.get('/login', async (req, res, next) => {
  try {
    const tokens = await oauth.login({
      request: req,
      response: res
    });

    if (!tokens) {
      return;
    }

    req.session.tokens = tokens;
    res.redirect('/dashboard');
  } catch (error) {
    next(error);
  }
});
```

### Node.js, manual flow

```js
const oauth = new ZenuxOAuth({
  clientId: process.env.ZENUX_CLIENT_ID,
  clientSecret: process.env.ZENUX_CLIENT_SECRET, // Non-public client secret
  redirectUri: 'https://your-app.com/auth/callback'
});

app.get('/auth/login', async (req, res) => {
  const authData = await oauth.login({ mode: 'manual' });
  res.redirect(authData.url);
});

app.get('/auth/callback', async (req, res) => {
  const tokens = await oauth.handleCallback({ request: req });
  res.json(tokens);
});
```

## Public vs Confidential (Non-Public) Clients

- **Public Clients (Browser SPAs, Mobile Apps)**:
  - Run in environments where credentials cannot be kept confidential.
  - Setup: Only provide `clientId`.
  - Security: Uses OAuth 2.0 PKCE (S256 challenge & code verifier) automatically.
  - **Never** expose `clientSecret` in frontend client code.

- **Confidential / Non-Public Clients (Node.js, Express, Backends)**:
  - Run on secure servers where secrets can be protected via environment variables.
  - Setup: Provide both `clientId` and `clientSecret`.
  - Security: `clientSecret` is automatically included in backend token exchanges, refreshes, revocations, and introspection.

## Default Behavior

### Frontend defaults

- default mode: `redirect`
- redirect URI: current page without `code`, `state`, or OAuth error params
- fetch: auto-detected
- storage: auto-detected

### Backend defaults

- default mode: `redirect`
- fetch: auto-detected from `globalThis.fetch`, `node-fetch`, or `undici`
- storage: in-memory unless you pass your own adapter

### Post-auth redirect defaults (tag & mount mode)

- **auto-redirect**: enabled by default (redirects to `/` after auth)
- **redirect-delay**: 1 second
- **redirect-url**: `/` (root path)

Set `auto-redirect="false"` on the tag to disable automatic redirection.

## Configuration

Only `clientId` is required for public clients; confidential backend clients also supply `clientSecret`.

```js
const oauth = new ZenuxOAuth({
  clientId: 'your-client-id',
  clientSecret: 'your-non-public-client-secret', // backend only!
  redirectUri: 'https://your-app.com/login',
  scopes: 'openid profile email',
  mode: 'ui',
  frontendMode: 'ui',
  backendMode: 'redirect',
  storage: 'sessionStorage',
  storagePrefix: 'zenux_oauth_',
  fetch: fetch,
  debug: true,
  theme: 'auto',
  usePKCE: true,
  validateState: true,
  autoRefresh: true,
  refreshThreshold: 60,
  popupWidth: 540,
  popupHeight: 720,
  uiWidth: 460,
  uiHeight: 720,
  uiFallbackMode: 'popup',
  uiAllowRedirectFallback: true,
  uiCloseConfirm: true,
  extraAuthParams: {
    prompt: 'login'
  }
});
```

### Important options

| Option | Required | Default | Notes |
| --- | --- | --- | --- |
| `clientId` | yes | - | OAuth Application Client ID |
| `clientSecret` | no (required for non-public backend) | `null` | Confidential secret for backend token exchange. Keep secret! |
| `redirectUri` | no | current page in browser | Useful for dedicated callback routes |
| `mode` | no | environment default | `ui` (or `inui`), `popup`, `redirect`, `manual` |
| `frontendMode` | no | `ui` | Browser default |
| `backendMode` | no | `redirect` | Server default |
| `theme` | no | `auto` | Embedded UI theme: `auto`, `light`, or `dark` |
| `storage` | no | `auto` | `sessionStorage`, `localStorage`, `memory`, `Map`, or custom adapter |
| `fetch` / `fetchFunction` | no | auto | Override only when needed |
| `uiFallbackMode` | no | `popup` | Preferred fallback when embedded provider auth cannot continue |
| `uiAllowRedirectFallback` | no | `true` | Allows full-page fallback when popup is blocked or not desired |
| `uiCloseConfirm` | no | `true` | Ask for confirmation before closing the embedded sheet |
| `debug` | no | `false` | Logs SDK internals |
| `autoRefresh` | no | `false` | Refreshes access tokens when possible |

## Redirect URI Matching

The server uses **prefix-based** redirect URI matching. If you register `https://example.com/callback` as a redirect URI, all of these will be accepted:

- `https://example.com/callback`
- `https://example.com/callback/`
- `https://example.com/callback?code=abc&state=xyz`

The origin (scheme + host + port) must match exactly.

## Main Methods

### `login(options?)`

Starts login, or completes it automatically if the current URL already contains OAuth callback params.

### `init(options?)`

Best for browser page load.

It checks the current URL and finishes the callback automatically when needed.

### `handleCallback(callbackUrl?, options?)`

Manual callback handling.

Use this when you want to process a specific URL or server request yourself.

### `getAuthorizationUrl(options?)`

Returns the authorization request data without redirecting.

### `getTokens()`

Returns stored tokens or `null`.

### `refreshTokens()`

Uses the refresh token, if available.

### `getUserInfo()`

Calls the user info endpoint using the current access token.

### `logout(options?)`

Clears tokens and optionally revokes them.

### `getAuthenticatedFetch()`

Returns a fetch wrapper that injects the bearer token automatically.

## Events

```js
oauth.on('loginRequest', (authData) => {
  console.log(authData.url);
});

oauth.on('login', (tokens) => {
  console.log('Logged in', tokens);
});

oauth.on('tokenRefresh', (tokens) => {
  console.log('Refreshed', tokens);
});

oauth.on('tokenExpired', () => {
  console.log('Refreshing soon');
});

oauth.on('logout', () => {
  console.log('Logged out');
});

oauth.on('error', (error) => {
  console.error(error);
});
```

## Manual Flow Example

```js
const oauth = new ZenuxOAuth({
  clientId: 'your-client-id',
  redirectUri: 'https://your-app.com/auth/callback'
});

const authData = await oauth.login({ mode: 'manual' });
console.log(authData.url);
console.log(authData.state);
console.log(authData.codeVerifier);
```

Later:

```js
const tokens = await oauth.handleCallback('https://your-app.com/auth/callback?code=abc&state=xyz');
```

## Authenticated Fetch

```js
const authFetch = oauth.getAuthenticatedFetch();

const response = await authFetch('https://api.example.com/me');
const data = await response.json();
```

## Supported Scopes

```js
console.log(ZenuxOAuth.supportedScopes);
```

Default scopes:

```txt
openid profile email
```

## Examples

- Browser same-page demo: `exmaples/browser/index.html`
- Browser dedicated callback demo: `exmaples/browser/callback.html`
- Express same-route demo: `exmaples/node/express-same-route.js`
- `testlogin.html` for a very small same-page setup

Serve the browser examples over `http://` or `https://`, not `file://`.

## Notes

- Keep secrets on the backend only
- Verify state unless you have a very specific reason not to
- Prefer the default same-page flow unless your app needs a dedicated callback route
- `popup` and `ui` both support automatic callback completion
- For direct Google, Discord, or GitHub login, popup mode is usually the safest UX

## Social API Wrappers

The SDK provides helper methods for interacting with users' connected social accounts (Twitter/X, LinkedIn, YouTube, Facebook, Instagram, etc.).

```js
const oauth = new ZenuxOAuth({ clientId: 'your-client-id' });
await oauth.login();

// Access social providers
const x = oauth.x();

// Listen to events on this specific provider
x.on('post_created', (event) => {
    console.log(`Successfully created a post on ${event.provider}!`, event.data);
});

// Get user data from provider
const userData = await x.getData();

// Get posts
const posts = await x.getPost();

// Create a post
await x.createPost({ message: 'Hello from Zenuxs API!' });

// Get analytics
const analytics = await x.analytics();
```

### Supported Providers
- `oauth.x()` or `oauth.twitter()`
- `oauth.linkedin()`
- `oauth.youtube()`
- `oauth.facebook()`
- `oauth.instagram()`

## License

MIT
