# ZenuxsCloud — Host Proxy Docs

`ZenuxsCloud` is a class inside `zenuxs-oauth` that talks to the **Zenuxs Host backend** (`hostapi.zenuxs.in`) using your Zenuxs OAuth token. No extra API keys or passwords — OAuth token is the only credential.

---

## What is "host API"

Every `host.*` call is a `POST` request to the **Zenuxs Cloud IDE backend** (the Express server). The `oauthBearer` middleware on that backend validates your Zenuxs OAuth token automatically, so you never manually send passwords or local JWTs.

```
host.servers.start(id)
    └── POST http://localhost:7000/server/start
            Authorization: Bearer <zenuxs-oauth-token>
```

---

## Setup

```js
import { ZenuxOAuth, ZenuxsCloud } from 'zenuxs-oauth';

const oauth = new ZenuxOAuth({
    clientId:    'your-client-id',
    redirectUri: 'https://yourapp.com/auth/callback',
    scopes:      'openid profile email github github:repos github:commit'
});

await oauth.login();

const host = new ZenuxsCloud({
    host:  'http://localhost:7000',
    oauth  // must be authenticated
});
```

Factory shorthand:

```js
import { createOAuthClient, createCloud } from 'zenuxs-oauth';

const oauth = createOAuthClient({ clientId: '...', redirectUri: '...' });
await oauth.login();
const host = createCloud({ host: 'http://localhost:7000', oauth });
```

---

## `host.servers` — Server Management

### `host.servers.list()`

Get all servers owned by the logged-in user.

```js
const { success, servers } = await host.servers.list();
// servers = [{ id, name, type, plan, status, port, publicUrl, ... }]
```

**Required:** nothing (uses OAuth token to identify user)

---

### `host.servers.get(serverId)`

Get a single server plus its public URL.

```js
const { success, server, publicUrl } = await host.servers.get('17732380410350376');
```

| Param | Required | Type | Description |
|---|---|---|---|
| `serverId` | ✅ | string/number | Server ID |

---

### `host.servers.create(opts)`

Create a new server. Automatically provisions Docker container, assigns a node, creates a subdomain.

```js
const result = await host.servers.create({
    name:        'My API',           // required
    type:        'node',             // required — 'node' | 'py' | 'web'
    plan:        'free',             // required — 'free' | 'tear1' | 'tear2' | 'tear3' | 'tear4'
    description: 'My backend API'   // optional
});

// result = { success, serverId, port, subdomain, publicUrl, nodeAssignment }
```

| Param | Required | Type | Description |
|---|---|---|---|
| `name` | ✅ | string | Server display name |
| `type` | ✅ | `'node'` \| `'py'` \| `'web'` | Runtime type — Node.js, Python, or static web (nginx) |
| `plan` | ✅ | `'free'` \| `'tear1'` \| `'tear2'` \| `'tear3'` \| `'tear4'` | Resource plan |
| `description` | ❌ | string | Optional description (default: `'Not provided'`) |

**Plans:**

| Plan | Memory | CPUs | Disk |
|---|---|---|---|
| `free` | 128 MB | 0.15 | 512 MB |
| `tear1` | 128 MB | 0.2 | 512 MB |
| `tear2` | 256 MB | 0.5 | 1 GB |
| `tear3` | 512 MB | 1.0 | 3 GB |
| `tear4` | 1 GB | 2.0 | 10 GB |

**Types:**

| Type | Runtime | Default port | Entry point |
|---|---|---|---|
| `node` | Node.js 18 Alpine | 3000 | `index.js` |
| `py` | Python 3.9 | 5000 | `app.py` |
| `web` | Nginx Alpine | 80 | `index.html` |

---

### `host.servers.start(serverId)`

Start a stopped server. If the container is missing it re-deploys automatically.

```js
const { success, message, publicUrl } = await host.servers.start('17732380410350376');
```

| Param | Required | Type |
|---|---|---|
| `serverId` | ✅ | string/number |

---

### `host.servers.stop(serverId)`

Stop a running server.

```js
const { success, message } = await host.servers.stop('17732380410350376');
```

---

### `host.servers.restart(serverId)`

Restart a server. Re-deploys if container is missing.

```js
const { success, message, publicUrl } = await host.servers.restart('17732380410350376');
```

---

### `host.servers.status(serverId)`

Get the live container status from the node agent.

```js
const { success, status } = await host.servers.status('17732380410350376');
// status = 'running' | 'stopped' | 'error'
```

---

### `host.servers.stats(serverId)`

Get CPU, memory and disk usage from the node agent.

```js
const { success, stats, limits } = await host.servers.stats('17732380410350376');
// stats  = { cpu, memory, disk, ... }
// limits = { memory: '128m', cpus: '0.15', diskQuota: '512m' }
```

---

### `host.servers.update(serverId, opts)`

Update server settings. Only the fields you pass are changed.

```js
await host.servers.update('17732380410350376', {
    name:            'New Name',       // optional
    description:     'Updated desc',   // optional
    developmentMode: true,             // optional — switches dev/prod container
    buildConfig:     { ... }           // optional — build config object
});
```

| Param | Required | Type | Description |
|---|---|---|---|
| `serverId` | ✅ | string/number | Server to update |
| `name` | ❌ | string | New display name |
| `description` | ❌ | string | New description |
| `developmentMode` | ❌ | boolean | `true` = run dev container, `false` = prod container |
| `buildConfig` | ❌ | object | Build config (merged with existing) |
| `adminIPs` | ❌ | string[] | IP whitelist for admin access |

---

### `host.servers.delete(serverId)`

Permanently delete a server — stops container, removes Docker image, deletes files and DB record.

```js
const { success, message } = await host.servers.delete('17732380410350376');
```

---

### `host.servers.monitor(serverId)`

Get combined status + stats in one call.

```js
const { success, status, stats } = await host.servers.monitor('17732380410350376');
```

---

### `host.servers.command(serverId, command)`

Run a shell command inside the server container.

```js
const { success, output, error, currentDirectory, exitCode } =
    await host.servers.command('17732380410350376', 'node --version');
```

| Param | Required | Type |
|---|---|---|
| `serverId` | ✅ | string/number |
| `command` | ✅ | string |

---

### `host.servers.commandHistory(serverId)`

Get the command log history for a server.

```js
const { success, history } = await host.servers.commandHistory('17732380410350376');
// history = [{ timestamp, type: 'command'|'stdout'|'stderr', content }]
```

---

### `host.servers.clearCommandHistory(serverId)`

Clear the command log.

```js
await host.servers.clearCommandHistory('17732380410350376');
```

---

## `host.logs(serverId, opts)` — Logs

Reads `server.log` from the server and returns lines.

| Option | Type | Default | Description |
|---|---|---|---|
| `last` | number | `100` | How many lines from the end to return |
| `errors` | boolean | `false` | `true` = return only error/exception/fatal lines |

```js
// Last 25 lines of all output
const { success, lines, total } = await host.logs('17732380410350376', { last: 25 });

// Last 50 error lines only
const { lines } = await host.logs('17732380410350376', { errors: true, last: 50 });
```

**Response:**
```json
{ "success": true, "lines": ["[INFO] Server running on port 3000"], "total": 1 }
```

---

## `host.errors(serverId, last?)` — Errors only

Shorthand for `host.logs(serverId, { errors: true, last })`.

Matches lines containing: `error`, `exception`, `fatal`, `uncaughtException`, `unhandledRejection` (case-insensitive).

```js
const { lines } = await host.errors('17732380410350376', 10);
```

| Param | Required | Default |
|---|---|---|
| `serverId` | ✅ | — |
| `last` | ❌ | `50` |

---

## `host.files(serverId, opts?)` — File Tree

Returns the file tree for a server. Always excludes: `node_modules`, `.git`, `dist`, `build`, `.next`, `.nuxt`.

| Option | Type | Default | Description |
|---|---|---|---|
| `folder` | string | `''` | Only return files inside this folder path |
| `maxDepth` | number | `null` | Max directory depth to traverse |

```js
// All files
const { success, files } = await host.files('17732380410350376');

// Only the src/ folder
const { files } = await host.files('17732380410350376', { folder: 'src' });

// Shallow — depth 1 only
const { files } = await host.files('17732380410350376', { maxDepth: 1 });
```

**Response:**
```json
{
  "success": true,
  "files": [
    { "name": "index.js", "type": "file", "path": "index.js", "size": 512, "sizeFormatted": "512 B" },
    { "name": "src",      "type": "folder", "path": "src", "children": [...] },
    { "name": ".env",     "type": "file",  "path": ".env" }
  ]
}
```

> `.env` appears in the list by name — its content is never returned here.

---

## `host.file(serverId, filePath)` — Read File

Read a file's content. `.env` file values are automatically masked.

```js
const { success, content } = await host.file('17732380410350376', 'index.js');

// .env masking — keys visible, values hidden
const { content } = await host.file('17732380410350376', '.env');
// "PORT=***\nDB_URL=***\nJWT_SECRET=***"
```

| Param | Required | Type |
|---|---|---|
| `serverId` | ✅ | string/number |
| `filePath` | ✅ | string — relative to `/app` e.g. `'src/app.js'` |

---

## `host.updateFile(serverId, filePath, content)` — Write File

Write content to a file. Creates the file if it doesn't exist.

```js
await host.updateFile('17732380410350376', 'index.js', `
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
`);
```

| Param | Required | Type |
|---|---|---|
| `serverId` | ✅ | string/number |
| `filePath` | ✅ | string |
| `content` | ✅ | string |

---

## `host.deleteFile(serverId, filePath)` — Delete File

```js
await host.deleteFile('17732380410350376', 'oldfile.js');
```

---

## `host.github` — GitHub Integration

GitHub is connected through the **Zenuxs OAuth `github:repos` scope** — no separate GitHub OAuth app required.

### Required scopes when calling `oauth.login()`:

```
openid profile email github github:repos github:commit
```

---

### `host.github.connect()`

Link GitHub to the current user's account using their Zenuxs OAuth token. Call once per user — their GitHub token is stored on the host backend and used automatically for all private repo deployments.

```js
const { success, username, message } = await host.github.connect();
```

---

### `host.github.status()`

Check if GitHub is connected.

```js
const { success, connected, username, avatarUrl, connectedAt } =
    await host.github.status();
```

---

### `host.github.disconnect()`

Remove GitHub connection.

```js
await host.github.disconnect();
```

---

### `host.github.pipelines(serverId)`

List all pipelines for a server.

```js
const { success, pipelines } = await host.github.pipelines('17732380410350376');
```

---

### `host.github.addPipeline(serverId, opts)`

Create a new CI/CD pipeline that links a GitHub repo to a server.

```js
const { success, pipeline, webhookUrl, webhookSecret } =
    await host.github.addPipeline('17732380410350376', {
        name:             'Production',               // required
        repository:       'https://github.com/you/app', // required
        branch:           'main',                     // optional — default 'main'
        buildCommand:     'npm install',              // optional — default 'npm install && npm run build'
        deployCommand:    'npm start',                // optional — default 'npm start'
        autoDeployOnPush: true,                       // optional — default true
        enabled:          true                        // optional — default true
    });
```

| Param | Required | Type | Default |
|---|---|---|---|
| `name` | ✅ | string | — |
| `repository` | ✅ | string | GitHub HTTPS URL |
| `branch` | ❌ | string | `'main'` |
| `buildCommand` | ❌ | string | `'npm install && npm run build'` |
| `deployCommand` | ❌ | string | `'npm start'` |
| `autoDeployOnPush` | ❌ | boolean | `true` |
| `enabled` | ❌ | boolean | `true` |

---

### `host.github.editPipeline(pipelineId, serverId, opts)`

Update any pipeline field. Only the fields you pass are changed.

```js
await host.github.editPipeline(pipeline._id, '17732380410350376', {
    branch:           'production',
    autoDeployOnPush: false
});
```

All params same as `addPipeline` but all are optional.

---

### `host.github.removePipeline(pipelineId, serverId)`

Delete a pipeline.

```js
await host.github.removePipeline(pipeline._id, '17732380410350376');
```

---

### `host.github.push(serverId, pipelineId)`

Manually trigger a deploy — clones the repo from GitHub and pushes it to the server container.

```js
const { success, message, deployment } =
    await host.github.push('17732380410350376', pipeline._id);
```

---

### `host.github.deployments(serverId)`

List the last 50 deployments for a server.

```js
const { success, deployments } = await host.github.deployments('17732380410350376');
// deployments[0] = { status, pipelineName, commit, triggeredBy, startedAt, completedAt, duration, logs }
```

---

### `host.github.deployment(deploymentId)`

Get a single deployment's full details + logs.

```js
const { success, deployment } = await host.github.deployment(deploymentId);
console.log(deployment.status);  // 'pending' | 'running' | 'success' | 'failed'
console.log(deployment.logs);    // full build + deploy log string
```

---

## Auto-deploy on push (webhook)

When `autoDeployOnPush: true`, every GitHub push to the configured branch triggers a deploy automatically.

1. Create pipeline with `autoDeployOnPush: true`
2. Copy the returned `webhookUrl`
3. Go to your GitHub repo → **Settings → Webhooks → Add webhook**
4. Set **Payload URL** = `webhookUrl`
5. Set **Content type** = `application/json`
6. Click **Add webhook**

Every push to `branch` now clones the repo and deploys it to the server automatically.

---

## Full example

```js
import { ZenuxOAuth, ZenuxsCloud } from 'zenuxs-oauth';

const oauth = new ZenuxOAuth({
    clientId:    'your-client-id',
    redirectUri: 'https://myapp.com/auth/callback',
    scopes:      'openid profile email github github:repos github:commit'
});

await oauth.login();

const host = new ZenuxsCloud({ host: 'http://localhost:7000', oauth });

// Create a Node.js server
const { serverId } = await host.servers.create({
    name: 'My API',
    type: 'node',
    plan: 'free'
});

// Start it
await host.servers.start(serverId);

// Check status
const { status } = await host.servers.status(serverId);
console.log(status); // 'running'

// Get last 30 log lines
const { lines } = await host.logs(serverId, { last: 30 });

// Get only error lines
const { lines: errors } = await host.errors(serverId, 10);

// Read server stats
const { stats } = await host.servers.stats(serverId);

// Browse files (src/ only, ignoring node_modules etc)
const { files } = await host.files(serverId, { folder: 'src' });

// Read and edit a file
const { content } = await host.file(serverId, 'index.js');
await host.updateFile(serverId, 'index.js', content + '\n// edited');

// Run a command inside the container
const { output } = await host.servers.command(serverId, 'node --version');

// Connect GitHub via OAuth scope
await host.github.connect();

// Create a pipeline + enable auto-deploy on push
const { pipeline, webhookUrl } = await host.github.addPipeline(serverId, {
    name:             'Production',
    repository:       'https://github.com/you/my-api',
    branch:           'main',
    buildCommand:     'npm install',
    autoDeployOnPush: true
});

// Manually trigger a deploy now
await host.github.push(serverId, pipeline._id);

// Check deployment status
const { deployment } = await host.github.deployment(deployment._id);
console.log(deployment.status, deployment.logs);

// Restart server after deploy
await host.servers.restart(serverId);
```

---

## Auth flow

```
Your app
  │
  ├─ oauth.login()  ──────────►  Zenuxs Accounts (OAuth)
  │                                    │ issues access_token with github:repos scope
  │◄──────────────────────────── tokens
  │
  └─ host.servers.start(id)  ──►  Zenuxs Host Backend (Express)
                                        │
                                   oauthBearer middleware
                                        │ POST /oauth/userinfo → Zenuxs Auth Server
                                        │ finds/creates local user
                                        │ injects req.body.token (short-lived local JWT)
                                        ▼
                                   serverController.startServer()
```

---

## Notes

- **`.env` values are always masked** — `host.file('.env')` returns `KEY=***`, keys are preserved
- **`node_modules`, `.git`, `dist`, `build`, `.next`, `.nuxt`** are always excluded from `host.files()`
- **`host.errors()`** matches lines with: `error`, `exception`, `fatal`, `uncaughtException`, `unhandledRejection` (case-insensitive)
- **`host.servers.command()`** runs inside the live Docker container via the node agent
- **GitHub connection is per-user**, stored once — all pipelines for that user use it automatically
- **`autoDeployOnPush`** requires adding the `webhookUrl` to GitHub repo settings manually
- After `oauth.login()` the token is stored in `sessionStorage` — `ZenuxsCloud` reads it automatically via `oauth.getAccessToken()`
