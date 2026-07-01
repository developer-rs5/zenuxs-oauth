'use strict';

const ZenuxOAuth = require('./zenux-oauth.js');
const { ZenuxOAuthError, ZenuxsCloud } = ZenuxOAuth;

module.exports = ZenuxOAuth;
module.exports.default = ZenuxOAuth;
module.exports.ZenuxOAuth = ZenuxOAuth;
module.exports.ZenuxOAuthError = ZenuxOAuthError;
module.exports.ZenuxsCloud = ZenuxsCloud;

/**
 * Create a ZenuxOAuth client instance.
 * @param {object} config - ZenuxOAuth config (clientId, redirectUri, scopes, ...)
 * @returns {ZenuxOAuth}
 */
module.exports.createOAuthClient = (config) => new ZenuxOAuth(config);

/**
 * Create a ZenuxsCloud host proxy.
 *
 * Example:
 *   import { ZenuxOAuth, ZenuxsCloud } from 'zenuxs-oauth';
 *
 *   const oauth = new ZenuxOAuth({ clientId: 'xxx', redirectUri: 'https://...' });
 *   const host  = new ZenuxsCloud({ host: 'http://localhost:7000', oauth });
 *
 *   // after login:
 *   await host.servers.start('123');
 *   await host.logs('123', { errors: false, last: 25 });
 *   await host.files('123', { folder: 'src' });
 *   await host.errors('123', 10);
 *   await host.github.push('123', pipelineId);
 *
 * @param {{ host: string, oauth: ZenuxOAuth }} config
 * @returns {ZenuxsCloud}
 */
module.exports.createCloud = (config) => new ZenuxsCloud(config);
