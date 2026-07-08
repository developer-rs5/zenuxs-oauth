export type ZenuxOAuthMode = 'ui' | 'inui' | 'iframe' | 'popup' | 'redirect' | 'manual';

export type ZenuxOAuthFetch = (...args: any[]) => Promise<any>;

export interface ZenuxOAuthStorageLike {
    getItem?(key: string): string | null;
    setItem?(key: string, value: string): void;
    removeItem?(key: string): void;
    get?(key: string): string | null;
    set?(key: string, value: string): void;
    remove?(key: string): void;
    clear?(): void;
    clearPrefix?(prefix: string): void;
}

export interface ZenuxOAuthConfig {
    clientId: string;
    authServer?: string;
    redirectUri?: string;
    scopes?: string;
    authorizeEndpoint?: string;
    tokenEndpoint?: string;
    userinfoEndpoint?: string;
    discoveryEndpoint?: string;
    jwksEndpoint?: string;
    clientInfoEndpoint?: string;
    revokeEndpoint?: string;
    storage?: 'auto' | 'localStorage' | 'sessionStorage' | 'memory' | ZenuxOAuthStorageLike;
    storagePrefix?: string;
    autoRefresh?: boolean;
    refreshThreshold?: number;
    debug?: boolean;
    usePKCE?: boolean;
    validateState?: boolean;
    fetch?: ZenuxOAuthFetch;
    fetchFunction?: ZenuxOAuthFetch;
    theme?: 'auto' | 'light' | 'dark' | string;
    mode?: ZenuxOAuthMode | string;
    frontendMode?: ZenuxOAuthMode | string;
    backendMode?: ZenuxOAuthMode | string;
    provider?: string;
    popupWidth?: number;
    popupHeight?: number;
    uiWidth?: number;
    uiHeight?: number;
    uiTitle?: string;
    uiDescription?: string;
    uiFallbackMode?: 'popup' | 'redirect' | string;
    uiAllowRedirectFallback?: boolean;
    uiCloseConfirm?: boolean;
    uiLoadHintDelay?: number;
    extraAuthParams?: Record<string, any>;
    extraTokenParams?: Record<string, any>;
}

export interface TokenResponse {
    access_token: string;
    token_type?: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
    expires_at?: number;
    [key: string]: any;
}

export interface UserInfo {
    sub: string;
    name?: string;
    email?: string;
    email_verified?: boolean;
    picture?: string;
    given_name?: string;
    family_name?: string;
    [key: string]: any;
}

export interface ZenuxOAuthAuthorizationRequest {
    url: string;
    state: string;
    nonce: string;
    codeVerifier?: string | null;
    redirectUri: string;
    mode: string;
}

export interface ZenuxOAuthLoginOptions {
    mode?: ZenuxOAuthMode | string;
    flow?: ZenuxOAuthMode | string;
    loginMode?: ZenuxOAuthMode | string;
    theme?: 'auto' | 'light' | 'dark' | string;
    provider?: string;
    identityProvider?: string;
    connection?: string;
    idp?: string;
    redirectUri?: string;
    currentUrl?: string;
    callbackUrl?: string;
    request?: any;
    response?: any;
    baseUrl?: string;
    timeout?: number;
    popupName?: string;
    popupWidth?: number;
    popupHeight?: number;
    popupFeatures?: string;
    uiTitle?: string;
    uiDescription?: string;
    uiFallbackMode?: 'popup' | 'redirect' | string;
    uiAllowRedirectFallback?: boolean;
    uiCloseConfirm?: boolean;
    extraAuthParams?: Record<string, any>;
    extraTokenParams?: Record<string, any>;
    autoLogin?: boolean;
    allowMissingCallback?: boolean;
    notifyParent?: boolean;
    closePopup?: boolean;
    closeDelay?: number;
    redirectStatus?: number;
    onSuccess?: (tokens: TokenResponse) => void;
    onError?: (error: ZenuxOAuthError) => void;
    [key: string]: any;
}

export interface ZenuxOAuthSessionState {
    isAuthenticated: boolean;
    tokens: TokenResponse | null;
    expiresAt: number | null;
    timeUntilExpiry: number | null;
}

export interface ZenuxOAuthExportedSession {
    tokens: TokenResponse | null;
    clientId: string;
    authServer: string;
}

declare class ZenuxOAuthError extends Error {
    constructor(message: string, code: string, details?: any);
    code: string;
    details: any;
    timestamp: string;
    toJSON(): any;
}

declare class ZenuxOAuth {
    constructor(config: ZenuxOAuthConfig);

    login(options?: ZenuxOAuthLoginOptions | ZenuxOAuthMode): Promise<TokenResponse | ZenuxOAuthAuthorizationRequest | null>;
    init(options?: ZenuxOAuthLoginOptions): Promise<TokenResponse | ZenuxOAuthSessionState | null>;
    handleCallback(callbackUrl?: string | ZenuxOAuthLoginOptions, options?: ZenuxOAuthLoginOptions): Promise<TokenResponse | null>;
    getAuthorizationUrl(options?: ZenuxOAuthLoginOptions): Promise<ZenuxOAuthAuthorizationRequest>;
    exchangeCodeForTokens(code: string, options?: ZenuxOAuthLoginOptions): Promise<TokenResponse>;
    getUserInfo(): Promise<UserInfo>;
    getDiscoveryDocument(): Promise<any>;
    getJwks(): Promise<any>;
    getClientInfo(clientId?: string): Promise<any>;
    getTokens(): TokenResponse | null;
    getAccessToken(): string | null;
    isAuthenticated(): boolean;
    isTokenExpired(bufferSeconds?: number | null): boolean;
    logout(options?: any): Promise<boolean>;
    refreshTokens(options?: any): Promise<TokenResponse>;
    revokeToken(token?: string, tokenType?: string): Promise<boolean>;
    decodeJWT(token: string): any;
    exportSession(): ZenuxOAuthExportedSession;
    importSession(data: ZenuxOAuthExportedSession): TokenResponse;
    getSessionState(): ZenuxOAuthSessionState;
    getAuthenticatedFetch(): ZenuxOAuthFetch;
    on(event: string, handler: Function): Function;
    off(event: string, handler?: Function): void;
    emit(event: string, payload?: any): void;
    destroy(): void;
    static supportedScopes: string[];
}

export default ZenuxOAuth;
export { ZenuxOAuth, ZenuxOAuthError };