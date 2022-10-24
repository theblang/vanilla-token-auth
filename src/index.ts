import Cookies, { CookieAttributes } from 'js-cookie';

type CustomOptions = {
    params?: Record<string, any>
    config?: string
    auth_origin_url?: string
}

type RejectOptions = {
    reason: string
    errors: string[]
}

type AuthHeaders = {
    'access-token': string
    'token-type': string
    client: string
    expiry: string
    uid: string
}

type CustomStorage = {
    persistData: (key: string, val: string) => void
    retrieveData: (key: string) => void
    deleteData: (key: string) => void
}

type Config = {
    /**
     * The base route to your api. Each of the following paths will be relative to this URL. Authentication headers will only be added to requests with this value as the base URL.
     */
    apiUrl: string
    /**
     * Relative path to sign user out. this will destroy the user's token both server-side and client-side.
     */
    signOutUrl: string
    /**
     * Path for signing in using email credentials.
     */
    emailSignInPath: string
    /**
     * Path for submitting new email registrations.
     */
    emailRegistrationPath: string
    /**
     * Path for submitting account update requests.
     */
    accountUpdatePath: string
    /**
     * Path for submitting account deletion requests.
     */
    accountDeletePath: string

    /**
     * The url to which the API should redirect after users visit the link contained in email-registration emails.
     */
    confirmationSuccessUrl: string | (() => string)
    /**
     * Path for requesting password reset emails.
     */
    passwordResetPath: string
    /**
     * Path for submitting new passwords for authenticated users.
     */
    passwordUpdatePath: string
    /**
     * The URL to which the API should redirect after users visit the links contained in password-reset emails.
     */
    passwordResetSuccessUrl: string | (() => string)
    /**
     * Relative path to validate authentication tokens.
     */
    tokenValidationPath: string
    /**
     * Older browsers have trouble with CORS. Pass a method here to determine whether or not a proxy should be used. Example: `function() { return !Modernizr.cors }`.
     */
    proxyIf: () => boolean
    /**
     * Proxy url if proxy is to be used
     */
    proxyUrl: string

    /**
     * Check if a user's auth token exists and is valid on page load.
     */
    validateOnPageLoad: boolean
    /**
     * Dictates the methodology of the OAuth login flow. One of: `sameWindow` (default), `newWindow`, or `inAppBrowser`.
     */
    omniauthWindowType: string
    /**
     * The method used to persist tokens between sessions. cookies are used by default, but `window.localStorage` and `window.sessionStorage` can be used as well. A custom object can also be used. Allowed strings are `cookies`, `localStorage`, and `sessionStorage`, otherwise an object implementing the following interface: `{ function persistData(key, val) {}, function retrieveData(key) {}, function deleteData(key) {} }`.
     */
    storage: string | CustomStorage

    /**
     * The transport used to send the auth token to the server. Either `cookies` (default) or `headers`.
     */
    transport: string
    /**
     * If this flag is set, the API's token validation will be called even if the auth token is not saved in `storage`. This can be useful for implementing a single sign-on (SSO) system.
     */
    forceValidateToken: boolean
    /**
     * A template for authentication tokens. The template will be provided with a context containing `token`, `clientId`, `expiry`, and `uid` params.
     */
    tokenFormat: AuthHeaders
    /**
     * Cookie options for js-cookie
     */
    cookieOps: CookieAttributes
    /**
     * A function that will open OmniAuth window by `url`.
     */
    createPopup: (url: string) => Window | null
    /**
     * A function that will return the token's expiry from the current headers. Returns `null` if no headers or expiry are found.
     */
    parseExpiry: (headers: AuthHeaders) => number | null

    /**
     * A function that will identify and return the current user's info (id, username, etc) in the response of a successful login request.
     */
    handleLoginResponse: (resp: HttpResponse['data']) => any
    /**
     * A function that will identify and return the current user's info (id, username, etc) in the response of a successful account update request.
     */
    handleAccountUpdateResponse: (resp: HttpResponse['data']) => any
    /**
     * A function that will identify and return the current user's info (id, username, etc) in the response of a successful token validation request.
     */
    handleTokenValidationResponse: (resp: HttpResponse['data']) => any

    /**
     * An object containing paths to auth endpoints. keys are names of the providers, values are their auth paths relative to the `apiUrl`.
     */
    authProviderPaths: Record<string, string>
    /**
     * A [`Fetch API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) compatible function wrapper.
     */
    httpWrapper: typeof window.fetch | undefined
    /**
     * Callback to be used by AngularJS to broadcast events.
     */
    broadcast: (name: string, payload?: any) => void
    /**
     * Helper to navigate to pages programmatically.
     */
    navigate: (url: string, replace?: boolean) => void
}

type HttpResponse<TData = any> = {
    /**
     * The response body transformed with the transform functions
     */
    data: TData;
    /**
     * HTTP status code of the response.
     */
    status: number;
};

/**
 * Promise with `resolve` and `reject` methods of itself
 */
interface DeferredPromise<T = any> {
    resolve(value: T | PromiseLike<T>): void
    reject(reason?: any): void
    promise: Promise<T>
}

/**
 * Interpolate a string with the given data.
 * Simple version of https://code.angularjs.org/1.7.9/docs/api/ng/service/$interpolate
 */
function interpolate(str: string, ctx: Record<string, any>) {
    return str.replace(/{{\s?([a-zA-Z]+)\s?}}/g, (match, key) => ctx[key] || match);
}

/**
 * Based on https://github.com/lodash/lodash/blob/2da024c3b4f9947a48517639de7560457cd4ec6c/isObject.js
 */
function isObject(value: unknown) {
    const type = typeof value
    return value != null && (type === 'object' || type === 'function')
}

// See https://github.com/quanticedu/back_royal/pull/10744#issuecomment-1287033565
// FIXME: if we decide to merge this change, we should add non-standard custom providers
// (apple_quantic, apple_smartly, wechat_web, wechat_native and wechat_official_account) to DeviseTokenAuthClient instance initialization
// in front-royal `devise_token_auth_client_module.js` and `devise-token-auth-client.ts` in Gatsby to support apple and wechat login
export const AuthProviderPathsDefaultConfig = {
    google_oauth2: '/auth/google_oauth2',
    facebook: '/auth/facebook',
    apple: '/auth/apple',
    twitter: '/auth/twitter',
    onelogin: '/auth/onelogin',
    wechat: '/auth/wechat',
}

const configs: Record<string, Config> = {
    default: {
        apiUrl: '/api',
        signOutUrl: '/auth/sign_out',
        emailSignInPath: '/auth/sign_in',
        emailRegistrationPath: '/auth',
        accountUpdatePath: '/auth',
        accountDeletePath: '/auth',
        confirmationSuccessUrl() {
            return window.location.href;
        },
        passwordResetPath: '/auth/password',
        passwordUpdatePath: '/auth/password',
        passwordResetSuccessUrl() {
            return window.location.href;
        },
        tokenValidationPath: '/auth/validate_token',
        // eslint-disable-next-line lodash-fp/prefer-constant
        proxyIf() {
            return false;
        },
        proxyUrl: '/proxy',
        validateOnPageLoad: true,
        omniauthWindowType: 'sameWindow',
        storage: 'cookies',
        transport: 'cookies',
        forceValidateToken: false,

        tokenFormat: {
            'access-token': '{{ token }}',
            'token-type': 'Bearer',
            client: '{{ clientId }}',
            expiry: '{{ expiry }}',
            uid: '{{ uid }}',
        },

        cookieOps: {
            path: '/',
            expires: 9999,
            secure: false,
        },

        // popups are difficult to test. mock this method in testing.
        createPopup(url) {
            return window.open(url, '_blank', 'closebuttoncaption=Cancel');
        },

        parseExpiry(headers: AuthHeaders) {
            // convert from ruby time (seconds) to js time (milliseconds)
            return parseInt(headers.expiry, 10) * 1000 || null;
        },

        handleLoginResponse(resp) {
            return resp.data;
        },
        handleAccountUpdateResponse(resp) {
            return resp.data;
        },
        handleTokenValidationResponse(resp) {
            return resp.data;
        },

        authProviderPaths: AuthProviderPathsDefaultConfig,

        // Default to fetch, but don't assume it's available (e.g., in Jest or when doing SSR)
        httpWrapper: typeof window !== 'undefined' && window.fetch != null ? window.fetch : undefined,

        broadcast(name, payload) {
            if (process.env.NODE_ENV === 'development') {
                console.log(`[${name}]:`, payload); // eslint-disable-line no-console
            }
        },

        navigate(url, replace) {
            if (replace) {
                return window.location.replace(url);
            }
            return window.location.assign(url);
        },
    },
};

let defaultConfigName = 'default';

export default class DeviseTokenAuthClient {
    /**
     * Configure DeviseTokenAuthClient with the given options.
     */
    constructor(params: Partial<Config> | Array<Record<string, Partial<Config>>>) {
        // user is using multiple concurrent configs (>1 user types).
        if (params instanceof Array && params.length) {
            throw new Error('DeviceTokenAuthClient config as an Array is not supported.\nWe need to migrate cloneDeep from lodash/fp/cloneDeep first.');
            // // extend each item in array from default settings
            // for (let i = 0; i < params.length; i++) {
            //     // get the name of the config
            //     const conf = params[i];
            //     let label = '';
            //     // eslint-disable-next-line no-restricted-syntax,guard-for-in
            //     for (const k in conf) {
            //         label = k;

            //         // set the first item in array as default config
            //         if (i === 0) {
            //             defaultConfigName = label;
            //         }
            //     }

            //     // use copy preserve the original default settings object while
            //     // extending each config object
            //     const defaults = cloneDeep(configs.default);
            //     const fullConfig = {} as any;
            //     fullConfig[label] = Object.assign(defaults, conf[label]);
            //     Object.assign(configs, fullConfig);
            // }

            // // remove existing default config
            // if (defaultConfigName !== 'default') {
            //     delete configs.default;
            // }
        } else if (params instanceof Object) {
            // user is extending the single default config
            Object.assign(configs.default, params);
        } else {
            // user is doing something wrong
            throw new Error('Invalid argument: DeviceTokenAuthClient config should be an Array or Object.');
        }
    }

    /**
     * Deferred object
     */
    dfd: DeferredPromise | null = null;

    /**
     * User data object
     */
    user: Record<string, any> = {};

    /**
     * Auth headers object
     */
    headers: Partial<AuthHeaders> = {};

    mustResetPassword = false;
    firstTimeLogin = false;
    oauthRegistration = false;

    timer: number | null = null;
    _hasSessionStorage: boolean | null = null;
    _hasLocalStorage: boolean | null = null;

    /**
     * Window message listener
     */
    listener: ((...args: any[]) => void) | null = null;

    /**
     * Timer for auth window message listener
     */
    requestCredentialsPollingTimer: number|null = null;

    /**
     * Cleanup auth window message listeners
     */
    cancelOmniauthInAppBrowserListeners: Function|null = null;

    /**
     * Wrapper for fetch.
     */
    http<TData>(input: RequestInfo | URL, init?: RequestInit): Promise<HttpResponse<TData>> {
        const httpWrapper = this.getConfig().httpWrapper;
        if (!httpWrapper) {
            throw new Error('No httpWrapper configured');
        }
        return httpWrapper(input, init).then(res =>
            res.json().then(data => {
                const response = { data, status: res.status };
                return res.ok ? response : Promise.reject(response);
            }),
        );
    }

    /**
     * Called once at startup
     */
    initialize() {
        this.initializeListeners();
        this.cancelOmniauthInAppBrowserListeners = () => {};
        const currHeaders = this.retrieveData('auth_headers') || {};
        Object.assign(this.headers, currHeaders);

        // Check to see if user is returning user
        if (this.getConfig().validateOnPageLoad) {
            this.validateUser({ config: this.getSavedConfig() });
        }
    }

    /**
     * Setup listener for Window messages
     */
    initializeListeners() {
        this.listener = this.handlePostMessage.bind(this);

        if (window.addEventListener) {
            window.addEventListener('message', this.listener, false);
        }
    }

    /**
     * Cancel any existing timers, listeners, and promises
     */
    cancel(reason?: RejectOptions) {
        // cancel any pending timers
        if (this.requestCredentialsPollingTimer != null) {
            window.clearTimeout(this.requestCredentialsPollingTimer);
        }

        // cancel inAppBrowser listeners if set
        if (this.cancelOmniauthInAppBrowserListeners) {
            this.cancelOmniauthInAppBrowserListeners();
        }

        // reject any pending promises
        if (this.dfd != null) {
            this.rejectDfd(reason);
        }

        // nullify timer after reflow
        window.setTimeout(() => {
            this.requestCredentialsPollingTimer = null;
        });
    }

    /**
     * Cancel any pending processes, clean up garbage
     */
    destroy() {
        this.cancel();

        if (window.removeEventListener) {
            // @ts-ignore
            window.removeEventListener('message', this.listener, false);
        }
    }

    /**
     * Handle the broadcast events from external auth tabs/popups
     */
    handlePostMessage(ev: MessageEvent<any>) {
        const config = this.getConfig();
        if (ev.data.message === 'deliverCredentials') {
            delete ev.data.message;

            // check if a new user was registered
            const oauthRegistration = ev.data.oauth_registration;
            this.handleValidAuth(ev.data, true);
            config.broadcast('auth:login-success', ev.data);
            if (oauthRegistration) {
                config.broadcast('auth:oauth-registration', ev.data);
            }
        }
        if (ev.data.message === 'authFailure') {
            const error = {
                reason: 'unauthorized',
                errors: [ev.data.error],
            };
            this.cancel(error);
            config.broadcast('auth:login-error', error);
        }
    }

    /**
     * Register by email. Server will send confirmation email containing
     * a link to activate the account. The link will redirect to this site.
     */
    submitRegistration<TData>(params: Record<string, any>, opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        return this.http<TData>(this.apiUrl(opts.config) + config.emailRegistrationPath, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                ...params,
                confirm_success_url: this.getResultOrValue(config.confirmationSuccessUrl),
                config_name: this.getCurrentConfigName(opts.config),
            }),
        }).then(
            resp => {
                config.broadcast('auth:registration-email-success', params);
                return resp;
            },
            resp => {
                config.broadcast('auth:registration-email-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Capture input from user, authenticate server-side
     */
    submitLogin<TData>(params: Record<string, any>, opts: CustomOptions = {}) {
        const promise = this.initDfd<TData>();
        const config = this.getConfig(opts.config);
        this.http(this.apiUrl(opts.config) + config.emailSignInPath, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params),
        }).then(
            resp => {
                this.setConfigName(opts.config);
                const authData = config.handleLoginResponse(resp.data);
                this.handleValidAuth(authData);
                config.broadcast('auth:login-success', this.user);
            },
            resp => {
                this.rejectDfd({
                    reason: 'unauthorized',
                    errors: resp.data ? resp.data.errors : ['Invalid credentials'],
                });
                config.broadcast('auth:login-error', resp.data);
            },
        );
        return promise;
    }

    /**
     * Check if user is authenticated.
     * This uses the stored auth headers to check if the user is authenticated.
     */
    userIsAuthenticated(): boolean {
        return this.retrieveData('auth_headers') && this.user.signedIn && !this.tokenHasExpired();
    }

    /**
     * Request password reset from API
     */
    requestPasswordReset<TData>(params: Record<string, any>, opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        params.redirect_url = this.getResultOrValue(config.passwordResetSuccessUrl);
        if (opts.config != null) {
            params.config_name = opts.config;
        }

        return this.http<TData>(this.apiUrl(opts.config) + config.passwordResetPath, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params),
        }).then(
            resp => {
                config.broadcast('auth:password-reset-request-success', params);
                return resp;
            },
            resp => {
                config.broadcast('auth:password-reset-request-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Update user password
     */
    updatePassword<TData>(params: any, opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        return this.http<TData>(this.apiUrl(opts.config) + config.passwordUpdatePath, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params),
        }).then(
            resp => {
                config.broadcast('auth:password-change-success', resp.data);
                this.mustResetPassword = false;
                return resp;
            },
            resp => {
                config.broadcast('auth:password-change-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Update user account info
     */
    updateAccount<TData>(params: any, opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        return this.http<TData>(this.apiUrl(opts.config) + config.accountUpdatePath, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params),
        }).then(
            resp => {
                const updateResponse = config.handleAccountUpdateResponse(resp.data);
                const curHeaders = this.retrieveData('auth_headers');

                Object.assign(this.user, updateResponse);

                // ensure any critical headers (uid + ?) that are returned in
                // the update response are updated appropriately in storage
                if (curHeaders) {
                    const newHeaders: Record<string, string> = {};
                    Object.entries(config.tokenFormat).forEach(([key]) => {
                        if (curHeaders[key] && updateResponse[key]) {
                            newHeaders[key] = updateResponse[key];
                        }
                    });
                    this.setAuthHeaders(newHeaders as AuthHeaders);
                }
                config.broadcast('auth:account-update-success', resp.data);
                return resp;
            },
            resp => {
                config.broadcast('auth:account-update-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Permanently destroy a user's account.
     */
    destroyAccount<TData>(params: any, opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        return this.http<TData>(this.apiUrl(opts.config) + config.accountUpdatePath, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(params),
        }).then(
            resp => {
                this.invalidateTokens();
                config.broadcast('auth:account-destroy-success', resp.data);
                return resp;
            },
            resp => {
                config.broadcast('auth:account-destroy-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Open external auth provider in separate window, send requests for
     * credentials until api auth callback page responds.
     */
    authenticate(provider: string, opts: CustomOptions = {}) {
        if (this.dfd == null) {
            this.setConfigName(opts.config);
            const promise = this.initDfd();
            this.openAuthWindow(provider, opts);
            return promise;
        }

        return this.dfd.promise;
    }

    /**
     * Set the current config name
     */
    setConfigName(configName?: string) {
        if (configName == null) {
            configName = defaultConfigName;
        }
        return this.persistData('currentConfigName', configName, configName);
    }

    /**
     * Open external window to authentication provider
     */
    openAuthWindow(provider: string, opts: CustomOptions = {}) {
        const { omniauthWindowType, createPopup } = this.getConfig(opts.config);
        const authUrl = this.buildAuthUrl(omniauthWindowType, provider, opts);

        if (omniauthWindowType === 'newWindow') {
            this.requestCredentialsViaPostMessage(createPopup(authUrl) as Window);
        } else if (omniauthWindowType === 'inAppBrowser') {
            this.requestCredentialsViaExecuteScript(createPopup(authUrl) as Window);
        } else if (omniauthWindowType === 'sameWindow') {
            this.visitUrl(authUrl);
        } else {
            throw new Error(`Unsupported omniauthWindowType "${omniauthWindowType}"`);
        }
    }

    /**
     * Testing actual redirects is difficult. Stub this for testing
     */
    // eslint-disable-next-line class-methods-use-this
    visitUrl(url: string) {
        return this.getConfig().navigate(url, true);
    }

    /**
     * Build url for authentication provider
     */
    buildAuthUrl(omniauthWindowType: string, provider: string, opts: CustomOptions = {}) {
        const { apiUrl, authProviderPaths } = this.getConfig(opts.config);
        const authUrl = new URL(apiUrl + authProviderPaths[provider]);

        const params = {
            auth_origin_url: opts.auth_origin_url || window.location.href,
            ...opts.params,
            omniauth_window_type: omniauthWindowType,
        };

        Object.entries(params).forEach(([key, val]) => authUrl.searchParams.append(key, val));

        return authUrl.toString();
    }

    /**
     * Ping auth window to see if user has completed registration.
     * this method is recursively called until:
     * 1. user completes authentication
     * 2. user fails authentication
     * 3. auth window is closed
     */
    requestCredentialsViaPostMessage(authWindow: Window) {
        // user has closed the external provider's auth window without completing login.
        if (authWindow.closed) {
            return this.handleAuthWindowClose();
        }
        // still awaiting user input
        authWindow.postMessage('requestCredentials', '*');
        this.requestCredentialsPollingTimer = window.setTimeout(
            () => this.requestCredentialsViaPostMessage(authWindow),
            500,
        );
        return this.requestCredentialsPollingTimer;
    }

    /**
     * Handle inAppBrowser's executeScript flow
     * flow will complete if:
     * 1. user completes authentication
     * 2. user fails authentication
     * 3. inAppBrowser auth window is closed
     */
    requestCredentialsViaExecuteScript(authWindow: Window) {
        this.cancelOmniauthInAppBrowserListeners?.();
        const handleAuthWindowClose = this.handleAuthWindowClose.bind(this);
        const handleLoadStop = this.handleLoadStop.bind(this, authWindow);
        const handlePostMessage = this.handlePostMessage.bind(this);

        authWindow.addEventListener('loadstop', handleLoadStop);
        authWindow.addEventListener('exit', handleAuthWindowClose);
        authWindow.addEventListener('message', handlePostMessage);

        this.cancelOmniauthInAppBrowserListeners = () => {
            authWindow.removeEventListener('loadstop', handleLoadStop);
            authWindow.removeEventListener('exit', handleAuthWindowClose);
            return authWindow.addEventListener('message', handlePostMessage);
        };
        return this.cancelOmniauthInAppBrowserListeners;
    }

    /**
     * Responds to inAppBrowser window loads
     */
    handleLoadStop(authWindow: Window) {
        const _this = this;

        // favor InAppBrowser postMessage API if available, otherwise revert to returning directly via
        // the executeScript API, which is known to have limitations on payload size
        const remoteCode = `\
function performBestTransit() { \
var data = requestCredentials(); \
if (webkit && webkit.messageHandlers && webkit.messageHandlers.cordova_iab) { \
var dataWithDeliverMessage = Object.assign({}, data, { message: 'deliverCredentials' }); \
webkit.messageHandlers.cordova_iab.postMessage(JSON.stringify(dataWithDeliverMessage)); \
return 'postMessageSuccess'; \
} else { \
return data; \
} \
} \
performBestTransit();`;

        // eslint-disable-next-line consistent-return
        // @ts-ignore
        return authWindow.executeScript({ code: remoteCode }, (response: any) => {
            const data = response[0];
            if (data === 'postMessageSuccess') {
                // the standard issue postHandler will take care of the rest
                return authWindow.close();
            }
            if (data) {
                const ev = new Event('message');
                // @ts-ignore
                ev.data = data;
                _this.cancelOmniauthInAppBrowserListeners?.();
                window.dispatchEvent(ev);
                _this.initDfd();
                return authWindow.close();
            }
        });
    }

    /**
     * Responds to inAppBrowser window closes
     */
    handleAuthWindowClose() {
        this.cancel({
            reason: 'unauthorized',
            errors: ['User canceled login'],
        });
        this.cancelOmniauthInAppBrowserListeners?.();
        this.getConfig().broadcast('auth:window-closed');
    }

    /**
     * This needs to happen after a reflow so that the promise
     * can be rejected properly before it is destroyed.
     */
    resolveDfd() {
        if (!this.dfd) {
            return undefined;
        }

        this.dfd.resolve(this.user);

        return new Promise(resolve => {
            window.setTimeout(() => {
                this.dfd = null;
                resolve(null);
            });
        });
    }

    /**
     * Generates query string based on simple or complex object graphs
     */
    buildQueryString(params: Record<string, any>, prefix?: string) {
        const str: string[] = [];
        Object.entries(params).forEach(([key, val]) => {
            const k = prefix ? `${prefix}[${key}]` : key;
            const encoded = isObject(val) ? this.buildQueryString(val, k) : `${k}=${encodeURIComponent(val)}`;
            str.push(encoded);
        });
        return str.join('&');
    }

    /**
     * Parses raw query string parameters
     */
    // eslint-disable-next-line class-methods-use-this
    parseQueryString(searchString: string) {
        const queryString = searchString.substring(1);
        const params: Record<string, string> = {};
        if (queryString) {
            const pairs = queryString.split('&');
            pairs.forEach(pair => {
                if (pair === '' || typeof pair === 'function') {
                    return;
                }
                const [key, val] = pair.split('=');
                params[decodeURIComponent(key)] = decodeURIComponent(val);
            });
        }
        return params;
    }

    /**
     * This is something that can be returned from 'resolve' methods
     * of pages that have restricted access
     */
    validateUser(opts: CustomOptions = {}) {
        let configName = opts.config;

        if (this.dfd == null) {
            const promise = this.initDfd();

            // save trip to API if possible. assume that user is still signed
            // in if auth headers are present and token has not expired.
            if (this.getConfig(configName).transport === 'headers' && this.userIsAuthenticated()) {
                // user is still presumably logged in
                this.resolveDfd();
            } else {
                // token querystring is present. user most likely just came from
                // registration email link.
                const params = this.parseQueryString(window.location.search);

                // auth_token matches what is sent with postMessage, but supporting token for
                // backwards compatibility
                const token = params.auth_token || params.token;

                if (token !== undefined) {
                    const clientId = params.client_id;
                    const { uid, expiry } = params;
                    configName = params.config;

                    // use the configuration that was used in creating
                    // the confirmation link
                    this.setConfigName(configName);

                    // check if redirected from password reset link
                    // TODO: check this boolean
                    // @ts-ignore
                    this.mustResetPassword = params.reset_password;

                    // check if redirected from email confirmation link
                    // TODO: check this boolean
                    // @ts-ignore
                    this.firstTimeLogin = params.account_confirmation_success;

                    // check if redirected from auth registration
                    // TODO: check this boolean
                    // @ts-ignore
                    this.oauthRegistration = params.oauth_registration;

                    // persist these values
                    this.setAuthHeaders(this.buildAuthHeaders({ token, clientId, uid, expiry }));

                    // build url base
                    let url = window.location.pathname;

                    // strip token-related qs from url to prevent re-use of these params
                    // on page refresh
                    [
                        'auth_token',
                        'token',
                        'client_id',
                        'uid',
                        'expiry',
                        'config',
                        'reset_password',
                        'account_confirmation_success',
                        'oauth_registration',
                    ].forEach(prop => delete params[prop]);

                    // append any remaining params, if any
                    if (Object.keys(params).length > 0) {
                        url += `?${this.buildQueryString(params)}`;
                    }

                    // redirect to target url
                    this.getConfig(configName).navigate(url);
                } else if (this.retrieveData('currentConfigName')) {
                    // token cookie is present. user is returning to the site, or
                    // has refreshed the page.
                    configName = this.retrieveData('currentConfigName');
                }

                // cookie might not be set, but forcing token validation has
                // been enabled
                if (this.getConfig().forceValidateToken) {
                    this.validateToken({ config: configName });
                } else if (this.getConfig(configName).transport === 'headers' && this.retrieveData('auth_headers')) {
                    // if token has expired, do not verify token with API
                    if (this.tokenHasExpired()) {
                        this.getConfig(configName).broadcast('auth:session-expired');
                        this.rejectDfd({
                            reason: 'unauthorized',
                            errors: ['Session expired.'],
                        });
                    } else {
                        // token has been saved in session var, token has not
                        // expired. must be verified with API.
                        this.validateToken({ config: configName });
                    }
                } else if (this.getConfig(configName).transport === 'cookies') {
                    // Note: We aren't specially handling the "Session expired" case like the headers transport flow.
                    // We don't really need to, the validateToken network call will 401 and trigger our re-authentication logic.
                    // The reason it makes sense to specially handle it in the headers transport flow is because you can save a network request.
                    this.validateToken({ config: configName });
                } else {
                    // new user session. will redirect to login
                    this.rejectDfd({
                        reason: 'unauthorized',
                        errors: ['No credentials'],
                    });
                    this.getConfig(configName).broadcast('auth:invalid');
                }
            }
            return promise;
        }

        return this.dfd.promise;
    }

    /**
     * Confirm that user's auth token is still valid.
     */
    validateToken<TData>(opts: CustomOptions = {}) {
        if (!this.tokenHasExpired()) {
            const config = this.getConfig(opts.config);
            return this.http<TData>(this.apiUrl(opts.config) + config.tokenValidationPath).then(
                resp => {
                    const authData = config.handleTokenValidationResponse(resp.data);
                    this.handleValidAuth(authData);

                    // broadcast event for first time login
                    if (this.firstTimeLogin) {
                        config.broadcast('auth:email-confirmation-success', this.user);
                    }

                    if (this.oauthRegistration) {
                        config.broadcast('auth:oauth-registration', this.user);
                    }

                    if (this.mustResetPassword) {
                        config.broadcast('auth:password-reset-confirm-success', this.user);
                    }

                    config.broadcast('auth:validation-success', this.user);

                    return resp;
                },
                resp => {
                    // broadcast event for first time login failure
                    if (this.firstTimeLogin) {
                        config.broadcast('auth:email-confirmation-error', resp.data);
                    }

                    if (this.mustResetPassword) {
                        config.broadcast('auth:password-reset-confirm-error', resp.data);
                    }

                    config.broadcast('auth:validation-error', resp.data);

                    // No data is no response, no response is no connection. Token cannot be destroyed if no connection
                    const invalidateTokens = resp.status > 0;

                    return this.rejectDfd(
                        {
                            reason: 'unauthorized',
                            errors: resp.data ? resp.data.errors : ['Unspecified error'],
                        },
                        invalidateTokens,
                    );
                },
            );
        }
        return this.rejectDfd({
            reason: 'unauthorized',
            errors: ['Expired credentials'],
        });
    }

    /**
     * Ensure token has not expired
     */
    tokenHasExpired() {
        const expiry = this.getExpiry();
        const now = new Date().getTime();

        return expiry !== null && expiry < now;
    }

    /**
     * Get expiry by method provided in config
     */
    getExpiry() {
        return this.getConfig().parseExpiry(this.retrieveData('auth_headers') || {});
    }

    /**
     * This service attempts to cache auth tokens, but sometimes we
     * will want to discard saved tokens. examples include:
     * 1. login failure
     * 2. token validation failure
     * 3. user logs out
     */
    invalidateTokens() {
        // cannot delete user object for scoping reasons. instead, delete
        // all keys on object.
        // eslint-disable-next-line no-restricted-syntax,guard-for-in
        for (const key in this.user) {
            delete this.user[key];
        }

        // remove any assumptions about current configuration
        this.deleteData('currentConfigName');

        if (this.timer != null) {
            window.clearInterval(this.timer);
        }

        // kill cookies, otherwise session will resume on page reload
        // setting this value to null will force the validateToken method
        // to re-validate credentials with api server when validate is called
        return this.deleteData('auth_headers');
    }

    /**
     * Destroy auth token on server, destroy user auth credentials
     */
    signOut<TData>(opts: CustomOptions = {}) {
        const config = this.getConfig(opts.config);
        return this.http<TData>(this.apiUrl(opts.config) + config.signOutUrl, { method: 'DELETE' }).then(
            resp => {
                this.invalidateTokens();
                config.broadcast('auth:logout-success');
                return resp;
            },
            resp => {
                this.invalidateTokens();
                config.broadcast('auth:logout-error', resp.data);
                throw resp;
            },
        );
    }

    /**
     * Handle successful authentication
     */
    handleValidAuth(user: Record<string, any>, setHeaders = false) {
        // cancel any pending postMessage checks
        if (setHeaders == null) {
            setHeaders = false;
        }
        if (this.requestCredentialsPollingTimer != null) {
            window.clearTimeout(this.requestCredentialsPollingTimer);
        }

        // cancel any inAppBrowser listeners
        this.cancelOmniauthInAppBrowserListeners?.();

        // must extend existing object for scoping reasons
        Object.assign(this.user, user);

        // add shortcut to determine user auth status
        this.user.signedIn = true;
        this.user.configName = this.getCurrentConfigName();

        // postMessage will not contain header. must save headers manually.
        if (setHeaders) {
            this.setAuthHeaders(
                this.buildAuthHeaders({
                    token: this.user.auth_token,
                    clientId: this.user.client_id,
                    uid: this.user.uid,
                    expiry: this.user.expiry,
                }),
            );
        }

        // fulfill promise
        return this.resolveDfd();
    }

    /**
     * Configure auth token format
     */
    buildAuthHeaders(ctx: Record<string, string>, opts: CustomOptions = {}) {
        const headers: Record<string, string> = {};

        const tokenFormat = this.getConfig(opts.config).tokenFormat;
        Object.entries(tokenFormat).forEach(([key, val]) => {
            headers[key] = interpolate(val, ctx);
        });

        return headers as AuthHeaders;
    }

    /**
     * Abstract persistent data store
     */
    persistData(key: string, val: any, configName?: string) {
        const { storage, transport, cookieOps } = this.getConfig(configName);

        if (transport === 'cookies') {
            return undefined;
        }

        if (storage instanceof Object) {
            return storage.persistData(key, val);
        }

        switch (storage) {
            case 'localStorage':
                return window.localStorage.setItem(key, JSON.stringify(val));
            case 'sessionStorage':
                return window.sessionStorage.setItem(key, JSON.stringify(val));
            default:
                return Cookies.set(key, val, cookieOps);
        }
    }

    /**
     * Abstract persistent data retrieval
     */
    retrieveData(key: string) {
        const { storage, transport } = this.getConfig();

        if (transport === 'cookies') {
            return undefined;
        }

        try {
            if (storage instanceof Object) {
                return storage.retrieveData(key);
            }
            switch (storage) {
                case 'localStorage':
                    return JSON.parse(window.localStorage.getItem(key) || 'null');
                case 'sessionStorage':
                    return JSON.parse(window.sessionStorage.getItem(key) || 'null');
                default:
                    return JSON.parse(Cookies.get(key) || 'null');
            }
        } catch (e) {
            // gracefully handle if JSON parsing
            if (e instanceof SyntaxError) {
                return null;
            }
            throw e;
        }
    }

    /**
     * Abstract persistent data removal
     */
    deleteData(key: string) {
        const { storage, transport, cookieOps } = this.getConfig();

        if (transport === 'cookies') {
            return undefined;
        }

        if (storage instanceof Object) {
            storage.deleteData(key);
        }

        switch (storage) {
            case 'localStorage':
                return window.localStorage.removeItem(key);
            case 'sessionStorage':
                return window.sessionStorage.removeItem(key);
            default: {
                const options: Record<string, any> = { path: cookieOps.path };

                if (cookieOps.domain !== undefined) {
                    options.domain = cookieOps.domain;
                }

                return Cookies.remove(key, options);
            }
        }
    }

    /**
     * Persist authentication token, client id, expiry, uid
     */
    setAuthHeaders(headers: AuthHeaders) {
        const newHeaders = {
            ...(this.retrieveData('auth_headers') || {}),
            ...headers,
        };
        this.persistData('auth_headers', newHeaders);

        const expiry = this.getExpiry();
        const now = new Date().getTime();

        if (expiry && expiry > now) {
            if (this.timer != null) {
                window.clearInterval(this.timer);
            }

            this.timer = window.setInterval(
                () => this.validateUser({ config: this.getSavedConfig() }),
                expiry - now,
            );
        }
    }

    /**
     * Init a ES6 style promise deferred object
     */
    initDfd<TData>() {
        let resolve: any, reject: any
        const promise = new Promise<TData>((_resolve, _reject) => {
            resolve = _resolve
            reject = _reject
        });
        this.dfd = {
            promise,
            resolve,
            reject,
        };
        return this.dfd.promise as Promise<TData>;
    }

    /**
     * Failed login => invalidate auth header and reject promise.
     * deferred object must be destroyed after reflow.
     */
    rejectDfd(reason?: RejectOptions, invalidateTokens = true) {
        if (invalidateTokens) {
            this.invalidateTokens();
        }

        if (this.dfd != null) {
            this.dfd.reject(reason);

            // must nullify after reflow so promises can be rejected
            return new Promise(resolve => {
                window.setTimeout(() => {
                    this.dfd = null;
                    resolve(null);
                });
            });
        }

        return undefined;
    }

    /**
     * Use proxy for IE
     */
    apiUrl(configName?: string) {
        const config = this.getConfig(configName);
        if (config.proxyIf()) {
            return config.proxyUrl;
        }
        return config.apiUrl;
    }

    /**
     * Get config
     */
    getConfig(name?: string) {
        return configs[this.getCurrentConfigName(name)];
    }

    /**
     * If value is a method, call the method. otherwise return the argument itself
     */
    // eslint-disable-next-line class-methods-use-this
    getResultOrValue(arg: any) {
        if (typeof arg === 'function') {
            return arg();
        }
        return arg;
    }

    /**
     * A config name will be return in the following order of precedence:
     * 1. matches arg
     * 2. saved from past authentication
     * 3. first available config name
     */
    getCurrentConfigName(name? : string) {
        return name || this.getSavedConfig();
    }

    /**
     * Can't rely on retrieveData because it will cause a recursive loop
     * if config hasn't been initialized. instead find first available
     * value of 'defaultConfigName'. searches the following places in
     * this priority:
     * 1. localStorage
     * 2. sessionStorage
     * 3. cookies
     * 4. default (first available config)
     */
    getSavedConfig() {
        let c: string | null = null;
        const key = 'currentConfigName';

        if (this.hasLocalStorage() && c == null) {
            c = JSON.parse(window.localStorage.getItem(key) || 'null');
        } else if (this.hasSessionStorage() && c == null) {
            c = JSON.parse(window.sessionStorage.getItem(key) || 'null');
        } else if (c == null) {
            c = Cookies.get(key) || 'null';
        }

        return c || defaultConfigName;
    }

    /**
     * Has SessionStorage available
     */
    hasSessionStorage() {
        if (this._hasSessionStorage == null) {
            this._hasSessionStorage = false;
            // trying to call setItem will
            // throw an error if sessionStorage is disabled
            try {
                window.sessionStorage.setItem('DeviceTokenAuthClient-test', 'DeviceTokenAuthClient-test');
                window.sessionStorage.removeItem('DeviceTokenAuthClient-test');
                this._hasSessionStorage = true;
            } catch (error) {
                this._hasSessionStorage = false;
            }
        }

        return this._hasSessionStorage;
    }

    /**
     * Has LocalStorage available
     */
    hasLocalStorage() {
        if (this._hasLocalStorage == null) {
            this._hasLocalStorage = false;
            // trying to call setItem will
            // throw an error if localStorage is disabled
            try {
                window.localStorage.setItem('DeviceTokenAuthClient-test', 'DeviceTokenAuthClient-test');
                window.localStorage.removeItem('DeviceTokenAuthClient-test');
                this._hasLocalStorage = true;
            } catch (error) {
                this._hasLocalStorage = false;
            }
        }

        return this._hasLocalStorage;
    }
}
