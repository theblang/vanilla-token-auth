# Vanilla Token Auth

A decaffeinated de-angularized drop-in replacement for [ng-token-auth](https://github.com/lynndylanhurley/ng-token-auth). Supports cookie transport added in [this `devise_token_auth` PR](https://github.com/lynndylanhurley/devise_token_auth/pull/1453).

`npm i vanilla-token-auth`

---

## Using cookie transport

If you want to use cookie transport with `devise_token_auth` for the token (instead of using headers/localStorage), specify `transport = 'cookies'` and `storage = undefined` in the config.

## Wiring into an existing networking library

Make use of the `httpWrapper` config, which should be a fetch-like wrapper around your networking library. [See examples below](#httpwrapper-examples).

## Wiring into AngularJS

If you still need to support AngularJS with this library, then in addition to `httpWrapper`, you can make use of the `broadcast` and `navigate` config callbacks to wrap `$broadcast` and routing.

If you still need to use the header interceptor logic from `ng-token-auth`, see this sample AngularJS module that wraps an instance of `DeviseTokenAuthClient` and uses [this ng-token-auth logic](https://github.com/theblang/vanilla-token-auth/blob/main/ng-token-auth.js#L1029):

```
angular
    .module('DeviseTokenAuthClient', [])
    .factory('ngDeviseTokenAuthClient', [
        '$injector',
        $injector => {
            return new DeviseTokenAuthClient({
                // config
            });
        },
    ])
    .config([
        '$httpProvider',
        $httpProvider => {
            // responses are sometimes returned out of order. check that response is
            // current before saving the auth data.
            function tokenIsCurrent(ngDeviseTokenAuthClient, headers) {
                const oldTokenExpiry = Number(ngDeviseTokenAuthClient.getExpiry());
                const newTokenExpiry = Number(ngDeviseTokenAuthClient.getConfig().parseExpiry(headers || {}));

                return newTokenExpiry >= oldTokenExpiry;
            }

            // uniform handling of response headers for success or error conditions
            function updateHeadersFromResponse(ngDeviseTokenAuthClient, resp) {
                const newHeaders = {};
                const tokenFormat = ngDeviseTokenAuthClient.getConfig().tokenFormat;
                Object.keys(tokenFormat).forEach(key => {
                    if (resp.headers(key)) {
                        newHeaders[key] = resp.headers(key);
                    }
                });

                if (tokenIsCurrent(ngDeviseTokenAuthClient, newHeaders)) {
                    ngDeviseTokenAuthClient.setAuthHeaders(newHeaders);
                }
            }

            // this is ugly...
            // we need to configure an interceptor (must be done in the configuration
            // phase), but we need access to the $http service, which is only available
            // during the run phase. the following technique was taken from this
            // stackoverflow post:
            // http://stackoverflow.com/questions/14681654/i-need-two-instances-of-angularjs-http-service-or-what
            $httpProvider.interceptors.push([
                '$injector',
                $injector => ({
                    request(req) {
                        $injector.invoke([
                            '$http',
                            'ngDeviseTokenAuthClient',
                            // eslint-disable-next-line consistent-return
                            function onRequest($http, ngDeviseTokenAuthClient) {
                                if (req.url.match(ngDeviseTokenAuthClient.apiUrl())) {
                                    return (() => {
                                        const result = [];
                                        const object = ngDeviseTokenAuthClient.retrieveData('auth_headers') || {};
                                        Object.keys(object).forEach(key => {
                                            result.push((req.headers[key] = object[key]));
                                        });
                                        return result;
                                    })();
                                }
                            },
                        ]);

                        return req;
                    },

                    response(resp) {
                        $injector.invoke([
                            '$http',
                            'ngDeviseTokenAuthClient',
                            // eslint-disable-next-line consistent-return
                            function onResponse($http, ngDeviseTokenAuthClient) {
                                if (resp.config.url.match(ngDeviseTokenAuthClient.apiUrl())) {
                                    return updateHeadersFromResponse(ngDeviseTokenAuthClient, resp);
                                }
                            },
                        ]);

                        return resp;
                    },

                    responseError(resp) {
                        $injector.invoke([
                            '$http',
                            'ngDeviseTokenAuthClient',
                            // eslint-disable-next-line consistent-return
                            function onResponseError($http, ngDeviseTokenAuthClient) {
                                if (
                                    resp &&
                                    resp.config &&
                                    resp.config.url &&
                                    resp.config.url.match(ngDeviseTokenAuthClient.apiUrl())
                                ) {
                                    return updateHeadersFromResponse(ngDeviseTokenAuthClient, resp);
                                }
                            },
                        ]);

                        return $injector.get('$q').reject(resp);
                    },
                }),
            ]);

            // define http methods that may need to carry auth headers
            const httpMethods = ['get', 'post', 'put', 'patch', 'delete'];

            // disable IE ajax request caching for each of the necessary http methods
            httpMethods.forEach(method => {
                if ($httpProvider.defaults.headers[method] == null) {
                    $httpProvider.defaults.headers[method] = {};
                }
                $httpProvider.defaults.headers[method]['If-Modified-Since'] = 'Mon, 26 Jul 1997 05:00:00 GMT';
            });
        },
    ])
    .run(['ngDeviseTokenAuthClient', ngDeviseTokenAuthClient => ngDeviseTokenAuthClient.initialize()]);
```

## `httpWrapper` examples

- AngularJS `$http`

```
angularModule.factory('ngHttpWrapper', [
    '$injector',
    $injector => {
        const $http = $injector.get('$http');

        // Mimics fetch signature and return value (a native promise), see https://github.com/microsoft/TypeScript/blob/v4.6.3/lib/lib.dom.d.ts#L16450
        /**
         * @param {RequestInfo} input
         * @param {RequestInit} [init]
         * @returns {Promise<Response>}
         */
        return (input, init = {}) => {
            if (typeof input !== 'string') {
                throw new Error('Must pass RequestInfo as a string');
            }

            const method = init.method ? init.method.toUpperCase() : 'GET';
            const body = init.body && JSON.parse(init.body);

            let qPromise;

            switch (method) {
                case 'GET':
                    qPromise = $http.get(input);
                    break;
                case 'POST':
                    qPromise = $http.post(input, body);
                    break;
                case 'PUT':
                    qPromise = $http.put(input, body);
                    break;
                case 'DELETE':
                    qPromise = $http.delete(input);
                    break;
                case 'PATCH':
                    throw new Error('Not implemented');
                default:
                    throw new Error(`Request method "${method}" is not supported`);
            }

            return new Promise((resolve, reject) => {
                qPromise
                    .then(response => {
                        resolve(
                            new Response(JSON.stringify(response.data), {
                                status: response.status,
                                statusText: response.statusText,
                            }),
                        );
                    })
                    .catch(error => {
                        reject(error);
                    });
            });
        };
    },
]);
```

- RTK Query

```
// Mimics fetch signature and return value (a native promise), see https://github.com/microsoft/TypeScript/blob/v4.6.3/lib/lib.dom.d.ts#L16450
export const rtkQueryHttpWrapper = async (input: RequestInfo, init: RequestInit = {}): Promise<Response> => {
    const response = await storeProvider.store!.dispatch(
        createApiObject.endpoints.dynamicEndpoint.initiate({ input, init }),
    );

    if (response.status === 'rejected') {
        throw response.error;
    }

    return new Response(JSON.stringify(response.data));
};
export default rtkQueryHttpWrapper;
```