# OAuth 2.0 Client for Ansible Tower / AWX
Based on:
[![Source Code](http://img.shields.io/badge/source-thephpleague/oauth2--client-blue.svg?style=flat-square)](https://github.com/thephpleague/oauth2-client)
---
### Resource Owner Password Credentials Grant

According to [section 1.3.3](http://tools.ietf.org/html/rfc6749#section-1.3.3) of the OAuth 2.0 standard (emphasis added):

> The credentials **should only be used when there is a high degree of trust**
> between the resource owner and the client (e.g., the client is part of the
> device operating system or a highly privileged application), and when other
> authorization grant types are not available (such as an authorization code).

#### EXAMPLE

``` php

$provider = new \Awx\OAuth2\Client\Provider\GenericProvider([
    // The client given in AWX when you create an application with authorization grant type "Resource owner password-based
    'clientId'                => AWX_CLIENT_ID,
    'clientSecret'            => AWX_CLIENT_SECRET,
    'urlAccessToken'          => 'https://<Ansible Tower IP or URL>/api/o/token/',
    'verify'                  => false, //Set to false for development and true after you obtain SSL certificates
    'urlAuthorize'            => null,
    'urlResourceOwnerDetails' => null,
]);

try {

    // Try to get an access token using the resource owner password credentials grant.
    $accessToken = $provider->getAccessToken('password', [
        'username' => AWX_USERNAME,
        'password' => AWX_PASSWORD
    ]);

} catch (\Awx\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

    // Failed to get the access token
    exit($e->getMessage());

}

// Save $accessToken to your data store.

```

### Authorization Code Grant
The following example uses the out-of-the-box GenericProvider provided by this library. If you're looking for a specific provider (i.e. Facebook, Google, GitHub, etc.), take a look at our list of provider client libraries. HINT: You're probably looking for a specific provider.

The authorization code grant type is the most common grant type used when authenticating users with a third-party service. This grant type utilizes a client (this library), a server (the service provider), and a resource owner (the user with credentials to a protected—or owned—resource) to request access to resources owned by the user. This is often referred to as 3-legged OAuth, since there are three parties involved.

The following example illustrates this using Brent Shaffer's demo OAuth 2.0 application named Lock'd In. When running this code, you will be redirected to Lock'd In, where you'll be prompted to authorize the client to make requests to a resource on your behalf.

Now, you don't really have an account on Lock'd In, but for the sake of this example, imagine that you are already logged in on Lock'd In when you are redirected there.
```php
$provider = new \Awx\OAuth2\Client\Provider\GenericProvider([
    'clientId'                => 'demoapp',    // The client ID assigned to you by the provider
    'clientSecret'            => 'demopass',   // The client password assigned to you by the provider
    'redirectUri'             => 'http://example.com/your-redirect-url/',
    'urlAuthorize'            => 'http://brentertainment.com/oauth2/lockdin/authorize',
    'urlAccessToken'          => 'http://brentertainment.com/oauth2/lockdin/token',
    'urlResourceOwnerDetails' => 'http://brentertainment.com/oauth2/lockdin/resource'
]);

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || (isset($_SESSION['oauth2state']) && $_GET['state'] !== $_SESSION['oauth2state'])) {

    if (isset($_SESSION['oauth2state'])) {
        unset($_SESSION['oauth2state']);
    }
    
    exit('Invalid state');

} else {

    try {

        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo 'Access Token: ' . $accessToken->getToken() . "<br>";
        echo 'Refresh Token: ' . $accessToken->getRefreshToken() . "<br>";
        echo 'Expired in: ' . $accessToken->getExpires() . "<br>";
        echo 'Already expired? ' . ($accessToken->hasExpired() ? 'expired' : 'not expired') . "<br>";

        // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);

        var_export($resourceOwner->toArray());

        // The provider provides a way to get an authenticated API request for
        // the service, using the access token; it returns an object conforming
        // to Psr\Http\Message\RequestInterface.
        $request = $provider->getAuthenticatedRequest(
            'GET',
            'http://brentertainment.com/oauth2/lockdin/resource',
            $accessToken
        );

    } catch (\Awx\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}
```
### Client Credentials Grant

Ansible Tower / AWX does not currently support Client Credentials Grant.  Support is included in this client if it does become available at some time in the future.

When your application is acting on its own behalf to access resources it controls/owns in a service provider, it may use the client credentials grant type. This is best used when the credentials for your application are stored privately and never exposed (e.g. through the web browser, etc.) to end-users. This grant type functions similarly to the resource owner password credentials grant type, but it does not request a user's username or password. It uses only the client ID and secret issued to your client by the service provider.

Unlike earlier examples, the following does not work against a functioning demo service provider. It is provided for the sake of example only.

``` php
// Note: the GenericProvider requires the `urlAuthorize` option, even though
// it's not used in the OAuth 2.0 client credentials grant type.

$provider = new \Awx\OAuth2\Client\Provider\GenericProvider([
    'clientId'                => 'XXXXXX',    // The client ID assigned to you by the provider
    'clientSecret'            => 'XXXXXX',    // The client password assigned to you by the provider
    'redirectUri'             => 'http://my.example.com/your-redirect-url/',
    'urlAuthorize'            => 'http://service.example.com/authorize',
    'urlAccessToken'          => 'http://service.example.com/token',
    'urlResourceOwnerDetails' => 'http://service.example.com/resource'
]);

try {

    // Try to get an access token using the client credentials grant.
    $accessToken = $provider->getAccessToken('client_credentials');

} catch (\Awx\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

    // Failed to get the access token
    exit($e->getMessage());

}
```

### Using a proxy

It is possible to use a proxy to debug HTTP calls made to a provider. All you need to do is set the `proxy` and `verify` options when creating your Provider instance. Make sure you enable SSL proxying in your proxy.

``` php
$provider = new \Awx\OAuth2\Client\Provider\GenericProvider([
    'clientId'                => 'XXXXXX',    // The client ID assigned to you by the provider
    'clientSecret'            => 'XXXXXX',    // The client password assigned to you by the provider
    'redirectUri'             => 'http://my.example.com/your-redirect-url/',
    'urlAuthorize'            => 'http://service.example.com/authorize',
    'urlAccessToken'          => 'http://service.example.com/token',
    'urlResourceOwnerDetails' => 'http://service.example.com/resource',
    'proxy'                   => '192.168.0.1:8888',
    'verify'                  => false
]);
```


### Refreshing a Token

Once your application is authorized, you can refresh an expired token using a refresh token rather than going through the entire process of obtaining a brand new token. To do so, simply reuse this refresh token from your data store to request a refresh.

_This example uses [Brent Shaffer's](https://github.com/bshaffer) demo OAuth 2.0 application named **Lock'd In**. See authorization code example above, for more details._

```php
$provider = new \Awx\OAuth2\Client\Provider\GenericProvider([
    'clientId'                => 'AWX_CLIENT_ID',    // The client ID assigned to you by the provider
    'clientSecret'            => 'AWX_CLIENT_SECRET',   // The client password assigned to you by the provider
    'redirectUri'             => 'http://example.com/your-redirect-url/',
    'urlAuthorize'            => 'http://brentertainment.com/oauth2/lockdin/authorize',
    'urlAccessToken'          => 'http://brentertainment.com/oauth2/lockdin/token',
    'urlResourceOwnerDetails' => 'http://brentertainment.com/oauth2/lockdin/resource'
]);

$existingAccessToken = getAccessTokenFromYourDataStore();

if ($existingAccessToken->hasExpired()) {
    $newAccessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $existingAccessToken->getRefreshToken()
    ]);
    if ($newAccessToken === 'EXPIRED_REFRESH_TOKEN') {

        // Try get access token using the resource owner password credentials grant.
        $accessToken = $provider->getAccessToken('password', [
            'username' => AWX_USERNAME,
            'password' => AWX_PASSWORD,
        ]);

        // Purge old tokens and store new access token to your data store.
    }
}
```


## Install

Add the following to your composer.json

``` json
"require": {
    "sdwru/oauth2-awx": "dev-master"
},
"repositories": [
    { "type": "git", "url": "https://github.com/sdwru/oauth2-awx.git" }
],
```

## Contributing

Please see [CONTRIBUTING](https://github.com/sdwru/oauth2-awx/blob/master/CONTRIBUTING.md) for details.

## License

The MIT License (MIT). Please see [License File](https://github.com/sdwru/oauth2-awx/blob/master/LICENSE) for more information.


[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
[PSR-7]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md
