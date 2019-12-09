<?php
require "../bootstrap.php";

use Src\Controllers\CustomerController;

// send some CORS headers so the API can be called from anywhere
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: OPTIONS,GET,POST,PUT,DELETE");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$requestMethod = $_SERVER["REQUEST_METHOD"];
$uriParts = explode( '/', $uri );

// define all valid endpoints - this will act as a simple router
$routes = [
    'customers' => [
        'method' => 'GET',
        'expression' => '/^\/customers\/?$/',
        'controller_method' => 'index'
    ],
    'customers.create' => [
        'method' => 'POST',
        'expression' => '/^\/customers\/?$/',
        'controller_method' => 'store'
    ],
    'customers.charge' => [
        'method' => 'POST',
        'expression' => '/^\/customers\/(\d+)\/charges\/?$/',
        'controller_method' => 'charge'
    ]
];

$routeFound = null;
foreach ($routes as $route) {
    if ($route['method'] == $requestMethod &&
        preg_match($route['expression'], $uri))
    {
        $routeFound = $route;
        break;
    }
}

if (! $routeFound) {
    header("HTTP/1.1 404 Not Found");
    exit();
}

$methodName = $route['controller_method'];

// authenticate the request:
if (! authenticate($methodName)) {
    header("HTTP/1.1 401 Unauthorized");
    exit('Unauthorized');
}

$controller = new CustomerController();
$controller->$methodName($uriParts);

// END OF FRONT CONTROLLER
// OAuth authentication functions follow

function authenticate($methodName)
{
    // extract the token from the headers
    if (! isset($_SERVER['HTTP_AUTHORIZATION'])) {
        return false;
    }

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
    preg_match('/Bearer\s(\S+)/', $authHeader, $matches);

    if(! isset($matches[1])) {
        return false;
    }

    $token = $matches[1];

    // decode the token
    $tokenParts = explode('.', $token);
    $decodedToken['header'] = json_decode(base64UrlDecode($tokenParts[0]), true);
    $decodedToken['payload'] = json_decode(base64UrlDecode($tokenParts[1]), true);
    $decodedToken['signatureProvided'] = base64UrlDecode($tokenParts[2]);

    // validate the token
    if ($methodName == 'charge') {
        return authenticateRemotely($token);
    } else {
        return authenticateLocally($decodedToken, $tokenParts);
    }
}

function authenticateRemotely($token)
{
    $metadataUrl = getenv('OKTA_ISSUER') . '/.well-known/oauth-authorization-server';
    $metadata = http($metadataUrl);
    $introspectionUrl = $metadata['introspection_endpoint'];

    $params = [
        'token' => $token,
        'client_id' => getenv('OKTA_SERVICE_APP_ID'),
        'client_secret' => getenv('OKTA_SERVICE_APP_SECRET')
    ];

    $result = http($introspectionUrl, $params);

    if (! $result['active']) {
        return false;
    }

    return true;
}

function authenticateLocally($decodedToken, $tokenParts)
{
    // first, check the items that can be verified without the Web keys:

    // 1. expiration time
    $tokenExpirationTime = $decodedToken['payload']['exp'];
    $now = time();

    if ($tokenExpirationTime < $now) {
        return false;
    }

    // 2. Issuer
    $tokenIssuer = $decodedToken['payload']['iss'];

    if ($tokenIssuer != getenv('OKTA_ISSUER')) {
        return false;
    }

    // 3. Audience
    $tokenAudience = $decodedToken['payload']['aud'];

    if ($tokenAudience != getenv('OKTA_AUDIENCE')) {
        return false;
    }

    // 4. Client ID
    $tokenClientId = $decodedToken['payload']['cid'];

    if ($tokenClientId != getenv('OKTA_CLIENT_ID')) {
        return false;
    }

    // Then, get the JSON Web Keys
    // (they should be cached to avoid
    // calls to Okta on each API request)...
    $metadataUrl = getenv('OKTA_ISSUER') . '/.well-known/oauth-authorization-server';
    $metadata = http($metadataUrl);
    $jwksUri = $metadata['jwks_uri'];
    $keys = http($jwksUri)['keys'][0];

    // ...and verify the parts that need the keys:

    // 5. Key ID ('kid' claim)
    $tokenKid = $decodedToken['header']['kid'];

    if ($tokenKid != $keys['kid']) {
        return false;
    }

    // 6. Signing algorithm
    $tokenAlgorithm = $decodedToken['header']['alg'];

    if ($tokenAlgorithm != $keys['alg']) {
        return false;
    }

    // 7. Signature verification
    $header = $tokenParts[0];
    $payload = $tokenParts[1];
    $message = $header . '.' . $payload;
    $tokenSignature = $decodedToken['signatureProvided'];
    $publicKey = createPemFromModulusAndExponent($keys['n'], $keys['e']);

    // hardcoded to OpenSSL:SHA256 which correspondes to 'RS256'
    // might need to change to hash_hmac depending on $keys['alg']
    $result = openssl_verify($message, $tokenSignature, $publicKey, OPENSSL_ALGO_SHA256);

    if (! $result) {
        return false;
    }

    return true;
}

function http($url, $params = null)
{
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    if ($params) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    }
    return json_decode(curl_exec($ch), true);
}

function createPemFromModulusAndExponent($n, $e)
{
    $modulus = base64UrlDecode($n);
    $publicExponent = base64UrlDecode($e);

    $components = [
        'modulus' => pack('Ca*a*', 2, encodeLength(strlen($modulus)), $modulus),
        'publicExponent' => pack('Ca*a*', 2, encodeLength(strlen($publicExponent)), $publicExponent)
    ];

    $RSAPublicKey = pack(
        'Ca*a*a*',
        48,
        encodeLength(strlen($components['modulus']) + strlen($components['publicExponent'])),
        $components['modulus'],
        $components['publicExponent']
    );

    // hex version of MA0GCSqGSIb3DQEBAQUA
    $rsaOID = pack('H*', '300d06092a864886f70d0101010500');
    $RSAPublicKey = chr(0) . $RSAPublicKey;
    $RSAPublicKey = chr(3) . encodeLength(strlen($RSAPublicKey)) . $RSAPublicKey;
    $RSAPublicKey = pack(
        'Ca*a*',
        48,
        encodeLength(strlen($rsaOID . $RSAPublicKey)),
        $rsaOID . $RSAPublicKey
    );

    $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
            chunk_split(base64_encode($RSAPublicKey), 64) .
            '-----END PUBLIC KEY-----';

    return $RSAPublicKey;
}

function base64UrlDecode($input)
{
    $remainder = strlen($input) % 4;
    if ($remainder) {
        $padlen = 4 - $remainder;
        $input .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($input, '-_', '+/'));
}

function encodeLength($length)
{
    if ($length <= 0x7F) {
        return chr($length);
    }
    $temp = ltrim(pack('N', $length), chr(0));
    return pack('Ca*', 0x80 | strlen($temp), $temp);
}

function base64UrlEncode($text)
{
    return str_replace(
        ['+', '/', '='],
        ['-', '_', ''],
        base64_encode($text)
    );
}
