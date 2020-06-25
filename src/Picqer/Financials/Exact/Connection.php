<?php

namespace Picqer\Financials\Exact;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

/**
 * Class Connection.
 */
class Connection
{
    /**
     * @var string
     */
    private $baseUrl = 'https://start.exactonline.nl';

    /**
     * @var string
     */
    private $apiUrl = '/api/v1';

    /**
     * @var string
     */
    private $authUrl = '/api/oauth2/auth';

    /**
     * @var string
     */
    private $tokenUrl = '/api/oauth2/token';

    /**
     * @var mixed
     */
    private $exactClientId;

    /**
     * @var mixed
     */
    private $exactClientSecret;

    /**
     * @var mixed
     */
    private $authorizationCode;

    /**
     * @var mixed
     */
    private $accessToken;

    /**
     * @var int the Unix timestamp at which the access token expires
     */
    private $tokenExpires;

    /**
     * @var mixed
     */
    private $refreshToken;

    /**
     * @var mixed
     */
    private $redirectUrl;

    /**
     * @var mixed
     */
    private $division;

    /**
     * @var Client|null
     */
    private $client;

    /**
     * @var callable(Connection)
     */
    private $tokenUpdateCallback;

    /**
     * @var callable(Connection)
     */
    private $acquireAccessTokenLockCallback;

    /**
     * @var callable(Connection)
     */
    private $acquireAccessTokenUnlockCallback;

    /**
     * @var callable[]
     */
    protected $middleWares = [];

    /**
     * @var string|null
     */
    public $nextUrl = null;

    /**
     * @var int|null
     */
    protected $dailyLimit;

    /**
     * @var int|null
     */
    protected $dailyLimitRemaining;

    /**
     * @var int|null
     */
    protected $dailyLimitReset;

    /**
     * @var int|null
     */
    protected $minutelyLimit;

    /**
     * @var int|null
     */
    protected $minutelyLimitRemaining;

    /**
     * @var mixed
     */
    private $batch = [];

    /**
     * @return Client
     */
    private function client()
    {
        if ($this->client) {
            return $this->client;
        }

        $handlerStack = HandlerStack::create();
        foreach ($this->middleWares as $middleWare) {
            $handlerStack->push($middleWare);
        }

        $this->client = new Client([
            'http_errors' => true,
            'handler'     => $handlerStack,
            'expect'      => false,
        ]);

        return $this->client;
    }

    /**
     * Insert a custom Guzzle client.
     *
     * @param Client $client
     */
    public function setClient($client)
    {
        $this->client = $client;
    }

    /**
     * Insert a Middleware for the Guzzle Client.
     *
     * @param $middleWare
     */
    public function insertMiddleWare($middleWare)
    {
        $this->middleWares[] = $middleWare;
    }

    /**
     * @throws ApiException
     *
     * @return Client
     */
    public function connect()
    {
        // Redirect for authorization if needed (no access token or refresh token given)
        if ($this->needsAuthentication()) {
            $this->redirectForAuthorization();
        }

        // If access token is not set or token has expired, acquire new token
        if (empty($this->accessToken) || $this->tokenHasExpired()) {
            $this->acquireAccessToken();
        }

        $client = $this->client();

        return $client;
    }

    /**
     * @param string $method
     * @param string $endpoint
     * @param mixed  $body
     * @param array  $params
     * @param array  $headers
     *
     * @return Request
     */
    private function createRequest($method, $endpoint, $body = null, array $params = [], array $headers = [])
    {
        // Add default json headers to the request
        $headers = array_merge($headers, [
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
            'Prefer'       => 'return=representation',
        ]);

        // If access token is not set or token has expired, acquire new token
        if (empty($this->accessToken) || $this->tokenHasExpired()) {
            $this->acquireAccessToken();
        }

        // If we have a token, sign the request
        if (! $this->needsAuthentication() && ! empty($this->accessToken)) {
            $headers['Authorization'] = 'Bearer ' . $this->accessToken;
        }

        // Create param string
        if (! empty($params)) {
            $endpoint .= '?' . http_build_query($params);
        }

        // Create the request
        $request = new Request($method, $endpoint, $headers, $body);

        return $request;
    }

    /**
     * @param string $url
     * @param array  $params
     * @param array  $headers
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function get($url, array $params = [], array $headers = [])
    {
        $url = $this->formatUrl($url, $url !== 'current/Me', $url == $this->nextUrl);

        try {
            $request = $this->createRequest('GET', $url, null, $params, $headers);
            $response = $this->client()->send($request);

            return $this->parseResponse($response, $url != $this->nextUrl);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }

    /**
     * @param string $url
     * @param array  $params
     * @param array  $headers
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function batchGet($url, array $params = [], array $headers = [], $callbacks = null, $item = null, $metaData = null)
    {
        $batchEndPoint = substr($url, 0, strpos($url, "/"));
        $url = $this->formatUrl($url, $url !== 'current/Me', $url == $this->nextUrl);

        try {
            $request = $this->createRequest('GET', $url, null, $params, $headers);

            $batch = new \stdClass();
            $batch->request = $request;
            $batch->callbacks = $callbacks;
            $batch->item = $item;
            $batch->metaData = $metaData;

            $this->addBatchRequestDataToBatch($batchEndPoint, $batch);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }
    
    /**
     * @param string $url
     * @param mixed  $body
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function post($url, $body)
    {
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('POST', $url, $body);
            $response = $this->client()->send($request);

            return $this->parseResponse($response);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }

    /**
     * @param string $url
     * @param mixed  $body
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function batchPost($url, $body, $callbacks = null, $item = null, $metaData = null)
    {
        $batchEndPoint = substr($url, 0, strpos($url, "/"));
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('POST', $url, $body);

            $batch = new \stdClass();
            $batch->request = $request;
            $batch->callbacks = $callbacks;
            $batch->item = $item;
            $batch->metaData = $metaData;

            $this->addBatchRequestDataToBatch($batchEndPoint, $batch);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }
    
    /**
     * @param string $url
     * @param mixed  $body
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function put($url, $body)
    {
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('PUT', $url, $body);
            $response = $this->client()->send($request);

            return $this->parseResponse($response);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }

    /**
     * @param string $url
     * @param mixed  $body
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function batchPut($url, $body, $callbacks = null, $item = null, $metaData = null)
    {
        $batchEndPoint = substr($url, 0, strpos($url, "/"));
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('PUT', $url, $body);

            $batch = new \stdClass();
            $batch->request = $request;
            $batch->callbacks = $callbacks;
            $batch->item = $item;
            $batch->metaData = $metaData;

            $this->addBatchRequestDataToBatch($batchEndPoint, $batch);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }
    
    /**
     * @param string $url
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function delete($url)
    {
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('DELETE', $url);
            $response = $this->client()->send($request);

            return $this->parseResponse($response);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }

    /**
     * @param string $url
     *
     * @throws ApiException
     *
     * @return mixed
     */
    public function batchDelete($url, $callbacks = null, $item = null, $metaData = null)
    {
        $batchEndPoint = substr($url, 0, strpos($url, "/"));
        $url = $this->formatUrl($url);

        try {
            $request = $this->createRequest('DELETE', $url);

            $batch = new \stdClass();
            $batch->request = $request;
            $batch->callbacks = $callbacks;
            $batch->item = $item;
            $batch->metaData = $metaData;

            $this->addBatchRequestDataToBatch($batchEndPoint, $batch);
        } catch (Exception $e) {
            $this->parseExceptionForErrorMessages($e);
        }
    }
    
    private function addBatchRequestDataToBatch($batchEndPoint, $batchRequestData)
    {
        //$endpoint = $this->formatUrl('logistics/$batch');
        //$endpoint = $this->formatUrl('crm/$batch');
        //$endpoint = $this->formatUrl('cashflow/$batch');
        if (!in_array($batchEndPoint, ['logistics', 'crm', 'cashflow', 'purchaseorder', 'salesinvoice'])) {
            throw new ApiException("Unkown batch endpoint: " . $batchEndPoint . " in " . __class__ . "::" . __FUNCTION__);
        }
        if (!array_key_exists($batchEndPoint, $this->batch)) {
            $this->batch[$batchEndPoint] = [];
        }
        $this->batch[$batchEndPoint][] = $batchRequestData;
    }
    
    /**
     * @return string
     */
    public function getAuthUrl()
    {
        return $this->baseUrl . $this->authUrl . '?' . http_build_query([
            'client_id'     => $this->exactClientId,
            'redirect_uri'  => $this->redirectUrl,
            'response_type' => 'code',
        ]);
    }

    /**
     * @param mixed $exactClientId
     */
    public function setExactClientId($exactClientId)
    {
        $this->exactClientId = $exactClientId;
    }

    /**
     * @param mixed $exactClientSecret
     */
    public function setExactClientSecret($exactClientSecret)
    {
        $this->exactClientSecret = $exactClientSecret;
    }

    /**
     * @param mixed $authorizationCode
     */
    public function setAuthorizationCode($authorizationCode)
    {
        $this->authorizationCode = $authorizationCode;
    }

    /**
     * @param mixed $accessToken
     */
    public function setAccessToken($accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * @param mixed $refreshToken
     */
    public function setRefreshToken($refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    public function redirectForAuthorization()
    {
        $authUrl = $this->getAuthUrl();
        header('Location: ' . $authUrl);
        exit;
    }

    /**
     * @param mixed $redirectUrl
     */
    public function setRedirectUrl($redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;
    }

    /**
     * @return bool
     */
    public function needsAuthentication()
    {
        return empty($this->refreshToken) && empty($this->authorizationCode);
    }

    /**
     * @param Response $response
     * @param bool     $returnSingleIfPossible
     *
     * @throws ApiException
     *
     * @return mixed
     */
    private function parseResponse(Response $response, $returnSingleIfPossible = true)
    {
        try {
            if ($response->getStatusCode() === 204) {
                return [];
            }

            $this->extractRateLimits($response);

            Psr7\rewind_body($response);
            $json = json_decode($response->getBody()->getContents(), true);
            if (false === is_array($json)) {
                throw new ApiException('Json decode failed. Got response: ' . $response->getBody()->getContents());
            }
            if (array_key_exists('d', $json)) {
                if (array_key_exists('__next', $json['d'])) {
                    $this->nextUrl = $json['d']['__next'];
                } else {
                    $this->nextUrl = null;
                }

                if (array_key_exists('results', $json['d'])) {
                    if ($returnSingleIfPossible && count($json['d']['results']) == 1) {
                        return $json['d']['results'][0];
                    }

                    return $json['d']['results'];
                }

                return $json['d'];
            }

            return $json;
        } catch (\RuntimeException $e) {
            throw new ApiException($e->getMessage());
        }
    }

    /**
     * @return mixed
     */
    private function getCurrentDivisionNumber()
    {
        if (empty($this->division)) {
            $me = new Me($this);
            $this->division = $me->find()->CurrentDivision;
        }

        return $this->division;
    }

    /**
     * @return mixed
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * @return mixed
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    private function acquireAccessToken()
    {
        try {
            if (is_callable($this->acquireAccessTokenLockCallback)) {
                call_user_func($this->acquireAccessTokenLockCallback, $this);
            }

            // If refresh token not yet acquired, do token request
            if (empty($this->refreshToken)) {
                $body = [
                    'form_params' => [
                        'redirect_uri'  => $this->redirectUrl,
                        'grant_type'    => 'authorization_code',
                        'client_id'     => $this->exactClientId,
                        'client_secret' => $this->exactClientSecret,
                        'code'          => $this->authorizationCode,
                    ],
                ];
            } else { // else do refresh token request
                $body = [
                    'form_params' => [
                        'refresh_token' => $this->refreshToken,
                        'grant_type'    => 'refresh_token',
                        'client_id'     => $this->exactClientId,
                        'client_secret' => $this->exactClientSecret,
                    ],
                ];
            }

            $response = $this->client()->post($this->getTokenUrl(), $body);

            Psr7\rewind_body($response);
            $body = json_decode($response->getBody()->getContents(), true);

            if (json_last_error() === JSON_ERROR_NONE) {
                $this->accessToken = $body['access_token'];
                $this->refreshToken = $body['refresh_token'];
                $this->tokenExpires = $this->getTimestampFromExpiresIn($body['expires_in']);

                if (is_callable($this->tokenUpdateCallback)) {
                    call_user_func($this->tokenUpdateCallback, $this);
                }
            } else {
                throw new ApiException('Could not acquire tokens, json decode failed. Got response: ' . $response->getBody()->getContents());
            }
        } catch (BadResponseException $ex) {
            throw new ApiException('Could not acquire or refresh tokens [http ' . $ex->getResponse()->getStatusCode() . ']', 0, $ex);
        } finally {
            if (is_callable($this->acquireAccessTokenUnlockCallback)) {
                call_user_func($this->acquireAccessTokenUnlockCallback, $this);
            }
        }
    }

    /**
     * Translates expires_in to a Unix timestamp.
     *
     * @param string $expiresIn number of seconds until the token expires
     *
     * @return int
     */
    private function getTimestampFromExpiresIn($expiresIn)
    {
        if (! ctype_digit($expiresIn)) {
            throw new \InvalidArgumentException('Function requires a numeric expires value');
        }

        return time() + $expiresIn;
    }

    /**
     * @return int the Unix timestamp at which the access token expires
     */
    public function getTokenExpires()
    {
        return $this->tokenExpires;
    }

    /**
     * @param int $tokenExpires the Unix timestamp at which the access token expires
     */
    public function setTokenExpires($tokenExpires)
    {
        $this->tokenExpires = $tokenExpires;
    }

    private function tokenHasExpired()
    {
        if (empty($this->tokenExpires)) {
            return true;
        }

        return ($this->tokenExpires - 60) < time();
    }

    private function formatUrl($endPoint, $includeDivision = true, $formatNextUrl = false)
    {
        if ($formatNextUrl) {
            return $endPoint;
        }

        if ($includeDivision) {
            return implode('/', [
                $this->getApiUrl(),
                $this->getCurrentDivisionNumber(),
                $endPoint,
            ]);
        }

        return implode('/', [
            $this->getApiUrl(),
            $endPoint,
        ]);
    }

    /**
     * @return mixed
     */
    public function getDivision()
    {
        return $this->division;
    }

    /**
     * @param mixed $division
     */
    public function setDivision($division)
    {
        $this->division = $division;
    }

    /**
     * @param callable $callback
     */
    public function setAcquireAccessTokenLockCallback($callback)
    {
        $this->acquireAccessTokenLockCallback = $callback;
    }

    /**
     * @param callable $callback
     */
    public function setAcquireAccessTokenUnlockCallback($callback)
    {
        $this->acquireAccessTokenUnlockCallback = $callback;
    }

    /**
     * @param callable $callback
     */
    public function setTokenUpdateCallback($callback)
    {
        $this->tokenUpdateCallback = $callback;
    }

    /**
     * Parse the reponse in the Exception to return the Exact error messages.
     *
     * @param Exception $e
     *
     * @throws ApiException
     */
    private function parseExceptionForErrorMessages(Exception $e)
    {
        if (! $e instanceof BadResponseException) {
            throw new ApiException($e->getMessage(), 0, $e);
        }

        $response = $e->getResponse();

        $this->extractRateLimits($response);

        Psr7\rewind_body($response);
        $responseBody = $response->getBody()->getContents();
        $decodedResponseBody = json_decode($responseBody, true);

        if (! is_null($decodedResponseBody) && isset($decodedResponseBody['error']['message']['value'])) {
            $errorMessage = $decodedResponseBody['error']['message']['value'];
        } else {
            $errorMessage = $responseBody;
        }

        throw new ApiException('Error ' . $response->getStatusCode() . ': ' . $errorMessage, $response->getStatusCode(), $e);
    }

    /**
     * @return int|null The maximum number of API calls that your app is permitted to make per company, per day
     */
    public function getDailyLimit()
    {
        return $this->dailyLimit;
    }

    /**
     * @return int|null The remaining number of API calls that your app is permitted to make for a company, per day
     */
    public function getDailyLimitRemaining()
    {
        return $this->dailyLimitRemaining;
    }

    /**
     * @return int|null The time at which the rate limit window resets in UTC epoch milliseconds
     */
    public function getDailyLimitReset()
    {
        return $this->dailyLimitReset;
    }

    /**
     * @return int|null The maximum number of API calls that your app is permitted to make per company, per minute
     */
    public function getMinutelyLimit()
    {
        return $this->minutelyLimit;
    }

    /**
     * @return int|null The remaining number of API calls that your app is permitted to make for a company, per minute
     */
    public function getMinutelyLimitRemaining()
    {
        return $this->minutelyLimitRemaining;
    }

    /**
     * @return string
     */
    protected function getBaseUrl()
    {
        return $this->baseUrl;
    }

    /**
     * @return string
     */
    private function getApiUrl()
    {
        return $this->baseUrl . $this->apiUrl;
    }

    /**
     * @return string
     */
    private function getTokenUrl()
    {
        return $this->baseUrl . $this->tokenUrl;
    }

    /**
     * Set base URL for different countries according to
     * https://developers.exactonline.com/#Exact%20Online%20sites.html.
     *
     * @param string $baseUrl
     */
    public function setBaseUrl($baseUrl)
    {
        $this->baseUrl = $baseUrl;
    }

    /**
     * @param string $apiUrl
     */
    public function setApiUrl($apiUrl)
    {
        $this->apiUrl = $apiUrl;
    }

    /**
     * @param string $authUrl
     */
    public function setAuthUrl($authUrl)
    {
        $this->authUrl = $authUrl;
    }

    /**
     * @param string $tokenUrl
     */
    public function setTokenUrl($tokenUrl)
    {
        $this->tokenUrl = $tokenUrl;
    }

    private function extractRateLimits(Response $response)
    {
        $this->dailyLimit = (int) $response->getHeaderLine('X-RateLimit-Limit');
        $this->dailyLimitRemaining = (int) $response->getHeaderLine('X-RateLimit-Remaining');
        $this->dailyLimitReset = (int) $response->getHeaderLine('X-RateLimit-Reset');

        $this->minutelyLimit = (int) $response->getHeaderLine('X-RateLimit-Minutely-Limit');
        $this->minutelyLimitRemaining = (int) $response->getHeaderLine('X-RateLimit-Minutely-Remaining');
    }
    
    public function runBatch($debug = false)
    {
        if ($debug) {
            echo "We have " . count($this->batch) . " batch endpoints in batch";
        }

        if (count($this->batch) == 0) {
            return true;
        }

        foreach ($this->batch as $batchEndPoint => $batches) {
            if (count($batches) == 0) {
                continue;//empty batch endpoint
            }

            $currentBatch = [];
            $currentBatchLength = 0;
            $changes = [];
            $gets = [];

            foreach ($batches as $batch) {
                $simpleHeaders = [];
                $simpleHeaders[] = "Content-Type: application/http";
                $simpleHeaders[] = "Content-Transfer-Encoding: binary";

                $part = "";
                $part .= implode("\r\n", $simpleHeaders) . "\r\n\r\n";
                $part .= $batch->request->getMethod() . " " . $batch->request->getUri() . " HTTP/1.1\r\n";

                $contents = $batch->request->getBody()->getContents();
                if ($contents != '') {
                    $simpleHeaders = [];
                    $simpleHeaders[] = "Content-Type: application/json";
                    $simpleHeaders[] = "Accept: application/json";

                    $part .= implode("\r\n", $simpleHeaders) . "\r\n\r\n";
                    $part .= $contents;
                } else {
                    $simpleHeaders = [];
                    $simpleHeaders[] = "Accept: application/json";

                    $part .= implode("\r\n", $simpleHeaders) . "\r\n";
                }
                $part .= "\r\n";

                if ($currentBatchLength + strlen($part) > 9 * 1024 * 1024) {
                    break;//we stoppen hier voor de huidige batch..
                }

                if ($batch->request->getMethod() == "GET") {
                    $gets[] = $part;
                } else {
                    $changes[] = $part;
                }

                $currentBatch[] = $batch;
                $currentBatchLength += strlen($part);
                array_shift($this->batch[$batchEndPoint]);
            }

            try {
                $batchId = 1;

                $headers = [
                    'Accept' => 'application/json',
                    'Content-Type' => 'multipart/mixed; boundary=batch_' . $batchId,
                    'Prefer' => 'return=representation',
                ];

                //LET OP: we doen eerst changes, dan gets
                $body = '--batch_' . $batchId . "\r\n";
                if (count($changes) > 0) {
                    $changeSetId = 1;
                    $body .= "Content-Type: multipart/mixed; boundary=changeset_" . $changeSetId . "\r\n\r\n";
                    $body .= "--changeset_" . $changeSetId . "\r\n";
                    $body .= implode($changes, "\r\n\r\n--changeset_" . $changeSetId . "\r\n");
                    $body .= "--changeset_" . $changeSetId . "--\r\n\r\n";
                    $body .= '--batch_' . $batchId;
                }
                if (count($gets) > 0) {
                    if (count($changes) > 0) {
                        $body .= "\r\n";
                    }
                    $body .= implode($gets, "\r\n\r\n--batch_" . $batchId . "\r\n");
                    $body .= '--batch_' . $batchId;
                }
                $body .= '--';


                //echo "<pre>".$body."</pre>";
                //exit();

                // If access token is not set or token has expired, acquire new token
                if (empty($this->accessToken) || $this->tokenHasExpired()) {
                    $this->acquireAccessToken();
                }

                // If we have a token, sign the request
                if (!$this->needsAuthentication() && !empty($this->accessToken)) {
                    $headers['Authorization'] = 'Bearer ' . $this->accessToken;
                }

                $endpoint = $this->formatUrl($batchEndPoint . '/$batch');
                $params = [];

                // Create param string
                if (!empty($params)) {
                    $endpoint .= '?' . http_build_query($params);
                }

                // Create the request
                $request = new Request("POST", $endpoint, $headers, $body);
                $response = $this->client()->send($request);

                $responseText = $response->getBody()->getContents();

                $responses = [];
                $batchSplit = explode("\r\n--batchresponse_", $responseText);
                foreach ($batchSplit as $splitIndex => $batchResponse) {
                    if ($splitIndex == 0 && count($changes) > 0) {
                        //first batch reserved for changes
                        $responseSplit = explode("\r\n--changesetresponse_", $batchResponse);
                        array_shift($responseSplit);
                        array_pop($responseSplit);

                        foreach ($responseSplit as $changeResponse) {
                            $responses[] = $changeResponse;
                        }
                    } else {
                        //get responses
                        $responses[] = $batchResponse;
                    }
                }

                //print_r($responses);
                //exit();

                if (1 == 1) {
                    $changesProcessed = 0;
                    $getsProcessed = 0;

                    foreach ($currentBatch as $index => $batch) {
                        //we moeten herleiden welke response bij deze batch hoort, terugrekenen
                        if ($batch->request->getMethod() == "GET") {
                            //get requests komen na de changes binnen
                            $responseIndex = $index + count($changes) - $changesProcessed;
                            $getsProcessed++;
                        } else {
                            $responseIndex = $index - $getsProcessed;
                            $changesProcessed++;
                        }


                        if (!isset($responses[$responseIndex])) {
                            echo "No response available for batchIndex " . $index . ": " . $responseText . "<br />\n";
                            continue;
                        }

                        $response = $responses[$responseIndex];

                        $responseHeaderSplit = explode("\r\n\r\n", $response, 3);
                        //print_r($responseHeaderSplit);
                        $batchHeader = $responseHeaderSplit[1];
                        $batchResponse = $responseHeaderSplit[2];

                        if ($debug) {
                            echo "Batch " . $index . " <pre>" . htmlspecialchars($batchHeader) . "</pre> response: <pre>" . htmlspecialchars($batchResponse) . "</pre><br /><br />";
                        }

                        $responseSuccess = false;

                        if ($batchResponse != '') {
                            $json = json_decode($batchResponse, true);
                            if (is_array($json)) {
                                //fill the object first
                                if (array_key_exists("d", $json)) {
                                    if (array_key_exists("results", $json["d"])) {
                                        if (count($json["d"]["results"]) == 1 && $batch->request->getMethod() != "GET") {
                                            if (isset($batch->item) && is_object($batch->item)) {
                                                foreach ($json["d"]["results"][0] as $key => $value) {
                                                    $batch->item->{$key} = $value;
                                                }
                                                $responseSuccess = true;
                                            }
                                        } else {
                                            //we did a batch get, we can process results here and use the __nextUrl
                                            //echo "BATCH GET RECEIVED YAY!: ".$batchResponse;
                                            //Als we problemen krijgen, moeten we dit stukje hier rechtzetten
                                            //
                                            //if (! empty($divisionId)) {
                                            //    $this->connection()->setDivision($originalDivision); // Restore division
                                            //}

                                            $results = $batch->item->collectionFromResult($json["d"]["results"]);
                                            if ($batch->callbacks !== null && is_object($batch->callbacks) && isset($batch->callbacks->success) && is_callable($batch->callbacks->success)) {
                                                call_user_func($batch->callbacks->success, $results, $batch->metaData);
                                            }
                                        }
                                    } else {
                                        if (isset($batch->item) && is_object($batch->item)) {
                                            foreach ($json["d"] as $key => $value) {
                                                $batch->item->{$key} = $value;
                                            }
                                            $responseSuccess = true;
                                        }
                                        //$object->fill($json["d"]);
                                    }
                                } else if (array_key_exists("error", $json)) {
                                    if (array_key_exists("message", $json["error"]) && array_key_exists("value", $json["error"]["message"]) && $json["error"]["message"]["value"] == "Gegeven bestaat reeds.") {
                                        echo "Gegeven bestaat reeds!<br />\n";
                                        break;//we end reading results.. because this error occured
                                    } else if (array_key_exists("message", $json["error"]) && array_key_exists("value", $json["error"]["message"]) && $json["error"]["message"]["value"] == "Moet zijn: Uniek - Artikel, Valuta, Eenheid, Aantal, Actief vanaf") {
                                        if ($batch->callbacks !== null && is_object($batch->callbacks) && isset($batch->callbacks->duplicate) && is_callable($batch->callbacks->duplicate)) {
                                            call_user_func($batch->callbacks->duplicate, $batch->item, $batch->metaData);
                                        } else {
                                            throw new ErrorException("on-duplicate callback not implemented");
                                        }
                                        //echo "Duplicate insert!<br />\n";
                                        break;//we end reading results.. because this error occured
                                    } else {
                                        echo "<div onClick=\"document.getElementById('responseBody').style.display = 'block';\">Error occurred</div> <pre id=\"responseBody\" style=\"display: none;\">" . htmlspecialchars($body) . "</pre><pre>" . htmlspecialchars(print_r($json["error"], true)) . "</pre><br />\n";
                                    }
                                } else {
                                    echo "Result not fillable? <pre>" . htmlspecialchars(print_r($json, true)) . "</pre>" . "<br />\n";
                                }
                            } else {
                                echo "Unexpected response for batch " . $index . ": <pre>" . htmlspecialchars($batchHeader) . "</pre> body <pre>" . htmlspecialchars($batchResponse) . "</pre><br />";
                            }
                        } else if (strpos($batchHeader, "HTTP/1.1 204 No Content") !== false) {
                            //then call the callback
                            $responseSuccess = true;
                        } else if ($batchHeader == "" && $batchResponse == "") {
                            //empty response, due to previous error...
                        } else {
                            echo "Batch " . $index . " unexpected output <pre>" . htmlspecialchars($batchHeader) . "</pre> response: <pre>" . htmlspecialchars($batchResponse) . "</pre><br /><br />";
                        }

                        if ($responseSuccess) {
                            //then call the callback
                            if ($batch->callbacks !== null && is_object($batch->callbacks) && isset($batch->callbacks->success) && is_callable($batch->callbacks->success)) {
                                call_user_func($batch->callbacks->success, $batch->item, $batch->metaData);
                            }
                        }
                    }
                } else {
                    echo "Invalid response count?!" . "<br />\n";
                    echo "<pre>" . htmlspecialchars($responseText) . "</pre>" . "<br />\n";
                }

                //return $this->parseResponse($response);
            } catch (Exception $e) {
                $this->parseExceptionForErrorMessages($e);
            }
        }
    }
}
