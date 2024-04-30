<?php

namespace Tararoutray\PhpSecurity;

/**
 * Server - A PHP Security Library
 * -------------------------------
 * This library provides a set of methods to sanitize data for input validation and data sanitization.
 * @author Tara Prasad Routray <https://github.com/tararoutray>
 * @license MIT
 * @link https://github.com/tararoutray/php-security
 */
class Server
{
    private $allowedOrigins = ['*'];

    private $rateLimitStoragePath = __DIR__ . '/ratelimit_storage';

    /**
     * Add security headers
     * ---------------------
     * This method adds security headers to the response. It helps to prevent XSS attacks, clickjacking, etc.
     * @param bool $disableCSP
     * @param array $customAllowedOrigins
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return void
     */
    public static function addSecurityHeaders(bool $disableCSP = false, $customAllowedOrigins = [])
    {
        if (!$disableCSP) {
            header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-src 'none'");
        }
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: SAMEORIGIN");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: same-origin");
        header("Strict-Transport-Security: max-age=63072000; includeSubDomains; preload");
        header("Feature-Policy: geolocation 'self'; microphone 'none'; camera 'none'");
        if (count($customAllowedOrigins) > 0) {
            self::$allowedOrigins = $customAllowedOrigins;
        }
        header("Access-Control-Allow-Origin: " . implode(',', self::$allowedOrigins));
        header("Expect-CT: enforce, max-age=86400");
    }

    /**
     * Set rate limit storage path
     * ----------------------------
     * This method sets the rate limit storage path.
     * @param string $path
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return void
     */
    public static function setRateLimitStoragePath(string $path)
    {
        self::$rateLimitStoragePath = $path;
    }

    /**
     * Enforce rate limiting
     * ----------------------
     * This method enforces rate limiting. It checks if the request is within the rate limit. If the request is within the rate limit, it returns true. If the request is outside the rate limit, it stops the script execution and returns a json response with a 429 status code.
     * @param int $requestLimit
     * @param int $timeInterval
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return bool
     */
    public static function enforceRateLimiting(int $requestLimit = 120, int $timeInterval = 60)
    {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        $requestedURL = $_SERVER['REQUEST_URI'];
        $storageKey = hash('sha256', "{$clientIP}|{$requestedURL}");
        $storageDirectory = self::$rateLimitStoragePath;
        $storageFilePath = "{$storageDirectory}/{$storageKey}";
        if (!file_exists($storageDirectory)) {
            mkdir($storageDirectory, 0777, true);
        }
        $requestData = @json_decode(@file_get_contents($storageFilePath), true);
        if (!$requestData) {
            $requestData = [
                'requestCount' => 0,
                'requestTimestamp' => time()
            ];
        }
        $currentTime = time();
        if ($currentTime - $requestData['requestTimestamp'] > $timeInterval) {
            $requestData['requestCount'] = 0;
            $requestData['requestTimestamp'] = $currentTime;
        }
        $requestData['requestCount']++;
        file_put_contents($storageFilePath, json_encode($requestData));
        if ($requestData['requestCount'] > $requestLimit) {
            return false;
        }
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode([
            'message' => 'Too many requests. Please try again later.'
        ]);
        die;
    }

    public static function 

}
