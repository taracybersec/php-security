# PHP Security - A modern and secure PHP library

## Introduction

PHP Security is a modern and secure PHP library that provides a set of methods to encrypt data, decrypt data, generate secure random passwords, and much more. It is built with PHP's built-in cryptography functions and is designed to be easy to use and highly secure.

## Features

- Secure data encryption and decryption with a variety of algorithms (AES-256-CBC, AES-128-GCM, ChaCha20-Poly1305, etc.)
- Supports both password-based and secret key encryption/decryption
- Generate complex and secure random passwords with a wide range of characteristics (length, uppercase, lowercase, numbers, symbols)

## Requirements

- PHP 7.2 or higher

## Installation

Install the latest version with

```
composer require taracybersec/php-security
```

## Features in Crypto

### 1. Set the secret key

To set the secret key to be used for encrypting and decrypting data, you can use the following method. This method takes a string as an argument and sets the secret key to be used by all encrypt and decrypt methods. The secret key is used for symmetric encryption and decryption. It is recommended to set the secret key once when the application starts and keep it in a secure location.

```
use TaraCyberSec\PhpSecurity\Crypto;

Crypto::setSecretKey('your_secret_key');
```

### 2. Generate a secret key

To generate a secret key for encrypting and decrypting data, you can use the following method. This method generates a random secret key that can be used for encrypting and decrypting data using the specified algorithm (AES-256-CBC, etc). The method returns an encoded string that can be stored in a database or sent over the network. The secret key is used for symmetric encryption and decryption. It is recommended to generate a new secret key once when the application starts and keep it in a secure location. The generated secret key is cryptographically secure and is suitable for use in high security applications.

```
use TaraCyberSec\PhpSecurity\Crypto;

Crypto::generateSecretKey(Crypto::ALGO_AES_256_CBC);
```

### 3. Encrypt data

To encrypt data using a secret key, you can use the following method. This method encrypts data using AES-256-CBC algorithm (you can choose your own) with a secret key. The method returns a base64 encoded string that can be stored in a database or sent over the network.

```
use TaraCyberSec\PhpSecurity\Crypto;

$data = "Sensitive information";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::encrypt($data, Crypto::ALGO_AES_256_CBC);
```

### 4. Decrypt data

To decrypt data that was encrypted using a secret key, you can use the following method. This method decrypts data that was encrypted using the specified algorithm (AES-256-CBC, etc) with a secret key. The method returns a decrypted string that can be used by your application. The decryption process uses the secret key that was set using the setSecretKey method of this class.

```
use TaraCyberSec\PhpSecurity\Crypto;

$data = "your encrypted data";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::decrypt($data, Crypto::ALGO_AES_256_CBC);
```

### 5. Check if an algorithm is supported

To check if an encryption algorithm is supported by the current PHP version, you can use the following method. This method checks if the specified algorithm is supported by the current PHP version, and if it is not, it will return false. If the algorithm is supported, it will return true. This method is useful if you want to check if an algorithm is supported before using it to encrypt data.

```
use TaraCyberSec\PhpSecurity\Crypto;

echo Crypto::isAlgorithmSupported('algo_name');
```

### 6. Get supported algorithms

To get a list of supported encryption algorithms for your current PHP version, you can use the following method. This method returns a list of supported algorithms for your current PHP version, and it is a great way to check if an algorithm is supported before using it to encrypt data.

The number of supported encryption algorithms may vary depending on your PHP version, operating system, and hardware. However, the list of supported algorithms is stable and will not change unless there is a major release of PHP.

```
use TaraCyberSec\PhpSecurity\Crypto;

$supportedEncAlgos = Crypto::getSupportedAlgorithms();
```

### 7. Generate a random string

To generate a secure random string, use this method. It will return a random string of the specified length. This method is useful if you need to generate a random string for things like generating a salt, generating a token, or anything else where you need a random string. The number of characters in the random string will be the specified length. The method will return a string.

```
use TaraCyberSec\PhpSecurity\Crypto;

echo Crypto::generateRandomString(32);
```

### 8. Generate a secure random password

To generate a secure random password with the specified characteristics, use this method. It will return a random password of the specified length that includes at least one lowercase character, one uppercase character, one number, and one symbol. The method will return a string.

```
use TaraCyberSec\PhpSecurity\Crypto;

echo Crypto::generateSecureRandomPassword(24, Crypto::PASS_LOWERCASE_ON, Crypto::PASS_UPPERCASE_ON, Crypto::PASS_NUMBERS_ON, Crypto::PASS_SYMBOLS_ON);
```

### 9. Encrypt data for CryptoJS

To encrypt data for CryptoJS, use this method. It encrypts data using the specified algorithm that supports the CryptoJS library used by JavaScript. It returns a JSON encoded string that can be safely passed to the CryptoJS library used by JavaScript. The encrypted data will be compatible with the CryptoJS library, which is a popular JavaScript library for encrypting and decrypting data. The encrypted data is JSON encoded, so it can be easily passed to JavaScript as a string. The encrypted data will be returned in a JSON object with a data property that contains the encrypted data, and an iv property that contains the initialization vector used during encryption. The number of characters in the encrypted data will vary depending on the length of the data being encrypted. The method will return a string.

```
use TaraCyberSec\PhpSecurity\Crypto;

$data = "Sensitive information";
Crypto::setSecretKey('your_secret_key');
echo Crypto::encryptForCryptoJS($data, Crypto::ALGO_AES_256_CBC);
```

### 10. Decrypt data from CryptoJS

To decrypt data from CryptoJS, use this method. It decrypts data using the specified algorithm that supports the CryptoJS library used by JavaScript. It returns a string that was encrypted using the CryptoJS library used by JavaScript. The number of characters in the decrypted data will be the same as the number of characters in the encrypted data. The method will return a string.

```
use TaraCyberSec\PhpSecurity\Crypto;

$data = "your encrypted data";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::decryptFromCryptoJS($data, Crypto::ALGO_AES_256_CBC);
```

Note: To make sure that your encrypted data is in compatible format while using CryptoJS, use the following steps:

```
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js" integrity="sha512-a+SUDuwNzXDvz4XrIcXHuCf089/iJAoN4lmrXJg18XnduKK6YlDHNRalv4yd1N40OKI80tFidF+rqTFKGPoWFQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>

const encrypt = (text, key) => {
    try {
        return CryptoJS.AES.encrypt(JSON.stringify(text), key, {
            format: {
                "encrypt": function (value, password) {
                    if (password.match(/[^\x00-\x7F]/)) {
                        console.warn("CryptoJSAES: Your passphrase contains non ASCII characters - This is not supported. Hash your passphrase with MD5 or similar hashes to prevent those issues");
                    }
                    return CryptoJS.AES.encrypt(JSON.stringify(value), password, { "format": CryptoJSAesJson }).toString();
                },
                "decrypt": function (jsonStr, password) {
                    if (password.match(/[^\x00-\x7F]/)) {
                        console.warn("CryptoJSAES: Your passphrase contains non ASCII characters - This is not supported. Hash your passphrase with MD5 or similar hashes to prevent those issues");
                    }
                    return JSON.parse(CryptoJS.AES.decrypt(jsonStr, password, { "format": CryptoJSAesJson }).toString(CryptoJS.enc.Utf8));
                },
                "stringify": function (cipherParams) {
                    var j = { "ct": cipherParams.ciphertext.toString(CryptoJS.enc.Base64) };
                    if (cipherParams.iv) j.iv = cipherParams.iv.toString();
                    if (cipherParams.salt) j.s = cipherParams.salt.toString();
                    return JSON.stringify(j).replace(/\s/g, "");
                },
                "parse": function (jsonStr) {
                    var j = JSON.parse(jsonStr);
                    var cipherParams = CryptoJS.lib.CipherParams.create({ "ciphertext": CryptoJS.enc.Base64.parse(j.ct) });
                    if (j.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(j.iv);
                    if (j.s) cipherParams.salt = CryptoJS.enc.Hex.parse(j.s);
                    return cipherParams;
                }
            }
        }).toString();
    } catch (error) {
        console.log(error.stack);
        return false;
    }
}
```

## Features in Sanitize

### 1. Deep encode

To securely clean an array of data to prevent XSS attacks, you can use the deepEncode method. This method deep encodes an array of data by recursively encoding each element of the array. It ensures that even if an attacker manages to inject malicious data into one of the elements, it will be HTML-encoded and won't be executed as code by the browser. The number of elements in the encoded data will be the same as the number of elements in the original data. The method will return an array of encoded data.

```
use TaraCyberSec\PhpSecurity\Sanitize;

$data = $request->all();
$data = Sanitize::deepEncode($data);

$request->replace($data);
```

### 2. Encode

To encode an input string, you can use the encode method. It encodes an input string to prevent XSS attacks by HTML-encoding it. This means that any special HTML characters in the string, such as "<" and ">", will be replaced with their corresponding HTML entities, "&lt;" and "&gt;", making it safe to use in an HTML document. The number of characters in the encoded string will be exactly the same as the number of characters in the original string. The method will return a string.

```
use TaraCyberSec\PhpSecurity\Sanitize;

$data = "<script>alert("some data")</script> here is a script";
$data = Sanitize::encode($data);
```

### 3. Deep clean

To clean an array of data, you can use the deepClean method. This method recursively cleaning each element of the array by cleaning every element in it, regardless of its type. This way, even if an attacker manages to inject malicious data into one of the elements, it will be cleaned out and won't be executed as code by the browser. Additionally, it trims the strings and strips the tags from them, making the data safe to use in your application. The number of elements in the cleaned data will be the same as the number of elements in the original data. The method will return an array of cleaned data.

```
use TaraCyberSec\PhpSecurity\Sanitize;

$data = $request->all();
$data = Sanitize::deepClean($data);

$request->replace($data);
```

### 4. Clean

To clean an input string, you can use the clean method. It removes HTML entities in the string, trims the whitespace from both ends of the string using trim, and strips the tags from the string using strip_tags. This way, even if an attacker manages to inject malicious data into the string, it will be trimmed, and tag-free, rendering it harmless.

```
use TaraCyberSec\PhpSecurity\Sanitize;

$data = "<script>alert("some data")</script> here is a script";
$data = Sanitize::clean($data);
```

### 5. Validate Uploaded Files

To validate uploaded files, you can use the validateUploadedFiles method. It validates uploaded files by scanning their content for malicious code or files, ensuring that they are safe to be uploaded into your web server. It recursively scans every file in the request body and checks if the file content is safe to be uploaded. This method helps prevent attacks such as file upload attacks and code injection attacks. It performs the following checks:

- Checks if the file is a valid image, PDF, or spreadsheet file based on its MIME type.
- Scans the file content for common malicious patterns.
- Checks if the file is a valid file type based on the file extension.

If any of these checks fail, the method adds an error message to an array of errors. The method then returns the array of errors. If the array of errors is empty, it means that all files in the request body are safe to be uploaded.

```
use TaraCyberSec\PhpSecurity\Sanitize;

$errors = Sanitize::validateUploadedFiles();
if (!empty($errors)) {
    http_response_code(422);
    header('Content-Type: application/json');
    echo json_encode([
        'message' => $errors[0],
        'errors' => $errors
    ]);
    die;
}
```

## Features for Server

### 1. Add security headers

To add security headers to all responses, you can use the addSecurityHeaders method. It helps to prevent XSS attacks, clickjacking, and other security threats by setting the Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Strict-Transport-Security, and Feature-Policy headers.

```
use TaraCyberSec\PhpSecurity\Server;

Server::addSecurityHeaders();
```

### 2. Set rate limit storage path

> Optional

To set the rate limit storage path, you can use the setRateLimitStoragePath method. This method sets the path where the library will store the rate limit data. The method takes a string as an argument and sets the path to the specified directory. The directory must exist and be writable by the web server. The default path is the current working directory.

```
use TaraCyberSec\PhpSecurity\Server;

$path = __DIR__ . "/rate_limit";
Server::setRateLimitStoragePath($path);
```

### 3. Enforce rate limiting

To enforce rate limiting, this method checks if the request is within the specified rate limit. If the request is within the rate limit, it returns true. If the request is outside the rate limit, it stops the script execution and returns a json response with a 429 status code. The method takes two arguments: the maximum number of requests allowed in the interval, and the interval in seconds.

```
use TaraCyberSec\PhpSecurity\Server;

Server::enforceRateLimiting();
```

You can customize the rate limiting defaults like this:

```
use TaraCyberSec\PhpSecurity\Server;

$requestLimit = 200; // max requests allowed in the interval: like 200 requests per 30 seconds
$interval = 30; // in seconds
Server::enforceRateLimiting($requestLimit, $interval);
```