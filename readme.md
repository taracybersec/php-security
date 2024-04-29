# PHP Security - A modern and secure PHP library

## Introduction

PHP Security is a modern and secure PHP library that provides a set of methods to encrypt data, decrypt data, generate secure random passwords, and much more. It is built with PHP's built-in cryptography functions and is designed to be easy to use and highly secure.

## Features

* Secure data encryption and decryption with a variety of algorithms (AES-256-CBC, AES-128-GCM, ChaCha20-Poly1305, etc.)
* Supports both password-based and secret key encryption/decryption
* Generate complex and secure random passwords with a wide range of characteristics (length, uppercase, lowercase, numbers, symbols)

## Requirements

* PHP 7.2 or higher

## Installation

Install the latest version with

```
composer require tararoutray/php-security
```

## Features in Crypto

### 1. Set the secret key

To set the secret key to be used for encrypting and decrypting data, you can use the following method. This method takes a string as an argument and sets the secret key to be used by all encrypt and decrypt methods. The secret key is used for symmetric encryption and decryption. It is recommended to set the secret key once when the application starts and keep it in a secure location.

```
use Tararoutray\PhpSecurity\Crypto;

Crypto::setSecretKey('your_secret_key');
```

### 2. Generate a secret key

To generate a secret key for encrypting and decrypting data, you can use the following method. This method generates a random secret key that can be used for encrypting and decrypting data using the specified algorithm (AES-256-CBC, etc). The method returns an encoded string that can be stored in a database or sent over the network. The secret key is used for symmetric encryption and decryption. It is recommended to generate a new secret key once when the application starts and keep it in a secure location. The generated secret key is cryptographically secure and is suitable for use in high security applications.

```
use Tararoutray\PhpSecurity\Crypto;

Crypto::generateSecretKey(Crypto::ALGO_AES_256_CBC);
```

### 3. Encrypt data

To encrypt data using a secret key, you can use the following method. This method encrypts data using AES-256-CBC algorithm (you can choose your own) with a secret key. The method returns a base64 encoded string that can be stored in a database or sent over the network.

```
use Tararoutray\PhpSecurity\Crypto;

$data = "Sensitive information";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::encrypt($data, Crypto::ALGO_AES_256_CBC);
```

### 4. Decrypt data

To decrypt data that was encrypted using a secret key, you can use the following method. This method decrypts data that was encrypted using the specified algorithm (AES-256-CBC, etc) with a secret key. The method returns a decrypted string that can be used by your application. The decryption process uses the secret key that was set using the setSecretKey method of this class.

```
use Tararoutray\PhpSecurity\Crypto;

$data = "your encrypted data";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::decrypt($data, Crypto::ALGO_AES_256_CBC);
```

### 5. Check if an algorithm is supported

To check if an encryption algorithm is supported by the current PHP version, you can use the following method. This method checks if the specified algorithm is supported by the current PHP version, and if it is not, it will return false. If the algorithm is supported, it will return true. This method is useful if you want to check if an algorithm is supported before using it to encrypt data.

```
use Tararoutray\PhpSecurity\Crypto;

echo Crypto::isAlgorithmSupported('algo_name');
```

### 6. Get supported algorithms

To get a list of supported encryption algorithms for your current PHP version, you can use the following method. This method returns a list of supported algorithms for your current PHP version, and it is a great way to check if an algorithm is supported before using it to encrypt data.

The number of supported encryption algorithms may vary depending on your PHP version, operating system, and hardware. However, the list of supported algorithms is stable and will not change unless there is a major release of PHP.

```
use Tararoutray\PhpSecurity\Crypto;

$supportedEncAlgos = Crypto::getSupportedAlgorithms();
```

### 7. Generate a random string

To generate a secure random string, use this method. It will return a random string of the specified length. This method is useful if you need to generate a random string for things like generating a salt, generating a token, or anything else where you need a random string. The number of characters in the random string will be the specified length. The method will return a string.

```
use Tararoutray\PhpSecurity\Crypto;

echo Crypto::generateRandomString(32);
```

### 8. Generate a secure random password

To generate a secure random password with the specified characteristics, use this method. It will return a random password of the specified length that includes at least one lowercase character, one uppercase character, one number, and one symbol. The method will return a string.

```
use Tararoutray\PhpSecurity\Crypto;

echo Crypto::generateSecureRandomPassword(24, Crypto::PASS_LOWERCASE_ON, Crypto::PASS_UPPERCASE_ON, Crypto::PASS_NUMBERS_ON, Crypto::PASS_SYMBOLS_ON);
```

### 9. Encrypt data for CryptoJS

To encrypt data for CryptoJS, use this method. It encrypts data using the specified algorithm that supports the CryptoJS library used by JavaScript. It returns a JSON encoded string that can be safely passed to the CryptoJS library used by JavaScript. The encrypted data will be compatible with the CryptoJS library, which is a popular JavaScript library for encrypting and decrypting data. The encrypted data is JSON encoded, so it can be easily passed to JavaScript as a string. The encrypted data will be returned in a JSON object with a data property that contains the encrypted data, and an iv property that contains the initialization vector used during encryption. The number of characters in the encrypted data will vary depending on the length of the data being encrypted. The method will return a string.

```
use Tararoutray\PhpSecurity\Crypto;

$data = "Sensitive information";
Crypto::setSecretKey('your_secret_key');
echo Crypto::encryptForCryptoJS($data, Crypto::ALGO_AES_256_CBC);
```

### 10. Decrypt data from CryptoJS

To decrypt data from CryptoJS, use this method. It decrypts data using the specified algorithm that supports the CryptoJS library used by JavaScript. It returns a string that was encrypted using the CryptoJS library used by JavaScript. The number of characters in the decrypted data will be the same as the number of characters in the encrypted data. The method will return a string.

```
use Tararoutray\PhpSecurity\Crypto;

$data = "your encrypted data";
Crypto::setSecretKey('your_secret_key');
$encryptedData = Crypto::decryptFromCryptoJS($data, Crypto::ALGO_AES_256_CBC);
```