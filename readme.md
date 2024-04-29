# PHP Security - A modern and secure PHP library

## Introduction

PHP Security is a modern and secure PHP library that provides a set of methods to encrypt data, decrypt data, generate secure random passwords, and much more. It is built with PHP's built-in cryptography functions and is designed to be easy to use and highly secure.

## Features

* Data encryption and decryption using AES-256-CBC, and all major encryption algorithms
* Supports both password-based encryption/decryption and secret key encryption/decryption
* Generate secure random passwords with varying levels of complexity
* Sanitize data using regular expressions
* Get a hash of data using SHA-512

## Requirements

* PHP 7.2 or higher

## Installation

Install the latest version with

```
composer require tararoutray/php-security
```

## Features

### Set the secret key

This method sets the secret key to be used for encrypting and decrypting data.

```
use Tararoutray\PhpSecurity\Crypto;

Crypto::setSecretKey('your_secret_key');
```

### Generate a secret key

To generate a secret key for encrypting and decrypting data using the specified algorithm (AES-256-CBC, etc), you can use the following method:

```
use Tararoutray\PhpSecurity\Crypto;

Crypto::generateSecretKey(Crypto::ALGO_AES_256_CBC);
```

### Encrypt data

To use the `encrypt` method from the library for encrypting data, follow these steps:

```
use Tararoutray\PhpSecurity\Crypto;

$data = "Sensitive information";
Crypto::setSecretKey('your_secret_key');
$encryptedData = $crypto->encrypt($data, Crypto::ALGO_AES_256_CBC);
```