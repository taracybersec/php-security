<?php

namespace Tararoutray\PhpSecurity;

/**
 * Crypto - A PHP Security Library
 * -------------------------------
 * This library provides a set of methods to encrypt data, decrypt data, and generate secure random passwords, and more.
 * @author Tara Prasad Routray <https://github.com/tararoutray>
 * @license MIT
 * @link https://github.com/tararoutray/php-security
 */
class Crypto
{
    private $secretKey;

    public const ALGO_AES_128_CBC = 'aes-128-cbc';
    public const ALGO_AES_128_CFB = 'aes-128-cfb';
    public const ALGO_AES_128_ECB = 'aes-128-ecb';
    public const ALGO_AES_128_OFB = 'aes-128-ofb';
    public const ALGO_AES_192_CBC = 'aes-192-cbc';
    public const ALGO_AES_192_CFB = 'aes-192-cfb';
    public const ALGO_AES_192_ECB = 'aes-192-ecb';
    public const ALGO_AES_192_OFB = 'aes-192-ofb';
    public const ALGO_AES_256_CBC = 'aes-256-cbc';
    public const ALGO_AES_256_CFB = 'aes-256-cfb';
    public const ALGO_AES_256_ECB = 'aes-256-ecb';
    public const ALGO_AES_256_OFB = 'aes-256-ofb';
    public const ALGO_AES_128_GCM = 'aes-128-gcm';
    public const ALGO_AES_192_GCM = 'aes-192-gcm';
    public const ALGO_AES_256_GCM = 'aes-256-gcm';
    public const ALGO_CAMELLIA_128_CBC = 'camellia-128-cbc';
    public const ALGO_CAMELLIA_128_CFB = 'camellia-128-cfb';
    public const ALGO_CAMELLIA_128_ECB = 'camellia-128-ecb';
    public const ALGO_CAMELLIA_128_OFB = 'camellia-128-ofb';
    public const ALGO_CAMELLIA_192_CBC = 'camellia-192-cbc';
    public const ALGO_CAMELLIA_192_CFB = 'camellia-192-cfb';
    public const ALGO_CAMELLIA_192_ECB = 'camellia-192-ecb';
    public const ALGO_CAMELLIA_192_OFB = 'camellia-192-ofb';
    public const ALGO_CAMELLIA_256_CBC = 'camellia-256-cbc';
    public const ALGO_CAMELLIA_256_CFB = 'camellia-256-cfb';
    public const ALGO_CAMELLIA_256_ECB = 'camellia-256-ecb';
    public const ALGO_CAMELLIA_256_OFB = 'camellia-256-ofb';
    public const ALGO_CHACHA20 = 'chacha20';
    public const ALGO_CHACHA20_POLY1305 = 'chacha20-poly1305';
    public const ALGO_BLOWFISH_CBC = 'bf-cbc';
    public const ALGO_BLOWFISH_CFB = 'bf-cfb';
    public const ALGO_BLOWFISH_ECB = 'bf-ecb';
    public const ALGO_BLOWFISH_OFB = 'bf-ofb';
    public const ALGO_SEED_CBC = 'seed-cbc';
    public const ALGO_SEED_CFB = 'seed-cfb';
    public const ALGO_SEED_ECB = 'seed-ecb';
    public const ALGO_SEED_OFB = 'seed-ofb';
    public const ALGO_SALSA20 = 'salsa20';
    public const ALGO_SALSA20_256_ECB = 'salsa20-256-ecb';
    public const ALGO_SALSA20_256_CBC = 'salsa20-256-cbc';
    public const ALGO_SALSA20_256_CFB = 'salsa20-256-cfb';
    public const ALGO_SALSA20_256_OFB = 'salsa20-256-ofb';
    public const ALGO_SALSA20_256_GCM = 'salsa20-256-gcm';
    public const ALGO_RC4 = 'rc4';
    public const ALGO_RC4_40 = 'rc4-40';
    public const ALGO_RC4_HMAC_MD5 = 'rc4-hmac-md5';
    public const ALGO_IDEA_CBC = 'idea-cbc';
    public const ALGO_IDEA_CFB = 'idea-cfb';
    public const ALGO_IDEA_ECB = 'idea-ecb';
    public const ALGO_IDEA_OFB = 'idea-ofb';
    public const ALGO_DES_CBC = 'des-cbc';
    public const ALGO_DES_CFB = 'des-cfb';
    public const ALGO_DES_ECB = 'des-ecb';
    public const ALGO_DES_EDE = 'des-ede';
    public const ALGO_DES_EDE_CBC = 'des-ede-cbc';
    public const ALGO_DES_EDE_CFB = 'des-ede-cfb';
    public const ALGO_DES_EDE_ECB = 'des-ede-ecb';
    public const ALGO_DES_EDE_OFB = 'des-ede-ofb';
    public const ALGO_DES_OFB = 'des-ofb';
    public const ALGO_DESX_CBC = 'desx-cbc';
    public const ALGO_CAST5_CBC = 'cast5-cbc';
    public const ALGO_CAST5_CFB = 'cast5-cfb';
    public const ALGO_CAST5_ECB = 'cast5-ecb';
    public const ALGO_CAST5_OFB = 'cast5-ofb';
    public const ALGO_ARCFOUR = 'rc4';
    public const ALGO_ARCFOUR_40 = 'rc4-40';
    public const ALGO_ARCFOUR_HMAC_MD5 = 'rc4-hmac-md5';

    public const PASS_LOWERCASE_ON = true;
    public const PASS_LOWERCASE_OFF = false;

    public const PASS_UPPERCASE_ON = true;
    public const PASS_UPPERCASE_OFF = false;

    public const PASS_NUMBERS_ON = true;
    public const PASS_NUMBERS_OFF = false;

    public const PASS_SYMBOLS_ON = true;
    public const PASS_SYMBOLS_OFF = false;

    /**
     * Create a new Crypto instance
     * ----------------------------
     * This method is the constructor of the class.
     * Use it to initialize the instance with the secret key used for encryption/decryption.
     * @param string $secretKey The secret key to use for encryption/decryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return void
     */
    public function __construct(string $secretKey)
    {
        $this->secretKey = $secretKey;
    }
    
    /**
     * Set the secret key
     * ------------------
     * This method sets the secret key to be used for encrypting and decrypting data.
     * @param string $secretKey The secret key to use for encryption/decryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return void
     */
    public static function setSecretKey(string $secretKey)
    {
        self::$secretKey = $secretKey;
    }
    
    /**
     * Generate a secret key
     * ---------------------
     * This method generates a secret key to be used for encrypting and decrypting data.
     * for encryption/decryption of data.
     * @param string $algorithm The algorithm to use for generating the secret key
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function generateSecretKey(string $algorithm)
    {
        return openssl_random_pseudo_bytes(openssl_cipher_iv_length($algorithm));
    }
    
    /**
     * Encrypt data
     * -------------
     * This method encrypts data using the specified algorithm and returns a base64 encoded string.
     * @param string $data The data to encrypt
     * @param string $algorithm The algorithm to use for encryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function encrypt(string $data, string $algorithm)
    {
        if (!self::isAlgorithmSupported($algorithm)) {
            throw new \Exception("Your PHP version " . phpversion() . " doesn't support encryption with " . $algorithm, 400);
        }
        try {
            $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($algorithm));
            $encrypted = openssl_encrypt($data, $algorithm, self::$secretKey, OPENSSL_RAW_DATA, $iv);
            return $iv . $encrypted;
        } catch (\Exception $e) {
            throw new \Exception("Encryption failed: {$e->getMessage()}", $e->getCode(), $e);
        }
    }
    
    /**
     * Decrypt data
     * -------------
     * This method decrypts data that was encrypted using the specified algorithm and secret key using the encrypt method of this class.
     * @param string $data The data to decrypt
     * @param string $algorithm The algorithm to use for decryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function decrypt(string $data, string $algorithm)
    {
        if (!self::isAlgorithmSupported($algorithm)) {
            throw new \Exception("Your PHP version " . phpversion() . " doesn't support decryption with " . $algorithm, 400);
        }
        try {
            $iv = substr($data, 0, openssl_cipher_iv_length($algorithm));
            return openssl_decrypt(substr($data, openssl_cipher_iv_length($algorithm)), $algorithm, self::$secretKey, OPENSSL_RAW_DATA, $iv);
        } catch (\Exception $e) {
            throw new \Exception("Decryption failed: {$e->getMessage()}", $e->getCode(), $e);
        }
    }
    
    /**
     * Check if an algorithm is supported
     * ----------------------------------
     * This method checks if the specified encryption algorithm is supported by the current PHP version.
     * If the algorithm is not supported, it will return false, otherwise it will return true.
     * @param string $algorithm The algorithm to check
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return bool
     */
    public static function isAlgorithmSupported(string $algorithm)
    {
        return in_array($algorithm, openssl_get_cipher_methods());
    }

}
