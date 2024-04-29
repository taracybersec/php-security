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

    /**
     * Get supported algorithms
     * -------------------------
     * This method returns a list of supported algorithms.
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return array
     */
    public static function getSupportedAlgorithms()
    {
        return openssl_get_cipher_methods();
    }

    /**
     * Generate a random string
     * ------------------------
     * This method generates a random string of the specified length.
     * @param int $length The length of the random string
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function generateRandomString(int $length = 32)
    {
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }

    /**
     * Generate a secure random password
     * ---------------------------------
     * This method generates a secure random password of the specified length.
     * @param int $length The length of the password
     * @param bool $lowercase Whether to include lowercase characters
     * @param bool $uppercase Whether to include uppercase characters
     * @param bool $numbers Whether to include numbers
     * @param bool $symbols Whether to include symbols
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function generateSecureRandomPassword(int $length = 24, bool $lowercase = self::PASS_LOWERCASE_ON, bool $uppercase = self::PASS_UPPERCASE_ON, bool $numbers = self::PASS_NUMBERS_ON, bool $symbols = self::PASS_SYMBOLS_ON)
    {
        $sets = [];
        if ($lowercase) {
            $sets[] = 'abcdefghijklmnopqrstuvwxyz';
        }
        if ($uppercase) {
            $sets[] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        }
        if ($numbers) {
            $sets[] = '1234567890';
        }
        if ($symbols) {
            $sets[] = '!@#$%^&*()_+-=[]{}|;:",./<>?';
        }
        $all = '';
        $password = '';
        foreach ($sets as $set) {
            $all .= $set;
        }
        $alphaLength = strlen($all) - 1;
        for ($i = 0; $i < $length; $i++) {
            $password .= $all[random_int(0, $alphaLength)];
        }
        return $password;
    }

    /**
     * Encrypt data for CryptoJS
     * -------------------------
     * This method encrypts data using the specified algorithm that supports CryptoJS libarary used by JavaScript.
     * It returns a JSON encoded string that supports CryptoJS library used by JavaScript.
     * @param string $data The data to encrypt
     * @param string $algorithm The algorithm to use for encryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function encryptForCryptoJS(string $data, string $algorithm = self::ALGO_AES_256_CBC)
    {
        try {
            $saltBytes = openssl_random_pseudo_bytes(8);
            $intermediateKeyingMaterial = '';
            $hash = '';
            while (strlen($intermediateKeyingMaterial) < 48) {
                $hash = md5($hash . self::$secretKey . $saltBytes, true);
                $intermediateKeyingMaterial .= $hash;
            }
            $encryptionKey = substr($intermediateKeyingMaterial, 0, 32);
            $initializationVector = substr($intermediateKeyingMaterial, 32, 16);
            $encryptedPayload = openssl_encrypt(json_encode($data), $algorithm, $encryptionKey, OPENSSL_RAW_DATA, $initializationVector);
            $encryptedData = ["ct" => base64_encode($encryptedPayload), "iv" => bin2hex($initializationVector), "s" => bin2hex($saltBytes)];
            return json_encode($encryptedData);
        } catch (\Exception $e) {
            throw new \Exception("Encryption failed: {$e->getMessage()}", $e->getCode(), $e);
        }
    }

    /**
     * Decrypt data from CryptoJS
     * ----------------------------
     * This method decrypts data using the specified algorithm that supports CryptoJS libarary used by JavaScript.
     * It returns a string that got encrypted by CryptoJS library used by JavaScript.
     * @param string $data The data to decrypt
     * @param string $algorithm The algorithm to use for decryption
     * @author Tara Prasad Routray <https://github.com/tararoutray>
     * @return string
     */
    public static function decryptFromCryptoJS(string $data, string $algorithm = self::ALGO_AES_256_CBC)
    {
        try {
            $encryptedPayload = json_decode($data, true);
            $saltBytes = hex2bin($encryptedPayload["s"]);
            $initializationVectorBytes = hex2bin($encryptedPayload["iv"]);
            $cipherTextBytes = base64_decode($encryptedPayload["ct"]);
            $concatenatedSecretKeyAndSalt = self::$secretKey . $saltBytes;
            $md5 = [];
            $md5[0] = md5($concatenatedSecretKeyAndSalt, true);
            $intermediateKeyingMaterial = $md5[0];
            for ($i = 1; $i < 32; $i++) {
                $md5[$i] = md5($md5[$i - 1] . $concatenatedSecretKeyAndSalt, true);
                $intermediateKeyingMaterial .= $md5[$i];
            }
            $key = substr($intermediateKeyingMaterial, 0, 32);
            $decryptedPayload = openssl_decrypt($cipherTextBytes, $algorithm, $key, OPENSSL_RAW_DATA, $initializationVectorBytes);
            $decodedPayload = json_decode($decryptedPayload, true);
            if ($decodedPayload === null) {
                return $decryptedPayload;
            }
            return $decodedPayload;
        } catch (\Exception $e) {
            throw new \Exception("Decryption failed: {$e->getMessage()}", $e->getCode(), $e);
        }
    }
}
