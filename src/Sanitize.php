<?php

namespace TaraCyberSec\PhpSecurity;

/**
 * Sanitize - A PHP Security Library
 * -------------------------------
 * This library provides a set of methods to sanitize data for input validation and data sanitization.
 * @author Tara Prasad Routray <https://github.com/taracybersec>
 * @license MIT
 * @link https://github.com/taracybersec/php-security
 */
class Sanitize
{
    /**
     * Deep encode
     * -----------
     * This method deep encodes an array of data to prevent XSS attacks by recursively encoding each element of the array. It takes an array of data and HTML-encodes every element in it, regardless of its type. This way, even if an attacker manages to inject malicious data into one of the elements, it will be encoded and won't be executed as code by the browser.
     * @param array $inputData
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    public static function deepEncode(array $inputData)
    {
        $encodedData = [];
        foreach ($inputData as $inputKey => $inputValue) {
            if (is_array($inputValue)) {
                $encodedData[$inputKey] = self::deepEncode($inputValue);
            } else {
                $decodedInputValue = json_decode($inputValue);
                if (gettype($decodedInputValue) === 'object') {
                    $encodedData[$inputKey] = $inputValue;
                } elseif (gettype(json_decode($inputValue)) === 'object') {
                    $encodedData[$inputKey] = $inputValue;
                } else {
                    $encodedData[$inputKey] = htmlspecialchars($inputValue, ENT_QUOTES, 'UTF-8');
                }
            }
        }
        return $encodedData;
    }

    /**
     * Encode
     * -------
     * This method encodes an input string to prevent XSS attacks by HTML-encoding it.
     * @param string $inputData
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return string
     */
    public static function encode(string $inputData)
    {
        return htmlspecialchars($inputData, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Deep clean
     * -----------
     * This method cleans an array of data by recursively decoding each element of the array. It takes an array of data and decodes every element in it, regardless of its type. This way, even if an attacker manages to inject malicious data into one of the elements, it will be decoded and won't be executed as code by the browser. Additionally, it trims the strings and strips the tags from them.
     * @param array $inputData
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @param bool $trim Set to true to trim the strings
     */
    public static function deepClean(array $inputData, bool $trim = false)
    {
        $cleanedData = [];
        foreach ($inputData as $inputKey => $inputValue) {
            if (is_array($inputValue)) {
                $cleanedData[$inputKey] = self::deepClean($inputValue);
            } else {
                $decodedInputValue = json_decode($inputValue);
                if (gettype($decodedInputValue) === 'object') {
                    $encodedData[$inputKey] = $inputValue;
                } elseif (gettype(json_decode($inputValue)) === 'object') {
                    $encodedData[$inputKey] = $inputValue;
                } else {
                    $encodedData[$inputKey] = ($trim) ? trim(strip_tags($inputValue)) : strip_tags($inputValue);
                }
            }
        }
        return $cleanedData;
    }

    /**
     * Clean
     * ------
     * This method cleans an input string by HTML-decoding it. Additionally, it trims the strings and strips the tags from them.
     * @param string $inputData
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return string
     */
    public static function clean(string $inputData, bool $trim = false)
    {
        return ($trim) ? trim(strip_tags($inputData)) : strip_tags($inputData);
    }
}
