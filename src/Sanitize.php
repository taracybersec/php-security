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

    /**
     * Validate Uploded Files
     * ----------------------
     * This method validates uploaded files by scanning their content for malicious code or files, ensuring that they are safe to be uploaded into your web server.
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    public static function validateUploadedFiles()
    {
        $errors = [];
        foreach ($_FILES as $fieldName => $file) {
            if (is_array($file['name'])) {
                $errors = array_merge(
                    $errors,
                    self::validateUploadedFilesRecursively($fieldName, $file)
                );
            } else {
                $errors = array_merge(
                    $errors,
                    self::validateFileContent($fieldName, $file)
                );
            }
            if (!empty($errors)) {
                break;
            }
        }
        return $errors;
    }

    /**
     * Validate Uploaded Files Recursively
     * ------------------------------------
     * This method recursively scans the uploaded files available in the request body and validates them. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateUploadedFilesRecursively($fieldName, $file)
    {
        $errors = [];
        foreach ($file['name'] as $key => $fileName) {
            $indFile = [
                'name' => $file['name'][$key],
                'type' => $file['type'][$key],
                'tmp_name' => $file['tmp_name'][$key],
                'error' => $file['error'][$key],
                'size' => $file['size'][$key],
            ];
            $errors = array_merge(
                $errors,
                self::validateFileContent($fieldName, $indFile)
            );
        }
        return $errors;
    }

    /**
     * Validate File Content
     * ----------------------
     * This method validates the file content. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateFileContent($fieldName, $file)
    {
        $errors = [];
        $fileMimeType = self::getFileMimeType($file);
        $errors = array_merge($errors, self::validateFileType($fileMimeType));
        if (empty($errors)) {
            $errors = array_merge($errors, self::validatePdfFile($fieldName, $file, $fileMimeType));
            $errors = array_merge($errors, self::validateOfficeFile($fieldName, $file, $fileMimeType));
            $errors = array_merge($errors, self::validateImageFile($fieldName, $file));
        }
        return $errors;
    }

    /**
     * Get File Mime Type
     * -------------------
     * This method returns the file mime type.
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return string
     */
    private static function getFileMimeType($file)
    {
        return mime_content_type($file['tmp_name']);
    }

    /**
     * Validate File Type
     * ------------------
     * This method validates the file type. It returns an array of errors if any.
     * @param string $fileMimeType
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateFileType($fileMimeType)
    {
        $errors = [];
        if (!in_array($fileMimeType, self::getSupportedFileTypes())) {
            $errors[] = 'Invalid file type';
        }
        return $errors;
    }

    /**
     * Get Supported File Types
     * -------------------------
     * This method returns an array of supported file types.
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function getSupportedFileTypes()
    {
        return array(
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'application/pdf',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        );
    }

    /**
     * Validate PDF File
     * -----------------
     * This method validates an PDF file. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @param string $fileMimeType
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validatePdfFile($fieldName, $file, $fileMimeType)
    {
        $errors = [];
        if ($fileMimeType === 'application/pdf') {
            $errors = self::validatePdfFileVersion($fieldName, $file);
        }
        return $errors;
    }

    /**
     * Validate PDF File Version
     * -------------------------
     * This method validates the PDF file version. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validatePdfFileVersion($fieldName, $file)
    {
        $errors = [];
        $fileHandle = fopen($file['tmp_name'], 'rb');
        $firstFiveBytes = fread($fileHandle, 5);
        fclose($fileHandle);
        if (!preg_match('%PDF-(\d+\.\d+)%', $firstFiveBytes, $matches) || $matches[1] < 1.4) {
            $errors[] = $fieldName . ' - Invalid or old version of PDF';
        }
        return $errors;
    }

    /**
     * Validate Office File
     * --------------------
     * This method validates an Office file. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @param string $fileMimeType
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateOfficeFile($fieldName, $file, $fileMimeType)
    {
        $errors = [];
        if (in_array($fileMimeType, self::getOfficeFileTypes())) {
            $errors = self::validateOfficeFileHeader($fieldName, $file);
        }
        return $errors;
    }

    /**
     * Get Office File Headers
     * ------------------------
     * This method returns a list of Office file headers.
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function getOfficeFileTypes()
    {
        return array(
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        );
    }

    /**
     * Validate Office File Header
     * ----------------------------
     * This method validates the header of an Office file.
     * @param string $fieldName
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateOfficeFileHeader($fieldName, $file)
    {
        $errors = [];
        $fileHandle = fopen($file['tmp_name'], 'rb');
        $header = fread($fileHandle, 4);
        fclose($fileHandle);
        if (!in_array($header, self::getOfficeFileHeaders())) {
            $errors[] = $fieldName . ' - Invalid Excel/Word file';
        }
        return $errors;
    }

    /**
     * Get Office File Headers
     * ------------------------
     * This method returns an array of Office file headers.
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function getOfficeFileHeaders()
    {
        return array("\xD0\xCF\x11\xE0", "\x50\x4B\x03\x04", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "\x50\x4B\x03\x04\x14\x00\x06\x00");
    }

    /**
     * Validate Image File
     * --------------------
     * This method validates an uploaded image file. It returns an array of errors if any.
     * @param string $fieldName
     * @param array $file
     * @author Tara Prasad Routray <https://github.com/taracybersec>
     * @return array
     */
    private static function validateImageFile($fieldName, $file)
    {
        $errors = [];
        if (!isset($file['tmp_name'])) {
            $errors[] = $fieldName . ' - Invalid image file';
            return $errors;
        }
        $fileHandle = fopen($file['tmp_name'], 'rb');
        if (!$fileHandle) {
            $errors[] = $fieldName . ' - Unable to open the file';
            return $errors;
        }
        $img = @imagecreatefromstring(file_get_contents($file['tmp_name']));
        if (!$img) {
            $errors[] = $fieldName . ' - Invalid image file';
        } else {
            imagedestroy($img);
        }
        return $errors;
    }
}
