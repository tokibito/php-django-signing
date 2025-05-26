<?php

namespace Nullpobug\Django\Signing;

use InvalidArgumentException;
use function base64_encode;
use function base64_decode;
use function hash;
use function hash_hmac;
use function intdiv;
use function rtrim;
use function str_repeat;
use function strlen;
use function strpos;
use function strtr;

/**
 * Utility class for encoding and decoding values in various formats.
 * This class provides methods for base-62 encoding/decoding, base64 URL-safe encoding/decoding,
 * and generating salted HMACs.
 */
class Utils
{
    /**
     * Encode a non-negative integer to a base-62 string.
     * refs: django.core.signing.b62_encode
     *
     * @param int $num The non-negative integer to encode.
     * @phpstan-param non-negative-int $num
     * @return string The base-62 encoded string.
     */
    public static function b62_encode(int $num): string
    {
        if ($num < 0) { // @phpstan-ignore smaller.alwaysFalse
            throw new InvalidArgumentException("Only non-negative integers allowed");
        }

        $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $base = 62;

        if ($num === 0) {
            return '0';
        }

        $result = '';
        while ($num > 0) {
            $result = $chars[$num % $base] . $result;
            $num = intdiv($num, $base);
        }

        return $result;
    }

    /**
     * Decode a base-62 encoded string to a non-negative integer.
     * refs: django.core.signing.b62_decode
     *
     *
     * @param string $str The base-62 encoded string to decode.
     * @return int The decoded non-negative integer.
     * @throws InvalidArgumentException If the input contains invalid characters.
     */
    public static function b62_decode(string $str): int
    {
        $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        $base = 62;

        $num = 0;
        $len = strlen($str);
        for ($i = 0; $i < $len; $i++) {
            $pos = strpos($chars, $str[$i]);
            if ($pos === false) {
                throw new InvalidArgumentException("Invalid character in input: " . $str[$i]);
            }
            $num = $num * $base + $pos;
        }

        return $num;
    }

    /**
     * Encode a string to a base64 URL-safe string.
     * refs: django.core.signing.b64_encode
     *
     * @param string $data The string to encode.
     * @return string The base64 URL-safe encoded string.
     */
    public static function b64_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decode a base64 URL-safe string to its original string.
     * refs: django.core.signing.b64_decode
     *
     * @param string $input The base64 URL-safe encoded string to decode.
     * @return string The decoded original string.
     * @throws InvalidArgumentException If the input is not a valid base64 URL-safe string.
     */
    public static function b64_decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Generate a salted HMAC using the specified algorithm.
     * refs: django.utils.crypto.salted_hmac
     *
     * @param string $key_salt Salt to be used in the key derivation.
     * @param string $value The value to be hashed.
     * @param string $secret_key The secret key used for HMAC key with the $key_salt
     * @param string $algorithm The hashing algorithm to use (default is 'sha1').
     * @return string The resulting HMAC.
    */
    public static function salted_hmac(string $key_salt, string $value, string $secret_key, string $algorithm = 'sha1'): string
    {
        $key = hash($algorithm, $key_salt . $secret_key, true);

        return hash_hmac($algorithm, $value, $key, true);
    }
}
