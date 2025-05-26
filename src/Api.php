<?php

namespace Nullpobug\Django\Signing;

use RuntimeException;
use Nullpobug\Django\Signing\Utils;
use Nullpobug\Django\Signing\Signer;
use Nullpobug\Django\Signing\TimestampSigner;

class Api
{
    /**
     * Dumps a value into a signed string.
     *
     * @param mixed $value The value to be signed.
     * @param string $secret The secret key used for signing.
     * @param string $salt The salt used for signing.
     * @param bool $compress Whether to compress the JSON data.
     * @param bool $add_timestamp Whether to add a timestamp to the signature.
     * @return string The signed and optionally compressed value.
     */
    public static function dumps($value, string $secret, string $salt, bool $compress = false, bool $add_timestamp = false): string
    {
        $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

        if ($compress) {
            $data = zlib_encode($json, ZLIB_ENCODING_DEFLATE);
        } else {
            $data = $json;
        }

        $b64 = Utils::b64_encode($data);
        // add a dot to the beginning of the string if compress is true
        if ($compress) {
            $b64 = '.' . $b64;
        }

        if ($add_timestamp) {
            $signer = new TimestampSigner($secret, $salt);
        } else {
            $signer = new Signer($secret, $salt);
        }

        return $signer->sign($b64);
    }

    /**
     * Loads a signed value, verifying its signature and optionally checking for expiration.
     *
     * @param string $signed_value The signed value to be loaded.
     * @param string $secret The secret key used for signing.
     * @param string $salt The salt used for signing.
     * @param int|null $max_age Optional maximum age in seconds for the signature.
     * @return mixed The original value if the signature is valid.
     * @throws RuntimeException If the signature is invalid or the data cannot be decoded.
     */
    public static function loads(string $signed_value, string $secret, string $salt, int|null $max_age = null)
    {
        // Use appropriate signer
        if (substr_count($signed_value, ':') === 2) {
            $signer = new TimestampSigner($secret, $salt);
            $b64 = $signer->unsign($signed_value, $max_age);
        } else {
            $signer = new Signer($secret, $salt);
            $b64 = $signer->unsign($signed_value);
        }

        // first character is a dot, indicating compression
        $is_compressed = false;
        if (strlen($b64) > 0 && $b64[0] === '.') {
            $is_compressed = true;
            $b64 = substr($b64, 1);
        }

        $raw = Utils::b64_decode($b64);
        if ($is_compressed) {
            $json = zlib_decode($raw);
        } else {
            $json = $raw;
        }

        if ($json === false) {
            throw new RuntimeException("Base64 decoding failed");
        }

        $data = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException("JSON decoding failed: " . json_last_error_msg());
        }

        return $data;
    }
}
