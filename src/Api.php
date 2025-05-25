<?php
namespace Nullpobug\Django\Signing;

use Nullpobug\Django\Signing\Utils;
use Nullpobug\Django\Signing\Signer;
use Nullpobug\Django\Signing\TimeStampSigner;

class Api {
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
