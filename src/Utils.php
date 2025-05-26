<?php

namespace Nullpobug\Django\Signing;

class Utils
{
  public static function b62_encode(int $num): string
  {
    if (!is_int($num) || $num < 0) {
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

  public static function b64_encode($data): string
  {
    if (!is_string($data)) {
      throw new InvalidArgumentException("Only strings allowed");
    }

    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  public static function b64_decode($input)
  {
    $remainder = strlen($input) % 4;
    if ($remainder) {
      $padlen = 4 - $remainder;
      $input .= str_repeat('=', $padlen);
    }
    return base64_decode(strtr($input, '-_', '+/'));
  }

  public static function salted_hmac($key_salt, $value, $secret_key, $algorithm = 'sha1')
  {
    if (!is_string($value)) {
      $value = strval($value);
    }
    $key = hash($algorithm, $key_salt . $secret_key, true);
    $hmac = hash_hmac($algorithm, $value, $key, true);
    return $hmac;
  }
}
