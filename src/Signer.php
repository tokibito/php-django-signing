<?php

namespace Nullpobug\Django\Signing;

use InvalidArgumentException;
use RuntimeException;
use Nullpobug\Django\Signing\Utils;
use function hash_equals;
use function str_contains;
use function strlen;
use function strrpos;
use function substr;

/**
 * Signer class for creating and verifying signatures.
 *
 * This class provides methods to sign a value by appending a signature,
 * and to unsign a signed value, verifying the signature.
 */
class Signer
{
    /**
     * @phpstan-param non-empty-string $sep
     */
    public function __construct(
        protected readonly string $secret,
        protected readonly string $salt = 'django.core.signing.Signer',
        public readonly string $sep = ':',
        protected readonly string $algorithm = 'sha256',
    ) {
        if (str_contains(haystack: $salt, needle: $sep)) {
            throw new InvalidArgumentException("Salt cannot contain the separator character");
        }
    }

    /**
     * Generate a signature for the given value.
     *
     * @param string $value The value to sign.
     * @return string The base64-encoded HMAC signature.
     */
    protected function get_signature(string $value): string
    {
        return Utils::b64_encode(Utils::salted_hmac($this->salt . 'signer', $value, $this->secret, $this->algorithm));
    }

    /**
     * Sign a value by appending a signature.
     *
     * @param string $value The value to sign.
     * @return string The signed value, which is the original value followed by the separator and the signature.
     */
    public function sign(string $value): string
    {
        return $value . $this->sep . $this->get_signature($value);
    }

    /**
     * Unsign a signed value, verifying the signature.
     *
     * @param string $signed_value The signed value to unsign.
     * @return string The original value if the signature is valid.
     * @throws RuntimeException If the signature does not match or the format is invalid.
     */
    public function unsign(string $signed_value): string
    {
        $sep_pos = strrpos($signed_value, $this->sep);
        if ($sep_pos === false) {
            throw new RuntimeException("Bad signature format");
        }

        $value = substr($signed_value, 0, $sep_pos);
        $sig = substr($signed_value, $sep_pos + strlen($this->sep));

        $expected_sig = $this->get_signature($value);

        if (!hash_equals($expected_sig, $sig)) {
            throw new RuntimeException("Signature does not match");
        }

        return $value;
    }
}
