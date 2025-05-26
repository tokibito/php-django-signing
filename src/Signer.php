<?php

namespace Nullpobug\Django\Signing;

use InvalidArgumentException;
use RuntimeException;
use Nullpobug\Django\Signing\Utils;

class Signer
{
    protected string $sep;
    protected string $salt;
    protected string $secret;
    protected string $algorithm;

    public function __construct(string $secret, string $salt = 'django.core.signing.Signer', string $sep = ':', string $algorithm = 'sha256')
    {
        if (preg_match('/[' . preg_quote($sep, '/') . ']/', $salt)) {
            throw new InvalidArgumentException("Salt cannot contain the separator character");
        }
        $this->secret = $secret;
        $this->salt = $salt;
        $this->sep = $sep;
        $this->algorithm = $algorithm;
    }

    protected function get_signature(string $value): string
    {
        return Utils::b64_encode(Utils::salted_hmac($this->salt . 'signer', $value, $this->secret, $this->algorithm));
    }

    public function sign(string $value): string
    {
        return $value . $this->sep . $this->get_signature($value);
    }

    public function unsign(string $signed_value): string
    {
        $sep_pos = strrpos($signed_value, $this->sep);
        if ($sep_pos === false) {
            throw new RuntimeException("Bad signature");
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
