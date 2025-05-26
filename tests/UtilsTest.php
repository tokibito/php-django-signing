<?php

namespace Nullpobug\Django\Signing\Tests;

use PHPUnit\Framework\TestCase;
use Nullpobug\Django\Signing\Utils;

class UtilsTest extends TestCase
{
    public function test_b62_encode()
    {
        $this->assertEquals('1tSn5c', Utils::b62_encode(1735693200));
    }

    public function test_b62_decode()
    {
        $this->assertEquals(1735693200, Utils::b62_decode('1tSn5c'));
    }

    public function test_b64_encode()
    {
        $this->assertEquals('SGVsbG8sIFdvcmxkIQ', Utils::b64_encode('Hello, World!'));
    }

    public function test_b64_decode()
    {
        $this->assertEquals('Hello, World!', Utils::b64_decode('SGVsbG8sIFdvcmxkIQ'));
    }

    public function test_salted_hmac()
    {
        $secret = 'my_secret';
        $salt = 'my_salt';
        $data = 'Hello, World!';
        $expected = 'Fn_42vDPSQUnPCYEGLM0bjoWUOQEiQXc3s2dJtPBfHQ';
        $result = Utils::b64_encode(Utils::salted_hmac($salt, $data, $secret, 'sha256'));
        $this->assertEquals($expected, $result);
    }
}
