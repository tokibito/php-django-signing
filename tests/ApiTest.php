<?php

namespace Nullpobug\Django\Signing\Tests;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use Nullpobug\Django\Signing\Api;

class ApiTest extends TestCase
{
    private string $secret = 'test_secret';
    private string $salt = 'test_salt';

    public function testDumpsAndLoadsSimpleArray(): void
    {
        $data = ['foo' => 'bar', 'baz' => 123];
        $signed = Api::dumps($data, $this->secret, $this->salt);
        $result = Api::loads($signed, $this->secret, $this->salt);
        $this->assertEquals($data, $result);
    }

    public function testDumpsAndLoadsWithCompression(): void
    {
        $data = ['foo' => 'bar', 'baz' => 123];
        $signed = Api::dumps($data, $this->secret, $this->salt, true);
        $result = Api::loads($signed, $this->secret, $this->salt);
        $this->assertEquals($data, $result);
    }

    public function testDumpsAndLoadsWithTimestamp(): void
    {
        $data = ['foo' => 'bar', 'baz' => 123];
        $signed = Api::dumps($data, $this->secret, $this->salt, false, true);
        $result = Api::loads($signed, $this->secret, $this->salt);
        $this->assertEquals($data, $result);
    }

    public function testDumpsAndLoadsWithCompressionAndTimestamp(): void
    {
        $data = ['foo' => 'bar', 'baz' => 123];
        $signed = Api::dumps($data, $this->secret, $this->salt, true, true);
        $result = Api::loads($signed, $this->secret, $this->salt);
        $this->assertEquals($data, $result);
    }

    public function testLoadsWithInvalidSignatureThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        Api::loads('invalid:signed:value', $this->secret, $this->salt);
    }

    public function testLoadsWithInvalidJsonThrows(): void
    {
        // Create a valid signature but tamper with the payload
        $data = ['foo' => 'bar'];
        $signed = Api::dumps($data, $this->secret, $this->salt);
        // Tamper with the payload part (before the signature)
        $parts = explode(':', $signed);
        $parts[0] = 'invalidbase64';
        $tampered = implode(':', $parts);

        $this->expectException(\RuntimeException::class);
        Api::loads($tampered, $this->secret, $this->salt);
    }

    public function testLoadsWithExpiredTimestampThrows(): void
    {
        $data = ['foo' => 'bar'];
        $signed = Api::dumps($data, $this->secret, $this->salt, false, true);
        // max_age = -1 to force expiration
        $this->expectException(\RuntimeException::class);
        Api::loads($signed, $this->secret, $this->salt, -1);
    }
}
