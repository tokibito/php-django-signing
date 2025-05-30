<?php

namespace Nullpobug\Django\Signing\Tests;

use RuntimeException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Nullpobug\Django\Signing\Signer;

class SignerTest extends TestCase
{
    private string $secret = 'test_secret';

    public function testSignAndUnsign(): void
    {
        $signer = new Signer($this->secret);
        $value = 'hello';
        $signed = $signer->sign($value);
        $this->assertNotEquals($value, $signed);
        $unsigned = $signer->unsign($signed);
        $this->assertSame($value, $unsigned);
    }

    public function testUnsignWithInvalidSignatureThrows(): void
    {
        $this->expectException(RuntimeException::class);
        $signer = new Signer($this->secret);
        $value = 'hello';
        $signed = $signer->sign($value);
        // Tamper with the signature
        $tampered = $signed . 'x';
        $signer->unsign($tampered);
    }

    public function testUnsignWithNoSeparatorThrows(): void
    {
        $this->expectException(RuntimeException::class);
        $signer = new Signer($this->secret);
        $signer->unsign('invalidsignedvalue');
    }

    public function testCustomSeparator(): void
    {
        $signer = new Signer($this->secret, 'mysalt', '|');
        $value = 'foo';
        $signed = $signer->sign($value);
        $this->assertStringContainsString('|', $signed);
        $unsigned = $signer->unsign($signed);
        $this->assertSame($value, $unsigned);
    }

    public function testCustomSalt(): void
    {
        $signer1 = new Signer($this->secret, 'salt1');
        $signer2 = new Signer($this->secret, 'salt2');
        $value = 'bar';
        $signed1 = $signer1->sign($value);
        $signed2 = $signer2->sign($value);
        $this->assertNotEquals($signed1, $signed2);
    }

    public function testSaltWithSeparatorThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Signer($this->secret, 'bad:salt');
    }

    public function testDifferentAlgorithm(): void
    {
        $signer1 = new Signer($this->secret, 'salt', ':', 'sha256');
        $signer2 = new Signer($this->secret, 'salt', ':', 'sha1');
        $value = 'baz';
        $signed1 = $signer1->sign($value);
        $signed2 = $signer2->sign($value);
        $this->assertNotEquals($signed1, $signed2);
    }
}
