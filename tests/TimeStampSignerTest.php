<?php

namespace Nullpobug\Django\Signing\Tests;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use Nullpobug\Django\Signing\TimestampSigner;
use Nullpobug\Django\Signing\Signer;
use Nullpobug\Django\Signing\Utils;

class TimestampSignerTest extends TestCase
{
    /**
     * @var TimestampSigner
     */
    protected $signer;

    public function setUp(): void
    {
        // Use a fixed secret for reproducibility
        $this->signer = new TimestampSigner('test-secret');
    }

    public function testSignAndUnsign()
    {
        $value = 'foobar';
        $signed = $this->signer->sign($value);
        $unsigned = $this->signer->unsign($signed);
        $this->assertEquals($value, $unsigned);
    }

    public function testSignAddsTimestamp()
    {
        $value = 'hello';
        $signed = $this->signer->sign($value);
        $parts = explode($this->signer->sep, $signed);
        // Should be value, timestamp, signature
        $this->assertCount(3, $parts);
        $this->assertEquals($value, $parts[0]);
        $this->assertNotEmpty($parts[1]);
        $this->assertNotEmpty($parts[2]);
    }

    public function testUnsignWithMaxAgeValid()
    {
        $value = 'bar';
        $signed = $this->signer->sign($value);
        // Should not throw
        $result = $this->signer->unsign($signed, 10);
        $this->assertEquals($value, $result);
    }

    public function testUnsignWithMaxAgeExpired()
    {
        $value = 'baz';
        // Manually create a signed value with an old timestamp
        $oldTimestamp = Utils::b62_encode(time() - 1000);
        $valueWithTs = $value . $this->signer->sep . $oldTimestamp;
        $signed = (new Signer('test-secret'))->sign($valueWithTs);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Signature has expired');
        $this->signer->unsign($signed, 1);
    }

    public function testUnsignBadFormat()
    {
        $badSigned = 'badvalue';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Bad signature format');
        $this->signer->unsign($badSigned);
    }

    public function testTimestampReturnsCorrectValue()
    {
        $value = 'abc';
        $signed = $this->signer->sign($value);
        $parts = explode($this->signer->sep, $signed);
        $expectedTimestamp = Utils::b62_decode($parts[1]);
        $actualTimestamp = $this->signer->timestamp($signed);
        $this->assertEquals($expectedTimestamp, $actualTimestamp);
    }

    public function testTimestampBadFormat()
    {
        $badSigned = 'foo.bar';
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Bad signature format');
        $this->signer->timestamp($badSigned);
    }
}
