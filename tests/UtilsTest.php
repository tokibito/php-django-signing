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
}
