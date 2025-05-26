# nullpobug/django-signing

Django compatible signing library for PHP

## Installation

```bash
composer require nullpobug/django-signing
```

## Usage

```php
use Nullpobug\Django\Signing\Api;

$secret_key = 'your-secret-key';
$salt = 'your-salt';
$compress = true; // Optional, default is false
$add_timestamp = true; // Optional, default is false

// Signing a value
$signed_value = Api::dumps([
    'key' => 'value',
    'foo' => 'bar',
], $secret_key, $salt, $compress, $add_timestamp);
echo "Signed Value: $signed_value\n";
// Signed Value: .eJyrVspOrVSyUipLzClNVdJRSsvPB_KSEouUagF46QiI:1uJbaB:IYz9-JnIyn7NAJJSIHe8eZ0vC3hj-3a_gFmCbpCrugU

// Unsigned value
$unsigned_value = Api::loads($signed_value, $secret_key, $salt);
echo print_r($unsigned_value);
// Array
// (
//     [key] => value
//     [foo] => bar
// )
```

Signed value is compatible with Django's signing library, allowing you to share signed data between PHP and Django applications.

## Website

This project is hosted on [GitHub](https://github.com/tokibito/php-django-signing).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.