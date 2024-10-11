# totp-php
RFC: [TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)

### Uri
```php
$uri = new Uri('otpauth://totp/test_account:your-site.com?secret=Y5C4TFC5Q6OZHMXS7NOEDO5AYUP5XWMK&algorithm=sha1&digits=6&period=30');

$secret = $uri->getSecret();

echo 'key = ' . $secret . "\r\n";
// output:
// key = Y5C4TFC5Q6OZHMXS7NOEDO5AYUP5XWMK

$uri = new Uri();
$uri->setLabel('test');
$uri->setType('totp'); //default is 'totp'
$uri->setSecret('Y5C4TFC5Q6OZHMXS7NOEDO5AYUP5XWMK');

echo 'totp uri = ' . $uri . "\r\n";
// output:
// totp uri = otpauth://totp/test?secret=Y5C4TFC5Q6OZHMXS7NOEDO5AYUP5XWMK

```
### 快速调用
默认为30秒步长，6个数字的验证码，使用SHA1算法。
```php
echo TOTP::generate('Y5C4TFC5Q6OZHMXS7NOEDO5AYUP5XWMK', time());
```

### 更多测试
```php
// Seed for HMAC-SHA1 - 20 bytes
$seed = Base32::decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
// Seed for HMAC-SHA256 - 32 bytes
$seed32 = Base32::decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====");
// Seed for HMAC-SHA512 - 64 bytes
$seed64 = Base32::decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=");
$T0 = 0;
$X = 30;
$testTime = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];

ini_set('date.timezone', 'UTC');
for ($t = 0; $t < count($testTime); $t++) {
    echo sprintf(
        "time: %s, date: %s, code: %s, alg: SHA1\r\n",
        $testTime[$t],
        date('Y-m-d H:i:s', $testTime[$t]),
        TOTP::compute($seed, $testTime[$t], 'sha1', 8, $X, $T0));


    echo sprintf(
        "time: %s, date: %s, code: %s, alg: SHA256\r\n",
        $testTime[$t],
        date('Y-m-d H:i:s', $testTime[$t]),
        TOTP::compute($seed32, $testTime[$t], 'sha256', 8, $X, $T0));

    echo sprintf(
        "time: %s, date: %s, code: %s, alg: SHA512\r\n",
        $testTime[$t],
        date('Y-m-d H:i:s', $testTime[$t]),
        TOTP::compute($seed64, $testTime[$t], 'sha512', 8, $X, $T0));
}

/* 输出结果：
time: 59, date: 1970-01-01 00:00:59, code: 94287082, alg: SHA1
time: 59, date: 1970-01-01 00:00:59, code: 46119246, alg: SHA256
time: 59, date: 1970-01-01 00:00:59, code: 90693936, alg: SHA512
time: 1111111109, date: 2005-03-18 01:58:29, code: 07081804, alg: SHA1
time: 1111111109, date: 2005-03-18 01:58:29, code: 68084774, alg: SHA256
time: 1111111109, date: 2005-03-18 01:58:29, code: 25091201, alg: SHA512
time: 1111111111, date: 2005-03-18 01:58:31, code: 14050471, alg: SHA1
time: 1111111111, date: 2005-03-18 01:58:31, code: 67062674, alg: SHA256
time: 1111111111, date: 2005-03-18 01:58:31, code: 99943326, alg: SHA512
time: 1234567890, date: 2009-02-13 23:31:30, code: 89005924, alg: SHA1
time: 1234567890, date: 2009-02-13 23:31:30, code: 91819424, alg: SHA256
time: 1234567890, date: 2009-02-13 23:31:30, code: 93441116, alg: SHA512
time: 2000000000, date: 2033-05-18 03:33:20, code: 69279037, alg: SHA1
time: 2000000000, date: 2033-05-18 03:33:20, code: 90698825, alg: SHA256
time: 2000000000, date: 2033-05-18 03:33:20, code: 38618901, alg: SHA512
time: 20000000000, date: 2603-10-11 11:33:20, code: 65353130, alg: SHA1
time: 20000000000, date: 2603-10-11 11:33:20, code: 77737706, alg: SHA256
time: 20000000000, date: 2603-10-11 11:33:20, code: 47863826, alg: SHA512
 */
```

