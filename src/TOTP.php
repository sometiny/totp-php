<?php

namespace App\Utils;

class TOTP
{
    public const X = 30;
    public const T0 = 0;
    public const HMAC = 'sha1';
    public const RETURN_LENGTH = 6;

    private static array $DIGITS_POWER = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];
    /**
     * make quick compute
     * @param string $key
     * @param int $t
     * @return string
     * @throws \Exception
     */
    public static function generate(
        string $key,
        int    $t = 0): string
    {

        if(strlen($key) !== 32) throw new \Exception('invalid key?key-length must be 32.');
        $key = Base32::quick_decode($key);

        return self::compute($key, $t);
    }

    /**
     * make quick verify
     * @param string $code
     * @param string $key
     * @param int $t
     * @return bool
     * @throws \Exception
     */
    public static function verify(string $code, string $key, int $t): bool
    {
        if(strlen($key) !== 32) throw new \Exception('invalid key?key-length must be 32.');
        $key = Base32::quick_decode($key);

        return $code == self::compute($key, $t);
    }

    /**
     * @param string $key shared secret key, binary
     * @param int $t time ticks
     * @param string $hamc hamc alg, sha1,sha256 and so on
     * @param int $return_length return number length
     * @param int $x step, default 30
     * @param int $t0 base ticks, default 0
     * @return string one time password
     */
    public static function compute(
        string $key,
        int    $t = 0,
        string $hamc = self::HMAC,
        int    $return_length = self::RETURN_LENGTH,
        int    $x = self::X,
        int    $t0 = self::T0): string
    {
        if ($t === 0) $t = time() - $t0;

        $unix_time = $t - $t % $x;
        $t = $unix_time / $x;

        $t = sprintf('%x', $t);

        $t = str_pad($t, 16, '0', STR_PAD_LEFT);

        $msg = hex2bin($t);

        return self::hotp($key, $msg, $hamc, $return_length);
    }

    /**
     * @param string $key shared secret key, binary
     * @param string $counter the counter
     * @param string $hamc hamc alg, sha1,sha256 and so on
     * @param int $return_length return number length
     * @return string
     */
    public static function hotp(
        string $key,
        string $counter,
        string $hamc = self::HMAC,
        int    $return_length = self::RETURN_LENGTH
    ): string
    {
        $hash = hash_hmac($hamc, $counter, $key, true);

        $hash = unpack('C*', $hash);


        $offset = $hash[count($hash)] & 0xf;

        $number = (($hash[$offset + 1] & 0x7f) << 24) |
            (($hash[$offset + 2] & 0xff) << 16) |
            (($hash[$offset + 3] & 0xff) << 8) |
            ($hash[$offset + 4] & 0xff);


        $otp = $number % self::$DIGITS_POWER[$return_length];

        return str_pad($otp . '', $return_length, '0', STR_PAD_LEFT);
    }


    /**
     * @param string $url
     * @return array
     * @throws \Exception
     */
    public static function fromUri(string $url): array
    {
        $isMatch = preg_match('#^otpauth://(totp|hotp)/(.+?)\?(.+?)$#', $url, $match);
        if(!$isMatch) throw new \Exception('invalid url');

        $type = $match[1];
        $label = urldecode($match[2]);
        parse_str($match[3], $parameters);
        if(empty($parameters['secret'])){
            throw new \Exception('secret is necessary!');
        }

        if($type === 'hotp' && empty($parameters['counter'])) {
            throw new \Exception('counter is necessary for hotp!');
        }

        $label_components = [];
        $idx = strpos($label, ':');
        if($idx !== false) {
            $label_components = [
                substr($label, 0, $idx),
                ltrim(substr($label, $idx), ':')
            ];
        }

        return [
            'type' => $type,
            'label' => $label,
            'label_components' => $label_components,
            'secret' => $parameters['secret'],
            'issuer' => $parameters['issuer'] ?? '',
            'algorithm' => $parameters['algorithm'] ?? 'sha1',
            'digits' => $parameters['digits'] ?? 6,
            'counter' => $parameters['counter'] ?? null,
            'period' => $parameters['period'] ?? 30,
        ];
    }
}
