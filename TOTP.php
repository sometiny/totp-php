<?php

class TOTP
{
    public const X = 30;
    public const T0 = 0;
    public const HMAC = 'sha1';
    public const RETURN_LENGTH = 6;

    private static array $DIGITS_POWER = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

    /**
     * @param $key string shared secret key, binary
     * @param $t integer time ticks
     * @param $hamc string hmac alg, sha1,sha256 and so on
     * @param $return_length integer return number length
     * @param $x integer step, default 30
     * @param $t0 integer base ticks, default 0
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


        $hash = hash_hmac($hamc, $msg, $key, true);

        $hash = unpack('C*', $hash);


        $offset = $hash[count($hash)] & 0xf;

        $number = (($hash[$offset + 1] & 0x7f) << 24) |
            (($hash[$offset + 2] & 0xff) << 16) |
            (($hash[$offset + 3] & 0xff) << 8) |
            ($hash[$offset + 4] & 0xff);


        $otp = $number % self::$DIGITS_POWER[$return_length];

        return str_pad($otp . '', $return_length, '0', STR_PAD_LEFT);
    }
}
