<?php

namespace Jazor\OTP;

class TOTP
{
    public const X = 30;
    public const T0 = 0;
    public const HMAC = 'sha1';
    public const RETURN_LENGTH = 6;

    private const DIGITS_POWER = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

    /**
     * make quick totp
     * @param string $key
     * @param int $t
     * @return string
     * @throws \Exception
     */
    public static function generate(
        string $key,
        int    $t = 0): string
    {

        $key = Base32::decode($key);

        return self::compute($key, $t);
    }

    /**
     * make quick totp verify
     * @param string $code
     * @param string $key
     * @param int $t
     * @return bool
     * @throws \Exception
     */
    public static function verify(string $code, string $key, int $t): bool
    {
        $key = Base32::decode($key);

        return $code == self::compute($key, $t);
    }

    /**
     * full and raw totp implement
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
     * hotp implement
     * @param string $key shared secret key, binary
     * @param string $counter the counter
     * @param string $algorithm hamc algorithm, sha1,sha256 and so on
     * @param int $return_length return number length
     * @return string
     * @throws \Exception
     */
    public static function hotp(
        string $key,
        string $counter,
        string $algorithm = self::HMAC,
        int    $return_length = self::RETURN_LENGTH
    ): string
    {
        if (strlen($counter) !== 8) throw new \Exception('invalid counter, length must be 8');

        $hash = hash_hmac($algorithm, $counter, $key, true);

        $hash = unpack('C*', $hash);


        $offset = $hash[count($hash)] & 0xf;

        $number = (($hash[$offset + 1] & 0x7f) << 24) |
            (($hash[$offset + 2] & 0xff) << 16) |
            (($hash[$offset + 3] & 0xff) << 8) |
            ($hash[$offset + 4] & 0xff);


        $otp = $number % self::DIGITS_POWER[$return_length];

        return str_pad($otp . '', $return_length, '0', STR_PAD_LEFT);
    }
}
