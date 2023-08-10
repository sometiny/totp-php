<?php

namespace Jazor\OTP;

class Base32
{

    private const encode_padding = [
        1 => 6,
        2 => 4,
        3 => 3,
        4 => 1,
    ];
    private const decode_padding = [
        6 => 1,
        4 => 2,
        3 => 3,
        1 => 4,
    ];
    public const base32_encode_lookup_table = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7',
        '='
    ];
    public const base32_decode_lookup_table = [
        'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7,
        'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
        'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
        'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31,
        '=' => 32
    ];

    public const base32_encode_lookup_table_hex = [
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        '='
    ];
    public const base32_decode_lookup_table_hex = [
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7,
        '8' => 8, '9' => 9, 'A' => 10, 'B' => 11, 'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15,
        'G' => 16, 'H' => 17, 'I' => 18, 'J' => 19, 'K' => 20, 'L' => 21, 'M' => 22, 'N' => 23,
        'O' => 24, 'P' => 25, 'Q' => 26, 'R' => 27, 'S' => 28, 'T' => 29, 'U' => 30, 'V' => 31,
        '=' => 32
    ];

    /**
     * make base32 decode
     * @param string $chars
     * @param array $table
     * @return string
     * @throws \Exception
     */
    public static function decode(string $chars, array $table = self::base32_decode_lookup_table): string
    {
        if (empty($chars)) return '';
        $length = strlen($chars);
        while ($chars[$length - 1] === '=') $length--;

        $padding_length = $length % 8;
        if ($padding_length > 0) {
            $padding_length = 8 - $padding_length;
            $chars = str_pad($chars, $length + $padding_length, "=");
        }

        $result = [];
        for ($i = 0; $i < $length; $i += 8) {
            $a = $table[$chars[$i]];
            $b = $table[$chars[$i + 1]];
            $c = $table[$chars[$i + 2]] & 0x1f;
            $d = $table[$chars[$i + 3]] & 0x1f;
            $e = $table[$chars[$i + 4]] & 0x1f;
            $f = $table[$chars[$i + 5]] & 0x1f;
            $g = $table[$chars[$i + 6]] & 0x1f;
            $h = $table[$chars[$i + 7]] & 0x1f;


            $x = ($a << 5 | $b) >> 2;
            $y = ($b & 0x3) << 5 | $c;
            $y = ($y << 5 | $d) >> 4;

            $z = (($d & 0xf) << 5 | $e) >> 1;

            $m = ($e & 0x1) << 5 | $f;

            $m = ($m << 5 | $g) >> 3;

            $n = ($g & 0x7) << 5 | $h;
            array_push($result, $x, $y, $z, $m, $n);
        }

        if ($padding_length > 0) {
            $removeLength = 5 - self::decode_padding[$padding_length];
            while ($removeLength-- > 0) array_pop($result);
        }

        return pack('C*', ...$result);

    }

    /**
     * make base32 encode
     * @param string $binary
     * @param array $table
     * @return string
     */
    public static function encode(string $binary, array $table = self::base32_encode_lookup_table): string
    {
        if (empty($binary)) return '';

        $length = strlen($binary);
        $remain_length = $length % 5;

        if ($remain_length > 0) $binary = str_pad($binary, $length + (5 - $remain_length), "\0");

        $result = '';

        for ($i = 0; $i < $length; $i += 5) {
            $x = ord($binary[$i]);
            $y = ord($binary[$i + 1]);
            $z = ord($binary[$i + 2]);
            $m = ord($binary[$i + 3]);
            $n = ord($binary[$i + 4]);


            $a = $x >> 3;
            $b = (($x & 0x7) << 8 | $y ) >> 6;
            $c = $y >> 1 & 0x1f;
            $d = (($y & 0x1) << 8 | $z ) >> 4;
            $e = (($z & 0xf) << 8 | $m ) >> 7;

            $f = $m >> 2 & 0x1f;

            $g = (($m & 0x3) << 8 | $n ) >> 5;

            $h = $n & 0x1f;

            $result .= sprintf('%s%s%s%s%s%s%s%s', $table[$a], $table[$b], $table[$c], $table[$d], $table[$e], $table[$f], $table[$g], $table[$h]);
        }
        if ($remain_length > 0) {
            $padding = self::encode_padding[$remain_length];
            $length = strlen($result);
            while ($padding-- > 0) $result[--$length] = '=';
        }

        return $result;
    }
}
