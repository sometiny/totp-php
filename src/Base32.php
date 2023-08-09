<?php

namespace Jazor\OTP;

class Base32
{

    private const base32_encode_lookup_table = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7',
        '='
    ];
    private const base32_decode_lookup_table = [
        'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7,
        'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
        'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
        'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31,
        '=' => 32
    ];

    private const base32_encode_lookup_table_hex = [
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        '='
    ];
    private const base32_decode_lookup_table_hex = [
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7,
        '8' => 8, '9' => 9, 'A' => 10, 'B' => 11, 'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15,
        'G' => 16, 'H' => 17, 'I' => 18, 'J' => 19, 'K' => 20, 'L' => 21, 'M' => 22, 'N' => 23,
        'O' => 24, 'P' => 25, 'Q' => 26, 'R' => 27, 'S' => 28, 'T' => 29, 'U' => 30, 'V' => 31,
        '=' => 32
    ];

    /**
     * decode final
     * @param array $result
     * @param array $bytes
     * @param int $remain_length
     * @return void
     * @throws \Exception
     */
    private static function decode_final(array &$result, array $bytes, int $remain_length)
    {

        list($a, $b, $c, $d, $e, $f, $g, $h) = $bytes;
        $x = (($a << 5) | $b) >> 2;
        if ($remain_length === 2) {
            $result[] = $x;
            return;
        }
        $y = (($b & 0x3) << 5) | $c;
        $y = (($y << 5) | $d) >> 4;

        if ($remain_length === 4) {
            array_push($result, $x, $y);
            return;
        }

        $z = ((($d & 0xf) << 5) | $e) >> 1;
        if ($remain_length === 5) {
            array_push($result, $x, $y, $z);
            return;
        }
        if ($remain_length === 7) {
            $m = (($e & 0x1) << 5) | $f;

            $m = (($m << 5) | $g) >> 3;
            array_push($result, $x, $y, $z, $m);
            return;
        }
        throw new \Exception('invalid base32 source');
    }


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
        while ($chars[$length - 1] === '=') {
            $length--;
        }
        $first_length = $length - $length % 8;
        $remain_length = $length % 8;


        $result = [];
        for ($i = 0; $i < $first_length; $i += 8) {
            $a = $table[$chars[$i]];
            $b = $table[$chars[$i + 1]];
            $c = $table[$chars[$i + 2]];
            $d = $table[$chars[$i + 3]];
            $e = $table[$chars[$i + 4]];
            $f = $table[$chars[$i + 5]];
            $g = $table[$chars[$i + 6]];
            $h = $table[$chars[$i + 7]];


            $x = (($a << 5) | $b) >> 2;
            $y = (($b & 0x3) << 5) | $c;
            $y = (($y << 5) | $d) >> 4;

            $z = ((($d & 0xf) << 5) | $e) >> 1;

            $m = (($e & 0x1) << 5) | $f;

            $m = (($m << 5) | $g) >> 3;

            $n = (($g & 0x7) << 5) | $h;
            array_push($result, $x, $y, $z, $m, $n);
        }

        if ($remain_length > 0) {
            $raws = array_fill(0, 8, 0);
            for ($i = 0; $i < $remain_length; $i++) {
                $raws[$i] = $table[$chars[$first_length + $i]];
            }
            self::decode_final($result, $raws, $remain_length);
        }

        return pack('C*', ...$result);;

    }

    /**
     * final encode
     * @param string $result
     * @param array $raws
     * @param int $remain_length
     * @param array $table
     * @return void
     */
    private static function encode_final(string &$result, array $raws, int $remain_length, array $table)
    {
        list($x, $y, $z, $m, $n) = $raws;
        $result .= $table[$x >> 3];
        if ($remain_length === 1) {
            $result .= $table[($x & 0x7) << 2];
            return;
        }
        $result .= $table[(($x & 0x7) << 2) | ($y >> 6)];
        $result .= $table[($y >> 1) & 0x1f];
        if ($remain_length === 2) {
            $result .= $table[($y & 0x1) << 4];
            return;
        }
        $result .= $table[(($y & 0x1) << 4) | ($z >> 4)];
        if ($remain_length === 3) {
            $result .= $table[($z & 0xf) << 1];
            return;
        }

        $result .= $table[(($z & 0xf) << 1) | ($m >> 7)];
        $result .= $table[($m >> 2) & 0x1f];
        $result .= $table[($m & 0x3) << 3];

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
        $bytes = array_values(unpack('C*', $binary));

        $length = count($bytes);
        $first_length = $length - $length % 5;
        $remain_length = $length % 5;

        $result = '';

        for ($i = 0; $i < $first_length; $i += 5) {
            $x = $bytes[$i];
            $y = $bytes[$i + 1];
            $z = $bytes[$i + 2];
            $m = $bytes[$i + 3];
            $n = $bytes[$i + 4];


            $a = $x >> 3;
            $b = (($x & 0x7) << 2) | ($y >> 6);
            $c = ($y >> 1) & (0x1f);
            $d = (($y & 0x1) << 4) | ($z >> 4);
            $e = (($z & 0xf) << 1) | ($m >> 7);

            $f = ($m >> 2) & 0x1f;

            $g = (($m & 0x3) << 3) | ($n >> 5);

            $h = $n & 0x1f;

            $result .= sprintf('%s%s%s%s%s%s%s%s', $table[$a], $table[$b], $table[$c], $table[$d], $table[$e], $table[$f], $table[$g], $table[$h]);
        }
        if ($remain_length > 0) {
            $raws = array_fill(0, 5, 0);
            for ($i = 0; $i < $remain_length; $i++) {
                $raws[$i] = $bytes[$first_length + $i];
            }
            self::encode_final($result, $raws, $remain_length, $table);
            while (strlen($result) % 8 !== 0) $result .= '=';
        }

        return $result;
    }
}
