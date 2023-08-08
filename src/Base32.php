<?php

namespace Jazor\OTP;

class Base32
{

    private const base32_lookup_table = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', '2', '3', '4', '5', '6', '7',
        '='
    ];
    private const base32_lookup_table2 = [
        'A' => 0, 'B' => 1, 'C' => 2, 'D' => 3, 'E' => 4, 'F' => 5, 'G' => 6, 'H' => 7,
        'I' => 8, 'J' => 9, 'K' => 10, 'L' => 11, 'M' => 12, 'N' => 13, 'O' => 14, 'P' => 15,
        'Q' => 16, 'R' => 17, 'S' => 18, 'T' => 19, 'U' => 20, 'V' => 21, 'W' => 22, 'X' => 23,
        'Y' => 24, 'Z' => 25, '2' => 26, '3' => 27, '4' => 28, '5' => 29, '6' => 30, '7' => 31,
        '=' => 32
    ];

    private const base32_lookup_table_hex = [
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        '='
    ];
    private const base32_lookup_table2_hex = [
        '0' => 0, '1' => 1, '2' => 2, '3' => 3, '4' => 4, '5' => 5, '6' => 6, '7' => 7,
        '8' => 8, '9' => 9, 'A' => 10, 'B' => 11, 'C' => 12, 'D' => 13, 'E' => 14, 'F' => 15,
        'G' => 16, 'H' => 17, 'I' => 18, 'J' => 19, 'K' => 20, 'L' => 21, 'M' => 22, 'N' => 23,
        'O' => 24, 'P' => 25, 'Q' => 26, 'R' => 27, 'S' => 28, 'T' => 29, 'U' => 30, 'V' => 31,
        '=' => 32
    ];


    private array $encodeTable = self::base32_lookup_table;
    private array $decodeTable = self::base32_lookup_table2;

    private function __construct($useHexTable)
    {
        if ($useHexTable === true) {
            $this->encodeTable = self::base32_lookup_table_hex;
            $this->decodeTable = self::base32_lookup_table2_hex;
        }
    }

    /**
     * @param bool $useHexTable
     * @return Base32
     */
    public static function getInstance(bool $useHexTable = false): Base32
    {
        return new static($useHexTable);
    }

    /**
     * base32 decode
     * @param string $source
     * @return string
     * @throws \Exception
     */
    public function decode(string $source): string
    {
        return self::quick_decode($source, $this->decodeTable);
    }


    /**
     * base32 encode
     * @param string $source
     * @return string
     * @throws \Exception
     */
    public function encode(string $source): string
    {
        return self::quick_encode($source, $this->encodeTable);
    }

    /**
     * quick decode
     * @param string $str
     * @param array $table
     * @return string
     * @throws \Exception
     */
    public static function quick_decode(string $str, array $table = self::base32_lookup_table2): string
    {
        if (empty($str)) return '';

        $bytes = self::decode_raw(array_map(function ($t) use($table) {
            return $table[$t];
        }, str_split($str)));

        return pack('C*', ...$bytes);

        /*
        array_unshift($result, 'C*');
        return call_user_func_array('pack', $result);
        */
    }

    /**
     * quick encode
     * @param string $binary
     * @param array $table
     * @return string
     */
    public static function quick_encode(string $binary, array $table = self::base32_lookup_table): string
    {
        if (empty($binary)) return '';

        $chars = self::encode_raw(array_values(unpack('C*', $binary)));

        $chars = array_map(function ($t) use ($table) {
            return $table[$t];
        }, $chars);

        return implode('', $chars);
    }


    /**
     * make final
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
     * make raw decode, without table
     * @param array $chars
     * @return array
     * @throws \Exception
     */
    private static function decode_raw(array $chars): array
    {
        if (empty($chars)) return [];
        $length = count($chars);
        while ($chars[$length - 1] === 32) {
            $length--;
        }
        $first_length = $length - $length % 8;
        $remain_length = $length % 8;


        $result = [];
        for ($i = 0; $i < $first_length; $i += 8) {
            $a = $chars[$i];
            $b = $chars[$i + 1];
            $c = $chars[$i + 2];
            $d = $chars[$i + 3];
            $e = $chars[$i + 4];
            $f = $chars[$i + 5];
            $g = $chars[$i + 6];
            $h = $chars[$i + 7];


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
                $raws[$i] = $chars[$first_length + $i];
            }
            self::decode_final($result, $raws, $remain_length);
        }

        return $result;

    }

    /**
     * final encode
     * @param array $result
     * @param array $raws
     * @param int $remain_length
     * @return void
     */
    private static function encode_final(array &$result, array $raws, int $remain_length)
    {
        list($x, $y, $z, $m, $n) = $raws;
        $result[] = $x >> 3;
        if ($remain_length === 1) {
            $result[] = ($x & 0x7) << 2;
            return;
        }
        $result[] = (($x & 0x7) << 2) | ($y >> 6);
        $result[] = ($y >> 1) & 0x1f;
        if ($remain_length === 2) {
            $result[] = ($y & 0x1) << 4;
            return;
        }
        $result[] = (($y & 0x1) << 4) | ($z >> 4);
        if ($remain_length === 3) {
            $result[] = ($z & 0xf) << 1;
            return;
        }

        $result[] = (($z & 0xf) << 1) | ($m >> 7);
        $result[] = ($m >> 2) & 0x1f;
        $result[] = ($m & 0x3) << 3;

    }

    /**
     * make raw encode, without table
     * @param array $bytes
     * @return array
     */
    private static function encode_raw(array $bytes): array
    {
        if (empty($bytes)) return [];

        $length = count($bytes);
        $first_length = $length - $length % 5;
        $remain_length = $length % 5;

        $result = [];

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

            array_push($result, $a, $b, $c, $d, $e, $f, $g, $h);
        }
        if ($remain_length > 0) {
            $raws = array_fill(0, 5, 0);
            for ($i = 0; $i < $remain_length; $i++) {
                $raws[$i] = $bytes[$first_length + $i];
            }
            self::encode_final($result, $raws, $remain_length);
            while (count($result) % 8 !== 0) $result[] = 32;
        }

        return $result;
    }
}
