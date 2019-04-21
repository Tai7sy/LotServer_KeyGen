<?php
/**
 * Created by PhpStorm.
 * User: Windy
 * Date: 2019/4/21
 * Time: 10:08:20
 */


function __ROL4__($decimal, $bits)
{
    $binary = decbin($decimal);
    $binary = str_pad($binary, 32, '0', STR_PAD_LEFT);
    return (
    bindec(substr($binary, $bits) . substr($binary, 0, $bits))
    );
}

function _DWORD_TO_BYTES($ARR)
{
    $bytes = '';
    for ($i = 0; $i < count($ARR); $i++) {
        $bin = hex2bin(dechex($ARR[$i]));
        $bytes .= $bin{3};
        $bytes .= $bin{2};
        $bytes .= $bin{1};
        $bytes .= $bin{0};
    }
    return $bytes;
}

function APX_ProtInitContext($Id, $IdLen, $Key, $KeyLen, &$ProtContext)
{
    $result = $KeyLen;
    $v6 = 0;
    $v7 = 0;

    $ProtContext[0] = 0;
    $ProtContext[1] = 0;
    if ($IdLen) {
        while (1) {
            $v7 = 0;
            $v8 = 0;
            if ($IdLen) {
                do {
                    $v9 = ord($Id[$v8]);
                    $v10 = 8 * $v8++;
                    $v7 |= $v9 << $v10;
                } while ($v8 < $IdLen && $v8 <= 3);
            }
            if ($IdLen <= 3)
                break;
            $v11 = substr($Id, 4);
            $v12 = $IdLen - 4;
            if ($v12) {
                $v13 = 0;
                $v14 = 0;
                do {
                    $v15 = ord($v11[$v14]);
                    $v16 = 8 * $v14++;
                    $v13 |= $v15 << $v16;
                } while ($v12 > $v14 && $v14 <= 3);
            } else {
                $v13 = 0;
            }
            if ($v12 <= 3)
                goto LABEL_18;
            $v6 += $v7;
            $ProtContext[1] += $v13;
            $IdLen = $v12 - 4;
            $ProtContext[0] = $v6;
            if (!$IdLen)
                goto LABEL_19;
            $Id = substr($v11, 4);
        }
        $v13 = 0;
        LABEL_18:
        $ProtContext[1] += $v13;
        $ProtContext[0] = $v6 + $v7;
    }
    LABEL_19:
    $v17 = $result;
    $v18 = 0;
    do {
        if ($v18 < $v17 && $result) {
            $v19 = 0;
            $v20 = 0;
            do {
                $v21 = ord($Key[$v18 + $v20]);
                $v22 = 8 * $v20++;
                $v19 |= $v21 << $v22;
            } while ($v20 < $result && $v20 <= 3);
            $v23 = $v19 - 1515870811;
        } else {
            $v23 = -1515870811;
        }
        $ProtContext[$v18 / 4 + 2] = $v23;
        $v18 += 4;
        $result = $result - 4;
    } while ($v18 != 32);

    // echo "5ee6dfca 74636573 d31e1606 1a090b18 d714150e a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5 \n";
    // $bytes = _DWORD_TO_BYTES($ProtContext);
    // hex_dump($bytes,strlen($bytes));
    return $result;
}

function APX_ProtUpdateContext(&$ProtContext)
{
    $edx = $ProtContext[1] + 0x74656E78;
    $_tmp = $ProtContext[0] + 0x45505041;

    $v2 = $ProtContext[2] + __ROL4__($_tmp ^ $edx, $edx & 0x1F);
    $v3 = $ProtContext[3] + __ROL4__($edx ^ $v2, $v2 & 0x1F);

    $v4 = $ProtContext[4] + __ROL4__($v3 ^ $v2, $v3 & 0x1F);
    $v5 = $ProtContext[5] + __ROL4__($v4 ^ $v3, $v4 & 0x1F);
    $v6 = $ProtContext[6] + __ROL4__($v5 ^ $v4, $v5 & 0x1F);
    $v7 = $ProtContext[7] + __ROL4__($v6 ^ $v5, $v6 & 0x1F);
    $result = $ProtContext[8] + __ROL4__($v7 ^ $v6, $v7 & 0x1F);
    $ProtContext[0] = $result;
    $ProtContext[1] = $ProtContext[9] + __ROL4__($result ^ $v7, $result & 0x1F);

    return $result;
}

function APX_ProtUninitContext(&$ProtContext)
{
    return 0;
}

function APX_ProtDecrypt($Id, $IdLen, $Key, $KeyLen, $CipherText, $CipherTextLen, &$OutPlainText)
{
    $v8 = $CipherTextLen;
    $v7 = 0;
    $v9 = 0;
    APX_ProtInitContext($Id, $IdLen, $Key, $KeyLen, $ProtContext);
    if ($v8) {
        for ($i = 0; ; $i = $v11) {
            $v11 = 0;
            $v12 = 0;
            do {
                $v13 = $v12;
                $v14 = 8 * $v12++;
                $v11 |= ord($CipherText{$v7 + $v13}) << $v14;
            } while ($v12 < $v8 && $v12 <= 3);
            APX_ProtUpdateContext($ProtContext);
            $v15 = 0;
            $v16 = $v11 - $i - $ProtContext[0];
            do {
                $v17 = $v15++;
                $OutPlainText{$v9 + $v17} = chr($v16 & 0xFF);
                $v16 >>= 8;
            } while ($v15 < $v8 && $v15 <= 3);
            if ($v8 <= 4)
                break;
            $v7 += 4;
            $v9 += 4;
            $v8 -= 4;
        }
    }
    APX_ProtUninitContext($ProtContext);
}

function APX_ProtEncrypt($Id, $IdLen, $Key, $KeyLen, $PlainText, $PlainTextLen, &$OutCipherText)
{
    $v8 = $PlainTextLen;
    $v7 = 0;
    $v9 = 0;
    APX_ProtInitContext($Id, $IdLen, $Key, $KeyLen, $ProtContext);
    if ($v8) {
        $v10 = 0;
        while (1) {
            $v11 = 0;
            $v12 = 0;
            do {
                $v13 = $v12;
                $v14 = 8 * $v12++;
                $v11 |= ord($PlainText{$v7 + $v13}) << $v14;
            } while ($v12 < $v8 && $v12 <= 3);
            APX_ProtUpdateContext($ProtContext);
            $v15 = 0;
            $v10 += $v11 + $ProtContext[0];
            $v16 = $v10;
            do {
                $v17 = $v15++;
                $OutCipherText{$v9 + $v17} = chr($v16 & 0xFF);
                $v16 >>= 8;
            } while ($v15 < $v8 && $v15 <= 3);
            if ($v8 <= 4)
                break;
            $v7 += 4;
            $v9 += 4;
            $v8 -= 4;
        }
    }
    APX_ProtUninitContext($ProtContext);
}

function hex_dump($data, $len = false)
{
    if ($len === false) {
        $len = count($data);
    }
    for ($i = 0; $i < $len; $i++) {
        $out = dechex(ord($data[$i]));
        if (strlen($out) === 1) $out = '0' . $out;
        echo $out . ' ';
        if (($i + 1) % 16 === 0) echo "\n";
    }
    echo "\n";
}


global $key, $lic_len;
$key = 'apx-section1';
$lic_len = 160;


function view_lic($buffer)
{
    global $key, $lic_len;
    $licInfo = str_repeat(chr(0), $lic_len);
    APX_ProtDecrypt($key, strlen($key), $key, strlen($key), $buffer, $lic_len, $licInfo);
    // hex_dump($licInfo, $lic_len);
    /*
    8e 4c 15 ca e9 0d d0 23 da 24 13 41 69 09 1d 30
    bc d4 2a 98 df 3c 45 8c 23 49 38 d3 b6 4f f4 dc
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    35 43 43 38 35 46 46 33 42 31 45 30 36 38 44 35
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    e3 07 0a 17 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    fe 03 00 01 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 3e ed 8f 03 00 00 00 00
    */

    echo "License: " . substr($licInfo, 0x40, 0x10) . "\n";
    echo "MaxSession: " . unpack('V', substr($licInfo, 0x70, 4))[1] . "\n";
    echo "MaxTcpAccSession: " . unpack('V', substr($licInfo, 0x74, 4))[1] . "\n";
    echo "MaxCompSession: " . unpack('V', substr($licInfo, 0x78, 4))[1] . "\n";
    echo "MaxByteCacheSession: " . unpack('V', substr($licInfo, 0x7C, 0x4))[1] . "\n";
    echo "MaxBandwidth: " . unpack('V', substr($licInfo, 0x68, 4))[1] . "\n";
    echo "ExpireDate: " .
        unpack('v', substr($licInfo, 0x60, 2))[1] . "-" .
        ord($licInfo[0x62]) . "-" .
        ord($licInfo[0x63]) . "\n";

    return $licInfo;
}


$lic_path = 'apx_01_23.lic';
$buffer = file_get_contents($lic_path);
$licInfo = view_lic($buffer);

echo " \n \nModified:\n";


$year = 2099;
$licInfo{0x60} = pack('v', $year)[0];
$licInfo{0x61} = pack('v', $year)[1];
APX_ProtEncrypt($key, strlen($key), $key, strlen($key), $licInfo, $lic_len, $modified_lic);

file_put_contents('out.lic', $modified_lic);
view_lic($modified_lic);