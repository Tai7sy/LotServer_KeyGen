<?php
/**
 * Created by PhpStorm.
 * User: Windy
 * Date: 2019/4/21
 * Time: 10:08:20
 */

if (php_sapi_name() === 'cli') {
    if ($argc <= 1) {
        die("
    Usage: 
        php keygen.php [mac]
        For example, php keygen.php 00:00:00:00:00:00
    ");
    }
    $mac = $argv[1];
    $version = isset($argv[2]) ? intval($argv[2]) : 1;
    $verbose = @$argv[2] === 'v' || @$argv[3] === 'v';
} else {
    if (!isset($_GET['mac'])) {
        die("Please input a mac address.\n");
    }
    $mac = $_GET['mac'];
    $version = isset($_GET['ver']) ? intval($_GET['ver']) : 1;
    $verbose = false;
}

if (strlen($mac) !== 17) // 00:00:00:00:00:00
    die("Invalid mac address\n");

global $key, $lic_len;
$key = 'apx-section1';

switch ($version) {
    case 0:
        $lic_len = 0x98;
        $lic_path = '.template_old.lic';
        function Decrypt($Key, $KeyLen, $CipherText, $CipherTextLen, &$OutPlainText)
        {
            APX_ProtDecrypt($Key, $KeyLen, $Key, $KeyLen, $CipherText, $CipherTextLen, $OutPlainText);
        }

        function Encrypt($Key, $KeyLen, $PlainText, $PlainTextLen, &$OutCipherText)
        {
            APX_ProtEncrypt($Key, $KeyLen, $Key, $KeyLen, $PlainText, $PlainTextLen, $OutCipherText);
        }

        break;
    case 1:
        $lic_len = 0xA0;
        $lic_path = '.template_3.11.20.10.lic';
        function Decrypt($Key, $KeyLen, $CipherText, $CipherTextLen, &$OutPlainText)
        {
            APX_ProtDecrypt_New($Key, $KeyLen, $Key, $KeyLen, $CipherText, $CipherTextLen, $OutPlainText);
        }

        function Encrypt($Key, $KeyLen, $PlainText, $PlainTextLen, &$OutCipherText)
        {
            APX_ProtEncrypt_New($Key, $KeyLen, $Key, $KeyLen, $PlainText, $PlainTextLen, $OutCipherText);
        }

        break;
    default:
        die("undefined version\n");
}

if (!is_file($lic_path)) {
    die("please give a template lic! \n");
}
$buffer = file_get_contents($lic_path);
if (strlen($buffer) !== $lic_len) {
    echo("template lic error! \n");
    exit;
}

// decrypt old license
$lic_info = decode_lic($buffer, $verbose);
$verbose && hex_dump($lic_info);

// hack it
modify_mac($lic_info, $mac);
modify_expire($lic_info, 2099, 12, 31);
modify_hash($lic_info, $version);

// encrypt and output
$modified_lic = str_repeat(chr(0), $lic_len);
Encrypt($key, strlen($key), $lic_info, $lic_len, $modified_lic);
if (php_sapi_name() === 'cli') {
    file_put_contents('out.lic', $modified_lic); // 将MAC地址写到文件
    echo "\nHexView:\n";
    hex_dump($modified_lic);
    echo "\n";
    $lic_info = decode_lic($modified_lic);
    $verbose && hex_dump($lic_info);
    echo "\n----> Output: out.lic\n";
} else {
    header('Content-type:application/octet-stream');
    header('Accept-Ranges:bytes');
    header('Accept-Length:' . $lic_len);
    header('Content-Disposition: attachment; filename=out.lic');
    echo $modified_lic;
}

function decode_lic($buffer, $output = true)
{
    global $key, $lic_len;
    $lic_info = str_repeat(chr(0), $lic_len);
    Decrypt($key, strlen($key), $buffer, $lic_len, $lic_info);
    // hex_dump($lic_info, $lic_len);
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

    if ($output) {
        echo "License: " . substr($lic_info, 0x40, 0x10) . "\n";
        echo "MaxSession: " . unpack('V', substr($lic_info, 0x70, 4))[1] . "\n";
        echo "MaxTcpAccSession: " . unpack('V', substr($lic_info, 0x74, 4))[1] . "\n";
        echo "MaxCompSession: " . unpack('V', substr($lic_info, 0x78, 4))[1] . "\n";
        echo "MaxByteCacheSession: " . unpack('V', substr($lic_info, 0x7C, 0x4))[1] . "\n";
        echo "MaxBandwidth: " . unpack('V', substr($lic_info, 0x68, 4))[1] . "\n";
        echo "ExpireDate: " .
            unpack('v', substr($lic_info, 0x60, 2))[1] . "-" .
            ord($lic_info[0x62]) . "-" .
            ord($lic_info[0x63]) . "\n";
    }
    return $lic_info;
}

/**
 * 修改到期时间
 * @param $lic_info
 * @param $year
 * @param int $month
 * @param int $day
 */
function modify_expire(&$lic_info, $year, $month = 12, $day = 31)
{
    $lic_info{0x60} = pack('v', $year)[0];
    $lic_info{0x61} = pack('v', $year)[1];
    $lic_info{0x62} = chr($month);
    $lic_info{0x63} = chr($day);
}

/**
 * 修改MAC地址
 * @param $lic_info
 * @param $mac
 * @param string $ip
 */
function modify_mac(&$lic_info, $mac, $ip = '172.27.0.14')
{
    global $key, $lic_len;
    /**
     * 网卡顺序
     * .rodata:0000000000485B00                                         ; "lo"
     * .rodata:0000000000485B08 dq offset aSit                          ; "sit"
     * .rodata:0000000000485B10 dq offset aStf                          ; "stf"
     * .rodata:0000000000485B18 dq offset aGif                          ; "gif"
     * .rodata:0000000000485B20 dq offset aDummy                        ; "dummy"
     * .rodata:0000000000485B28 dq offset aVmnet                        ; "vmnet"
     * .rodata:0000000000485B30 dq offset aVir                          ; "vir"
     * .rodata:0000000000485B38 dq offset aIp6gre+3                     ; "gre"
     * .rodata:0000000000485B40 dq offset aIpip                         ; "ipip"
     * .rodata:0000000000485B48 dq offset aPpp                          ; "ppp"
     * .rodata:0000000000485B50 dq offset aBond                         ; "bond"
     * .rodata:0000000000485B58 dq offset aTun                          ; "tun"
     * .rodata:0000000000485B60 dq offset aTap                          ; "tap"
     * .rodata:0000000000485B68 dq offset aIp6gre                       ; "ip6gre"
     * .rodata:0000000000485B70 dq offset aIp6tnl                       ; "ip6tnl"
     * .rodata:0000000000485B78 dq offset aTeql                         ; "teql"
     * .rodata:0000000000485B80 dq offset aIpVti                        ; "ip_vti"
     */


    // 计算MAC地址
    $mac_arr = explode(':', $mac);
    $mac_bin = '';
    foreach ($mac_arr as $mac_i) {
        $mac_bin .= chr(hexdec($mac_i));
    }
    // hex_dump($mac_bin);

    $mac_hash = str_pad($mac_bin, 0x10, chr(0), STR_PAD_RIGHT);
    for ($i = 0; $i < 0x10; $i++) {
        $mac_hash[$i] = chr(ord($mac_hash[$i % 6]) + $i);
    }
    // hex_dump($mac_hash);

    $license = '';
    for ($i = 0; $i < 0x8; $i++) {
        $calc = (ord($mac_hash[$i]) + ord($mac_hash[$i + 8])) & 0xFF;
        $license .= sprintf("%02X", $calc);
    }

    $hash2 = hex2bin(str_pad(dechex(unpack('V', pack('N', ip2long($ip)))[1]), 0x8, '0', STR_PAD_LEFT));
    $hash2{0} = chr(ord($hash2{0}) ^ ord($mac_hash{0}));
    $hash2{1} = chr(ord($hash2{1}) ^ ord($mac_hash{1}));
    $hash2{2} = chr(ord($hash2{2}) ^ ord($mac_hash{2}));
    $hash2{3} = chr(ord($hash2{3}) ^ ord($mac_hash{3}));
    $hash2 = dechex(unpack('V', $hash2)[1]); // 用于lic绑定IP


    if (php_sapi_name() === 'cli') {
        // echo "(license " . $license . $hash2 . ")\n"; // 不校验IP ~~~
        echo "(license " . $license . ")\n";
    }
    for ($i = 0x40; $i < 0x50; $i++) {
        $lic_info{$i} = $license{$i - 0x40};
    }
}

/**
 * 修改校验位
 * @param $lic_info
 * @param $version
 */
function modify_hash(&$lic_info, $version)
{
    global $key, $lic_len;

    if ($version === 0) {
        // 全是0, 干脆固定不改了
//        $hash_ret = str_repeat(chr(0), 0x20);
//        Decrypt($key, strlen($key), $lic_info, 0x20, $hash_ret);
//        hex_dump($hash_ret);
//        exit;
    } elseif ($version === 1) {
        // 随机数
        /**
         * lic 的前面 0x20 字节是
         * 35 39 37 36 34 30 33 30 00 00 00 00 00 00 00 00   <-  sprintf("%d", unpack('V', substr($tmp, 0x98, 4))[1]);
         * 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         * 加密后的结果
         */
//        $hash_ret = str_repeat(chr(0), 0x20);
//        Decrypt($key, strlen($key), $lic_info, 0x20, $hash_ret);
//        hex_dump($hash_ret);
//        exit;
        $tmp = $lic_info;
        // $hash = sprintf("%d", unpack('V', substr($lic_info, 0x98, 0x4))[1]);
        $hash = sprintf("%d", rand(0, 0x7FFFFFFF));
        for ($i = 0; $i < 0x20; $i++) {
            if ($i < strlen($hash))
                $tmp[$i] = $hash[$i];
            else
                $tmp[$i] = chr(0);
        }
        $hash_ret = str_repeat(chr(0), 0x20);
        Encrypt($key, strlen($key), $tmp, 0x20, $hash_ret);
        // hex_dump($tmp);
        // hex_dump($hash_ret);

        $lic_info{0x98} = pack('V', $hash)[0];
        $lic_info{0x99} = pack('V', $hash)[1];
        $lic_info{0x9A} = pack('V', $hash)[2];
        $lic_info{0x9B} = pack('V', $hash)[3];

        for ($i = 0; $i < 0x20; $i++) {
            $lic_info{$i} = $hash_ret{$i};
        }
    }
}

function __ROL4__($decimal, $bits)
{
    $binary = decbin($decimal);
    $binary = str_pad($binary, 32, '0', STR_PAD_LEFT);
    return (
    bindec(substr($binary, $bits) . substr($binary, 0, $bits))
    );
}

function _INT32($val)
{
    return $val & 0xFFFFFFFF;
}

function _DWORD_TO_BYTES($ARR)
{
    $bytes = '';
    for ($i = 0; $i < count($ARR); $i++) {
        $bytes .= pack('V', $ARR[$i]);
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
                    $v7 = _INT32($v7 | ($v9 << $v10));
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
                    $v13 = _INT32($v13 | ($v15 << $v16));
                } while ($v12 > $v14 && $v14 <= 3);
            } else {
                $v13 = 0;
            }
            if ($v12 <= 3)
                goto LABEL_18;
            $v6 = _INT32($v6 + $v7);
            $ProtContext[1] = _INT32($ProtContext[1] + $v13);
            $IdLen = $v12 - 4;
            $ProtContext[0] = $v6;
            if (!$IdLen)
                goto LABEL_19;
            $Id = substr($v11, 4);
        }
        $v13 = 0;
        LABEL_18:
        $ProtContext[1] = _INT32($ProtContext[1] + $v13);
        $ProtContext[0] = _INT32($v6 + $v7);
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
                $v19 = _INT32($v19 | ($v21 << $v22));
            } while ($v20 < $result && $v20 <= 3);
            $v23 = _INT32($v19 - 1515870811);
        } else {
            $v23 = -1515870811;
        }
        $ProtContext[$v18 / 4 + 2] = $v23;
        $v18 += 4;
        $result = $result - 4;
    } while ($v18 != 32);

    // echo "5ee6dfca 74636573 d31e1606 1a090b18 d714150e a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5 a5a5a5a5 \n";
    // $bytes = _DWORD_TO_BYTES($ProtContext);
    // hex_dump($bytes, strlen($bytes));
    return $result;
}

function APX_ProtUpdateContext(&$ProtContext)
{
    $edx = _INT32($ProtContext[1] + 0x74656E78);
    $_tmp = _INT32($ProtContext[0] + 0x45505041);

    $v2 = _INT32($ProtContext[2] + __ROL4__($_tmp ^ $edx, $edx & 0x1F));
    $v3 = _INT32($ProtContext[3] + __ROL4__($edx ^ $v2, $v2 & 0x1F));

    $v4 = _INT32($ProtContext[4] + __ROL4__($v3 ^ $v2, $v3 & 0x1F));
    $v5 = _INT32($ProtContext[5] + __ROL4__($v4 ^ $v3, $v4 & 0x1F));
    $v6 = _INT32($ProtContext[6] + __ROL4__($v5 ^ $v4, $v5 & 0x1F));
    $v7 = _INT32($ProtContext[7] + __ROL4__($v6 ^ $v5, $v6 & 0x1F));
    $result = _INT32($ProtContext[8] + __ROL4__($v7 ^ $v6, $v7 & 0x1F));
    $ProtContext[0] = _INT32($result);
    $ProtContext[1] = _INT32($ProtContext[9] + __ROL4__($result ^ $v7, $result & 0x1F));

    return $result;
}

function APX_ProtUninitContext(&$ProtContext)
{
    return 0;
}

/**
 * Version >= 3.11.20.10
 * @param string $Id
 * @param int $IdLen
 * @param string $Key
 * @param int $KeyLen
 * @param string $CipherText
 * @param int $CipherTextLen
 * @param string $OutPlainText
 */
function APX_ProtDecrypt_New($Id, $IdLen, $Key, $KeyLen, $CipherText, $CipherTextLen, &$OutPlainText)
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
                $v11 = _INT32($v11 | (ord($CipherText{$v7 + $v13}) << $v14));
            } while ($v12 < $v8 && $v12 <= 3);
            APX_ProtUpdateContext($ProtContext);
            $v15 = 0;
            $v16 = _INT32($v11 - $i - $ProtContext[0]);
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

/**
 * Version >= 3.11.20.10
 * @param string $Id
 * @param int $IdLen
 * @param string $Key
 * @param int $KeyLen
 * @param string $PlainText
 * @param int $PlainTextLen
 * @param string $OutCipherText
 */
function APX_ProtEncrypt_New($Id, $IdLen, $Key, $KeyLen, $PlainText, $PlainTextLen, &$OutCipherText)
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
                $v11 = _INT32($v11 | (ord($PlainText{$v7 + $v13}) << $v14));
            } while ($v12 < $v8 && $v12 <= 3);
            APX_ProtUpdateContext($ProtContext);
            $v15 = 0;
            $v10 = _INT32($v10 + $v11 + $ProtContext[0]);
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

/**
 * 用于代码加解密以及 LotServer < 3.11.20.10 时lic加解密
 * @param string $Id
 * @param int $IdLen
 * @param string $Key
 * @param int $KeyLen
 * @param string $CipherText
 * @param int $CipherTextLen
 * @param string $OutPlainText
 */
function APX_ProtDecrypt($Id, $IdLen, $Key, $KeyLen, $CipherText, $CipherTextLen, &$OutPlainText)
{
    $v7 = $CipherTextLen;
    $v8 = $CipherText;
    APX_ProtInitContext($Id, $IdLen, $Key, $KeyLen, $ProtContext);

    for ($i = 0; $v7; $v7 -= 4) {
        $v10 = 0;
        $v11 = 0;
        if ($v7) {
            do {
                $v13 = ord($v8{$i + $v11});
                $v14 = _INT32(8 * $v11++);
                $v10 = _INT32($v10 | ($v13 << $v14));
            } while ($v11 < $v7 && $v11 <= 3);
            $v15 = $i;
            APX_ProtUpdateContext($ProtContext);
            $v16 = _INT32($v10 - $ProtContext[0]);
            $v17 = 0;
            $v21 = $v15;
            do {
                $v18 = $v17++;
                $OutPlainText{$i + $v18} = chr($v16 & 0xFF);
                // var_dump(dechex(ord($OutPlainText{$i + $v18})));
                $v16 >>= 8;
            } while ($v17 < $v7 && $v17 <= 3);
        } else {
            $v20 = $i;
            APX_ProtUpdateContext($ProtContext);
            $v21 = $v20;
        }
        if ($v7 <= 4)
            break;
        $i = $v21 + 4;
    }
    APX_ProtUninitContext($ProtContext);
}

/**
 * 用于代码加解密以及 LotServer < 3.11.20.10 时lic加解密
 * @param string $Id
 * @param int $IdLen
 * @param string $Key
 * @param int $KeyLen
 * @param string $PlainText
 * @param int $PlainTextLen
 * @param string $OutCipherText
 */
function APX_ProtEncrypt($Id, $IdLen, $Key, $KeyLen, $PlainText, $PlainTextLen, &$OutCipherText)
{
    $v7 = $PlainTextLen;
    $v8 = $PlainText;
    APX_ProtInitContext($Id, $IdLen, $Key, $KeyLen, $ProtContext);
    for ($i = 0; $v7; $v7 -= 4) {
        $v10 = 0;
        $v11 = 0;
        if ($v7) {
            do {
                $v13 = ord($v8{$i + $v11});
                $v14 = _INT32(8 * $v11++);
                $v10 = _INT32($v10 | ($v13 << $v14));
            } while ($v11 < $v7 && $v11 <= 3);
            $v15 = $i;
            APX_ProtUpdateContext($ProtContext);
            $v16 = _INT32($ProtContext[0] + $v10);
            $v17 = 0;
            $v20 = $v15;
            do {
                $v18 = $v17++;
                $OutCipherText{$i + $v18} = chr($v16 & 0xFF);;
                $v16 >>= 8;
            } while ($v17 < $v7 && $v17 <= 3);
        } else {
            $v19 = $i;
            APX_ProtUpdateContext($ProtContext);
            $v20 = $v19;
        }
        if ($v7 <= 4)
            break;
        $i = $v20 + 4;
    }
    APX_ProtUninitContext($ProtContext);
}

function hex_dump($data, $len = false)
{
    if ($len === false) {
        $len = strlen($data);
    }
    for ($i = 0; $i < $len; $i++) {
        $out = dechex(ord($data[$i]));
        if (strlen($out) === 1) $out = '0' . $out;
        echo $out . ' ';
        if (($i + 1) % 16 === 0) echo "\n";
    }
    echo "\n";
}
