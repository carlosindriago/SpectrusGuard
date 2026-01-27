<?php

class Spectrus_TOTP_Engine
{

    /**
     * Genera un secreto aleatorio en Base32 (Requisito para Google Auth)
     */
    public static function generate_secret($length = 16)
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 standard alphabet
        $secret = '';
        for ($i = 0; $i < $length; $i++) {
            $secret .= $chars[rand(0, 31)];
        }
        return $secret;
    }

    /**
     * Valida el código ingresado por el usuario
     */
    public static function verify_code($secret, $code)
    {
        // Chequeamos el intervalo actual y el anterior/siguiente (para tolerancia de reloj de 30s)
        for ($i = -1; $i <= 1; $i++) {
            $calculated = self::get_code($secret, $i);
            if (hash_equals((string) $calculated, (string) $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calcula el código de 6 dígitos basado en el tiempo actual
     */
    private static function get_code($secret, $time_slice_offset = 0)
    {
        $timestamp = floor(time() / 30) + $time_slice_offset;
        $binary_key = self::base32_decode($secret);

        // Pack time into binary string
        $binary_timestamp = pack('N*', 0) . pack('N*', $timestamp);

        // HMAC-SHA1 (Estándar TOTP)
        $hash = hash_hmac('sha1', $binary_timestamp, $binary_key, true);

        // Extracción dinámica (Dynamic Truncation)
        $offset = ord($hash[19]) & 0xf;
        $otp = (
            ((ord($hash[$offset + 0]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;

        return str_pad($otp, 6, '0', STR_PAD_LEFT);
    }

    private static function base32_decode($base32)
    {
        $base32 = strtoupper($base32);
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        foreach (str_split($base32) as $char) {
            if (strpos($chars, $char) === false)
                continue;
            $binary .= str_pad(decbin(strpos($chars, $char)), 5, '0', STR_PAD_LEFT);
        }
        $binary_str = '';
        foreach (str_split($binary, 8) as $byte) {
            $binary_str .= chr(bindec(str_pad($byte, 8, '0', STR_PAD_RIGHT)));
        }
        return $binary_str;
    }
}
