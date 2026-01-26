<?php
/**
 * GhostShield Malware Signatures
 *
 * Database of known malware signatures and patterns used to detect
 * infected files in WordPress installations.
 *
 * @package GhostShield
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Get malware signatures database
 *
 * Returns an array of signature patterns organized by category.
 * Each pattern can be a plain string or a regex (starting with /).
 *
 * @return array Malware signatures.
 */
function gs_get_malware_signatures()
{
    return array(

        // ================================
        // BACKDOORS & SHELLS
        // More specific patterns to avoid false positives
        // ================================

        'FilesMan Backdoor' => array(
            '/FilesMan\s*\(/i',                    // FilesMan function call
            '/class\s+FilesMan\b/i',               // FilesMan class definition
            '/$filesMan\s*=/i',                    // FilesMan variable
        ),

        'WSO Shell' => array(
            '/WSO\s+\d+\.\d+\s+Shell/i',           // "WSO 2.5 Shell" etc
            '/Web\s*Shell\s*by\s*oRb/i',           // Full attribution string
            '/\$auth_pass\s*=\s*["\'][a-f0-9]{32}["\']/i', // MD5 password hash (common in WSO)
            '/\$default_action\s*=\s*["\']FilesMan["\']/i', // WSO config
            '/@\s*ini_set\s*\(\s*["\']error_log["\']\s*,\s*NULL\s*\)/i', // WSO stealth
        ),

        'C99 Shell' => array(
            '/c99shell/i',
            '/c99madshell/i',
            '/c99_sess_put/i',
            '/\$c99sh_/i',                         // C99 shell variables
        ),

        'R57 Shell' => array(
            '/r57shell/i',
            '/r57_get_php_version/i',
            '/\$r57_/i',                           // R57 shell variables
        ),

        'B374K Shell' => array(
            '/b374k\s*shell/i',                    // "b374k shell" with context
            '/b374k\s*\d+\.\d+/i',                 // Version number "b374k 2.8"
        ),

        'P0wny Shell' => array(
            '/p0wny\s*shell/i',
            '/p0wnyshell/i',
        ),

        'Alfa Shell' => array(
            '/Alfa\s*Shell/i',
            '/AlfaTeam\s*Shell/i',
        ),

        'Weevely Backdoor' => array(
            '/weevely/i',
            '/\$k\s*=\s*["\'][a-f0-9]{8}["\']/i',  // Weevely key pattern
        ),


        // ================================
        // OBFUSCATION PATTERNS
        // ================================

        'Base64 Eval' => array(
            '/eval\s*\(\s*base64_decode\s*\(/i',
            '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode/i',
        ),

        'Base64 Assert' => array(
            '/assert\s*\(\s*base64_decode\s*\(/i',
        ),

        'Gzinflate Eval' => array(
            '/eval\s*\(\s*gzinflate\s*\(/i',
            '/eval\s*\(\s*gzuncompress\s*\(/i',
            '/eval\s*\(\s*gzdecode\s*\(/i',
        ),

        'Str_Rot13 Eval' => array(
            '/eval\s*\(\s*str_rot13\s*\(/i',
        ),

        'Hex Encoded' => array(
            '/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){10,}/',
        ),

        'Char Code Obfuscation' => array(
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)\s*\./i',
        ),

        // ================================
        // DYNAMIC CODE EXECUTION
        // ================================

        'Eval $_REQUEST' => array(
            '/eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        ),

        'Assert $_REQUEST' => array(
            '/assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        ),

        'Create Function Backdoor' => array(
            '/create_function\s*\(\s*[\'\"]\s*[\'\"]\s*,\s*\$_(GET|POST|REQUEST)/i',
        ),

        'Preg_Replace /e Modifier' => array(
            '/preg_replace\s*\(\s*["\'].*\/[a-z]*e[a-z]*["\']/i',
        ),

        'Call User Func Array' => array(
            '/call_user_func_array\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ),

        'Include Remote' => array(
            '/include\s*\(\s*[\'"]https?:\/\//i',
            '/require\s*\(\s*[\'"]https?:\/\//i',
        ),

        // ================================
        // WORDPRESS SPECIFIC MALWARE
        // ================================

        'WP VCD Malware' => array(
            'wp_vcd',
            '$_ckCookie',
            'set_vc_data',
            'get_vc_data',
            '/\$_ck\s*=\s*new\s+ck_class/',
        ),

        'WP Favicon Malware' => array(
            '/class_exists\s*\(\s*[\'"]Plugin_Developer[\'"]\s*\)/',
            'Plugin_Developer',
        ),

        'Inject Before Head' => array(
            '/wp_head.*base64_decode/is',
            '/add_action\s*\(\s*[\'"]wp_head[\'"]\s*,\s*.*base64/i',
        ),

        'Injected Admin User' => array(
            '/wp_insert_user.*role.*administrator/is',
        ),

        // ================================
        // MAILERS & SPAM
        // ================================

        'PHP Mailer Abuse' => array(
            '/mail\s*\(\s*\$_(GET|POST|REQUEST)/i',
            '/wp_mail\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ),

        'Spam Script' => array(
            'PHPMailer_Spam',
            'AlphaMail',
        ),

        // ================================
        // CRYPTOMINERS
        // ================================

        'Crypto Miner' => array(
            'CoinHive.Anonymous',
            'coinhive.min.js',
            'CryptoNight',
            '/miner\.start\s*\(/',
        ),

        // ================================
        // INFORMATION DISCLOSURE
        // ================================

        'Credential Stealer' => array(
            '/file_get_contents\s*\(\s*[\'"].*wp-config\.php[\'"]/',
            '/fopen\s*\(\s*[\'"].*wp-config\.php[\'"]/',
        ),

        'Database Dumper' => array(
            '/mysqldump\s+-u/',
            '/SHOW\s+TABLES\s+FROM/i',
        ),

        // ================================
        // REDIRECTS & INJECTIONS
        // ================================

        'Header Redirect Injection' => array(
            '/header\s*\(\s*[\'"]Location:.*\$_(GET|POST|REQUEST)/i',
        ),

        'JavaScript Injection' => array(
            '/document\.write\s*\(\s*unescape/i',
            '/eval\s*\(\s*unescape/i',
        ),

        // Removed SEO Spam - too many false positives
        // 'SEO Spam Injection' commented out to avoid flagging content sites

        // ================================
        // SUSPICIOUS FUNCTIONS
        // Only flag when combined with user input
        // ================================

        'Passthru Backdoor' => array(
            '/passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        ),

        'Shell Exec Backdoor' => array(
            '/shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
            '/`\s*\$_(GET|POST|REQUEST)/i',
        ),

        'Proc Open Backdoor' => array(
            '/proc_open\s*\(.*\$_(GET|POST|REQUEST)/is',
        ),

        'Popen Backdoor' => array(
            '/popen\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ),

        'System Backdoor' => array(
            '/\bsystem\s*\(\s*\$_(GET|POST|REQUEST)/i',
            '/\bexec\s*\(\s*\$_(GET|POST|REQUEST)/i',
        ),

        // ================================
        // FILE OPERATIONS
        // ================================

        'File Put Contents Webshell' => array(
            '/file_put_contents\s*\(\s*.*\.php.*\$_(GET|POST|REQUEST)/is',
        ),

        'Fwrite Webshell' => array(
            '/fwrite\s*\(.*\$_(GET|POST|REQUEST)/is',
        ),

        'Move Uploaded Malicious' => array(
            '/move_uploaded_file.*\.\s*\$_(GET|POST|REQUEST)/is',
        ),

        // ================================
        // OBFUSCATED STRINGS
        // ================================

        'Long Base64 String' => array(
            '/[a-zA-Z0-9+\/=]{500,}/',
        ),

        'Packed JavaScript' => array(
            'eval(function(p,a,c,k,e,d)',
            '/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/',
        ),

    );
}

/**
 * Get high priority (most dangerous) signatures only
 *
 * @return array High priority signatures.
 */
function gs_get_critical_signatures()
{
    $all = gs_get_malware_signatures();

    $critical_keys = array(
        'FilesMan Backdoor',
        'WSO Shell',
        'C99 Shell',
        'R57 Shell',
        'Base64 Eval',
        'Eval $_REQUEST',
        'WP VCD Malware',
    );

    return array_intersect_key($all, array_flip($critical_keys));
}

/**
 * Get signature count
 *
 * @return int Total number of signatures.
 */
function gs_get_signature_count()
{
    $signatures = gs_get_malware_signatures();
    $count = 0;

    foreach ($signatures as $patterns) {
        $count += is_array($patterns) ? count($patterns) : 1;
    }

    return $count;
}
