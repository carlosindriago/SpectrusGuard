<?php
/**
 * SpectrusGuard Advanced Detector
 *
 * Advanced malware detection using PHP tokenizer, obfuscation analysis,
 * and WordPress-specific threat patterns. Designed to detect sophisticated
 * malware that bypasses traditional signature-based scanning.
 *
 * @package SpectrusGuard
 * @since   3.0.1
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Advanced_Detector
 *
 * Token-based advanced malware detection engine.
 */
class SG_Advanced_Detector
{
    /**
     * Dangerous functions that should trigger alerts
     *
     * @var array
     */
    private $dangerous_functions = array(
        'eval',
        'system',
        'shell_exec',
        'passthru',
        'proc_open',
        'popen',
        'exec',
        'assert',
        'create_function',
        'phpinfo',
        'pcntl_exec',
        'ini_alter',
        'dl',
    );

    /**
     * Suspicious functions that need context analysis
     *
     * @var array
     */
    private $suspicious_functions = array(
        'base64_decode',
        'gzinflate',
        'gzuncompress',
        'gzdecode',
        'str_rot13',
        'call_user_func',
        'call_user_func_array',
        'preg_replace',
        'move_uploaded_file',
        'file_put_contents',
        'fwrite',
        'file_get_contents',
        'curl_exec',
        'wp_remote_get',
        'wp_remote_post',
    );

    /**
     * WP functions that create/modify users (potential backdoor)
     *
     * @var array
     */
    private $user_manipulation_functions = array(
        'wp_create_user',
        'wp_insert_user',
        'wp_update_user',
    );

    /**
     * Query manipulation hooks (almost always malicious)
     *
     * @var array
     */
    private $dangerous_hooks = array(
        'pre_user_query',
        'pre_user_search',
        'posts_where',
        'posts_join',
    );

    /**
     * Suspicious URL keywords for blacklisting
     *
     * @var array
     */
    private $suspicious_url_keywords = array(
        'casino',
        'pills',
        'viagra',
        'cialis',
        'essay',
        'payday',
        'loan',
        'porn',
        'xxx',
        'cheap-',
        'buy-now',
    );

    /**
     * Scan a file using advanced token-based analysis
     *
     * @param string $file_path Absolute file path.
     * @return array Threats found.
     */
    public function scan_file($file_path)
    {
        if (!file_exists($file_path) || !is_readable($file_path)) {
            return array();
        }

        $threats = array();

        // Get file content
        $content = @file_get_contents($file_path);
        if (false === $content) {
            return array();
        }

        // 1. Tokenizer Analysis
        $token_threats = $this->analyze_tokens($file_path, $content);
        $threats = array_merge($threats, $token_threats);

        // 2. Obfuscation Detection
        $obfuscation_threats = $this->detect_obfuscation($file_path, $content);
        $threats = array_merge($threats, $obfuscation_threats);

        // 3. WordPress Hook Analysis (if plugin/theme)
        if ($this->is_plugin_or_theme_file($file_path)) {
            $hook_threats = $this->analyze_wordpress_hooks($file_path, $content);
            $threats = array_merge($threats, $hook_threats);
        }

        // 4. XSS Detection
        $xss_threats = $this->detect_xss($file_path, $content);
        $threats = array_merge($threats, $xss_threats);

        // 5. Hidden Content Detection (spam)
        if (strpos($file_path, '.php') !== false) {
            $spam_threats = $this->detect_hidden_spam($file_path, $content);
            $threats = array_merge($threats, $spam_threats);
        }

        // 6. Input-to-Execution Flow Analysis
        $execution_threats = $this->detect_input_execution_flow($file_path, $content);
        $threats = array_merge($threats, $execution_threats);

        return $threats;
    }

    /**
     * Analyze PHP tokens for suspicious patterns
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function analyze_tokens($file_path, $content)
    {
        $threats = array();

        // Tokenize the file
        $tokens = @token_get_all($content);
        if (!is_array($tokens)) {
            return $threats;
        }

        $token_count = count($tokens);
        for ($i = 0; $i < $token_count; $i++) {
            $token = $tokens[$i];

            // Skip if not an array (simple string tokens)
            if (!is_array($token)) {
                continue;
            }

            list($id, $text, $line) = $token;

            // Detect dangerous function calls
            if ($id === T_STRING && in_array(strtolower($text), $this->dangerous_functions, true)) {
                // Check if it's actually a function call (next non-whitespace token should be '(')
                if ($this->is_function_call($tokens, $i)) {
                    $threats[] = array(
                        'file' => str_replace(ABSPATH, '', $file_path),
                        'type' => 'dangerous_function',
                        'severity' => 'CRITICAL',
                        'description' => sprintf('Dangerous function call: %s()', $text),
                        'line' => $line,
                        'function' => $text,
                    );
                }
            }

            // Detect variable function calls: $var()
            if ($id === T_VARIABLE) {
                // Check if next non-whitespace token is '('
                if ($this->is_function_call($tokens, $i)) {
                    $threats[] = array(
                        'file' => str_replace(ABSPATH, '', $file_path),
                        'type' => 'variable_function',
                        'severity' => 'HIGH',
                        'description' => sprintf('Variable function call (common obfuscation): %s()', $text),
                        'line' => $line,
                        'variable' => $text,
                    );
                }
            }

            // Detect user manipulation functions
            if ($id === T_STRING && in_array(strtolower($text), $this->user_manipulation_functions, true)) {
                $threats[] = array(
                    'file' => str_replace(ABSPATH, '', $file_path),
                    'type' => 'user_manipulation',
                    'severity' => 'HIGH',
                    'description' => sprintf('User creation/modification function: %s()', $text),
                    'line' => $line,
                    'function' => $text,
                );
            }
        }

        return $threats;
    }

    /**
     * Check if a token is followed by a function call parenthesis
     *
     * @param array $tokens All tokens.
     * @param int   $index Current token index.
     * @return bool True if it's a function call.
     */
    private function is_function_call($tokens, $index)
    {
        // Look ahead for '(' skipping whitespace
        for ($j = $index + 1; $j < count($tokens); $j++) {
            $next_token = $tokens[$j];

            // Skip whitespace
            if (is_array($next_token) && $next_token[0] === T_WHITESPACE) {
                continue;
            }

            // Check if it's an opening parenthesis
            if ($next_token === '(' || (is_array($next_token) && $next_token[0] === '(')) {
                return true;
            }

            // If we hit something else, it's not a function call
            return false;
        }

        return false;
    }

    /**
     * Detect obfuscation patterns
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_obfuscation($file_path, $content)
    {
        $threats = array();

        // Pattern 1: base64_decode + eval/assert
        if (preg_match('/eval\s*\(\s*base64_decode\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'obfuscation',
                'severity' => 'CRITICAL',
                'description' => 'Base64 + eval obfuscation detected',
                'line' => $line,
            );
        }

        // Pattern 2: str_rot13 + eval
        if (preg_match('/eval\s*\(\s*str_rot13\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'obfuscation',
                'severity' => 'CRITICAL',
                'description' => 'ROT13 obfuscation with eval detected',
                'line' => $line,
            );
        }

        // Pattern 3: Long base64 strings (likely encoded malware)
        if (preg_match('/[a-zA-Z0-9+\/]{500,}/', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'obfuscation',
                'severity' => 'MEDIUM',
                'description' => 'Extremely long base64 string detected (possible encoded payload)',
                'line' => $line,
            );
        }

        // Pattern 4: Hex encoded strings (multiple \x sequences)
        if (preg_match('/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){15,}/', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'obfuscation',
                'severity' => 'HIGH',
                'description' => 'Hex-encoded string obfuscation detected',
                'line' => $line,
            );
        }

        return $threats;
    }

    /**
     * Analyze WordPress hooks for malicious behavior
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function analyze_wordpress_hooks($file_path, $content)
    {
        $threats = array();

        // Pattern 1: add_action/add_filter with dangerous hooks
        foreach ($this->dangerous_hooks as $hook) {
            $pattern = '/add_(action|filter)\s*\(\s*[\'"]\s*' . preg_quote($hook, '/') . '\s*[\'"]/i';
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => str_replace(ABSPATH, '', $file_path),
                    'type' => 'dangerous_hook',
                    'severity' => 'CRITICAL',
                    'description' => sprintf('Dangerous hook usage: %s (query manipulation)', $hook),
                    'line' => $line,
                );
            }
        }

        // Pattern 2: wp_head/wp_footer with base64_decode (spam injection)
        if (preg_match('/add_action\s*\(\s*[\'"](wp_head|wp_footer)[\'"].*base64/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'spam_injection',
                'severity' => 'HIGH',
                'description' => 'Potential spam injection in wp_head/wp_footer with base64',
                'line' => $line,
            );
        }

        // Pattern 3: Conditional spam (hiding from logged-in users)
        if (preg_match('/!is_user_logged_in\s*\(\s*\).*add_action.*wp_footer/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'conditional_spam',
                'severity' => 'HIGH',
                'description' => 'Content hidden from logged-in admins (common spam tactic)',
                'line' => $line,
            );
        }

        return $threats;
    }

    /**
     * Detect XSS vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_xss($file_path, $content)
    {
        $threats = array();

        // Pattern: echo $_GET/$_POST without sanitization
        $xss_patterns = array(
            '/echo\s+\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/print\s+\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
            '/print_r\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i',
        );

        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                // Check if there's sanitization nearby
                $snippet = substr($content, max(0, $match[0][1] - 100), 200);
                $has_sanitization = preg_match('/(esc_html|esc_attr|esc_url|sanitize_|wp_kses)/i', $snippet);

                if (!$has_sanitization) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => str_replace(ABSPATH, '', $file_path),
                        'type' => 'xss_vulnerability',
                        'severity' => 'CRITICAL',
                        'description' => 'Unsanitized output of user input (XSS vulnerability)',
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect hidden spam content (CSS tricks)
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_hidden_spam($file_path, $content)
    {
        $threats = array();

        // Pattern 1: Hidden CSS with links (left: -9999px, display: none, etc.)
        $hidden_css_patterns = array(
            '/left:\s*-\d{4,}px.*<a\s+href/is',
            '/display:\s*none.*<a\s+href/is',
            '/position:\s*absolute.*left:\s*-\d{3,}/is',
            '/visibility:\s*hidden.*<a\s+href/is',
        );

        foreach ($hidden_css_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                // Check for suspicious URLs
                $snippet = substr($content, $match[0][1], 500);
                foreach ($this->suspicious_url_keywords as $keyword) {
                    if (stripos($snippet, $keyword) !== false) {
                        $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                        $threats[] = array(
                            'file' => str_replace(ABSPATH, '', $file_path),
                            'type' => 'hidden_spam',
                            'severity' => 'HIGH',
                            'description' => sprintf('Hidden spam links detected (keyword: %s)', $keyword),
                            'line' => $line,
                        );
                        break; // Only report once per pattern match
                    }
                }
            }
        }

        // Pattern 2: Suspicious URLs in general content
        foreach ($this->suspicious_url_keywords as $keyword) {
            if (preg_match('/<a\s+href[^>]*' . preg_quote($keyword, '/') . '/i', $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => str_replace(ABSPATH, '', $file_path),
                    'type' => 'suspicious_link',
                    'severity' => 'MEDIUM',
                    'description' => sprintf('Suspicious link keyword found: %s', $keyword),
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect input-to-execution flow (user input reaching exec functions)
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_input_execution_flow($file_path, $content)
    {
        $threats = array();

        // Pattern: $_GET/$_POST -> base64_decode -> eval/assert
        $flow_patterns = array(
            '/\$_(GET|POST|REQUEST|COOKIE).*base64_decode.*eval/is',
            '/\$_(GET|POST|REQUEST|COOKIE).*base64_decode.*assert/is',
            '/\$_(GET|POST|REQUEST|COOKIE).*gzinflate.*eval/is',
        );

        foreach ($flow_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => str_replace(ABSPATH, '', $file_path),
                    'type' => 'input_execution_flow',
                    'severity' => 'CRITICAL',
                    'description' => 'User input directly flows to code execution (backdoor pattern)',
                    'line' => $line,
                );
            }
        }

        // Pattern: create_function with user input
        if (preg_match('/create_function\s*\(.*\$_(GET|POST|REQUEST)/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => str_replace(ABSPATH, '', $file_path),
                'type' => 'deprecated_dangerous',
                'severity' => 'CRITICAL',
                'description' => 'create_function (deprecated) used with user input',
                'line' => $line,
            );
        }

        return $threats;
    }

    /**
     * Check if file is in plugins or themes directory
     *
     * @param string $file_path File path.
     * @return bool True if plugin/theme file.
     */
    private function is_plugin_or_theme_file($file_path)
    {
        $plugins_dir = WP_CONTENT_DIR . '/plugins';
        $themes_dir = WP_CONTENT_DIR . '/themes';

        return (strpos($file_path, $plugins_dir) !== false || strpos($file_path, $themes_dir) !== false);
    }

    /**
     * Get threat severity color for display
     *
     * @param string $severity Severity level.
     * @return string Color code.
     */
    public function get_severity_color($severity)
    {
        $colors = array(
            'CRITICAL' => '#dc3545',
            'HIGH' => '#fd7e14',
            'MEDIUM' => '#ffc107',
            'LOW' => '#28a745',
        );

        return isset($colors[$severity]) ? $colors[$severity] : '#6c757d';
    }
}
