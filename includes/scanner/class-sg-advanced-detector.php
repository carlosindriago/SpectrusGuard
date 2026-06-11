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
     * Threat score threshold to flag a file.
     */
    const THREAT_SCORE_THRESHOLD = 25;

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
        if (false === $content || '' === trim($content)) {
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

        // 7. SQL Injection Detection
        $sql_threats = $this->detect_sql_injection($file_path, $content);
        $threats = array_merge($threats, $sql_threats);

        // 8. CSRF Detection
        $csrf_threats = $this->detect_csrf($file_path, $content);
        $threats = array_merge($threats, $csrf_threats);

        // 9. Unsafe File Upload Detection
        $upload_threats = $this->detect_unsafe_file_upload($file_path, $content);
        $threats = array_merge($threats, $upload_threats);

        // 10. Cryptocurrency Mining Detection (JS files)
        if (strpos($file_path, '.js') !== false || pathinfo($file_path, PATHINFO_EXTENSION) === 'js') {
            $crypto_threats = $this->detect_crypto_mining($file_path, $content);
            $threats = array_merge($threats, $crypto_threats);
        }

        // 11. Information Disclosure (DB Credentials)
        $info_threats = $this->detect_information_disclosure($file_path, $content);
        $threats = array_merge($threats, $info_threats);

        // 12. Local File Inclusion (LFI)
        $lfi_threats = $this->detect_lfi($file_path, $content);
        $threats = array_merge($threats, $lfi_threats);

        // 13. Path Traversal
        $traversal_threats = $this->detect_path_traversal($file_path, $content);
        $threats = array_merge($threats, $traversal_threats);

        // 14. Arbitrary File Write
        $write_threats = $this->detect_arbitrary_file_write($file_path, $content);
        $threats = array_merge($threats, $write_threats);

        // 15. Arbitrary File Delete
        $delete_threats = $this->detect_arbitrary_file_delete($file_path, $content);
        $threats = array_merge($threats, $delete_threats);

        // 16. Email Header Injection
        $email_threats = $this->detect_email_injection($file_path, $content);
        $threats = array_merge($threats, $email_threats);

        // 17. SSRF (Server-Side Request Forgery)
        $ssrf_threats = $this->detect_ssrf($file_path, $content);
        $threats = array_merge($threats, $ssrf_threats);

        // 18. Command Injection
        $cmd_threats = $this->detect_command_injection($file_path, $content);
        $threats = array_merge($threats, $cmd_threats);

        // 19. Object Injection (Deserialization)
        $obj_threats = $this->detect_object_injection($file_path, $content);
        $threats = array_merge($threats, $obj_threats);

        $total_score = $this->calculate_threat_score($threats);
        if ($total_score < self::THREAT_SCORE_THRESHOLD) {
            return array();
        }

        return $this->enrich_threats($threats, $content, $total_score);
    }

    /**
     * Normalize file path for reporting, making it relative to ABSPATH.
     *
     * @param string $file_path Absolute file path.
     * @return string Normalized relative file path.
     */
    private function normalize_file_path(string $file_path): string
    {
        if (!defined('ABSPATH') || empty(ABSPATH)) {
            return basename($file_path);
        }

        $abs_path = rtrim(ABSPATH, "/\\") . '/';
        $normalized = str_replace($abs_path, '', $file_path);

        return ltrim($normalized, "/\\");
    }

    /**
     * Add score and context metadata to reported threats.
     *
     * @param array  $threats File threats.
     * @param string $content File content.
     * @param int    $score File threat score.
     * @return array Enriched threats.
     */
    private function enrich_threats(array $threats, string $content, int $score): array
    {
        foreach ($threats as &$threat) {
            $threat['score'] = $score;
            $context = $this->build_threat_context($content, $threat);
            if ('' !== $context) {
                $threat['context'] = $context;
            }
        }

        return $threats;
    }

    /**
     * Build a safe context snippet for a threat.
     *
     * @param string $content File content.
     * @param array  $threat Threat data.
     * @return string Safe threat context.
     */
    private function build_threat_context(string $content, array $threat): string
    {
        if ($this->is_empty_content($content) || empty($threat['line'])) {
            return '';
        }

        $line_number = (int) $threat['line'];
        $lines = preg_split('/\R/', $content);
        if (!is_array($lines) || !isset($lines[$line_number - 1])) {
            return '';
        }

        $start = max(0, $line_number - 2);
        $snippet = implode(' ', array_slice($lines, $start, 3));

        return $this->sanitize_context_snippet($snippet);
    }

    /**
     * Normalize and redact a context snippet before reporting it.
     *
     * @param string $snippet Raw snippet.
     * @return string Sanitized snippet.
     */
    private function sanitize_context_snippet(string $snippet): string
    {
        if (preg_match('/DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT/i', $snippet)) {
            return '[REDACTED]';
        }

        $collapsed = preg_replace('/\s+/', ' ', trim($snippet));
        if (!is_string($collapsed) || '' === $collapsed) {
            return '';
        }

        if (strlen($collapsed) <= 120) {
            return $collapsed;
        }

        return substr($collapsed, 0, 117) . '...';
    }

    /**
     * Determine whether content is empty for detector processing.
     *
     * @param string $content File content.
     * @return bool True when content is empty.
     */
    private function is_empty_content(string $content): bool
    {
        return '' === trim($content);
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

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
                    // Ignore when prefixed by object operator (->, ?->), double colon (::), or preceded by T_FUNCTION
                    $is_method_or_def = false;
                    for ($k = $i - 1; $k >= 0; $k--) {
                        $prev_token = $tokens[$k];
                        if (is_array($prev_token)) {
                            $prev_id = $prev_token[0];
                            if ($prev_id === T_WHITESPACE || $prev_id === T_COMMENT || $prev_id === T_DOC_COMMENT) {
                                continue;
                            }
                            if ($prev_id === T_OBJECT_OPERATOR || $prev_id === T_DOUBLE_COLON || $prev_id === T_FUNCTION) {
                                $is_method_or_def = true;
                            }
                            if (defined('T_NULLSAFE_OBJECT_OPERATOR') && $prev_id === T_NULLSAFE_OBJECT_OPERATOR) {
                                $is_method_or_def = true;
                            }
                            break;
                        } else {
                            break;
                        }
                    }

                    if (!$is_method_or_def) {
                        $snippet = $this->get_argument_snippet($tokens, $i);
                        $severity = $this->contains_user_input($snippet) ? SG_SEV_CRITICAL : SG_SEV_MEDIUM;
                        $threats[] = array(
                            'file' => $this->normalize_file_path($file_path),
                            'type' => 'dangerous_function',
                            'severity' => $severity,
                            'description' => sprintf('Dangerous function call: %s()', $text),
                            'line' => $line,
                            'function' => $text,
                        );
                    }
                }
            }

            // Detect variable function calls: $var()
            if ($id === T_VARIABLE) {
                // Check if next non-whitespace token is '('
                if ($this->is_function_call($tokens, $i)) {
                    if ($this->should_ignore_variable_function($text, $content, $line)) {
                        continue;
                    }

                    // Check if preceded by user input tokens in a search window of 50 tokens
                    $has_user_input_precursor = $this->has_variable_function_user_input_precursor($tokens, $i);
                    $is_callback = $this->is_wordpress_callback_variable($text, $content, $line);
                    $severity = ($has_user_input_precursor && !$is_callback) ? SG_SEV_HIGH : SG_SEV_INFO;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'variable_function',
                        'severity' => $severity,
                        'description' => sprintf('Variable function call (common obfuscation): %s()', $text),
                        'line' => $line,
                        'variable' => $text,
                    );
                }
            }

            // Detect user manipulation functions
            if ($id === T_STRING && in_array(strtolower($text), $this->user_manipulation_functions, true)) {
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'user_manipulation',
                    'severity' => SG_SEV_HIGH,
                    'description' => sprintf('User creation/modification function: %s()', $text),
                    'line' => $line,
                    'function' => $text,
                );
            }
        }

        return $threats;
    }

    /**
     * Decide whether a variable function call should be ignored.
     *
     * @param string $variable_name Variable name token.
     * @param string $content File content.
     * @param int    $line Current line number.
     * @return bool True when the call should be ignored.
     */
    private function should_ignore_variable_function(string $variable_name, string $content, int $line): bool
    {
        if (in_array(strtolower($variable_name), array('$this', '$self', '$class'), true)) {
            return true;
        }

        return $this->has_ignore_annotation($content, $line);
    }

    /**
     * Check whether the previous line contains an ignore annotation.
     *
     * @param string $content File content.
     * @param int    $line Current line number.
     * @return bool True when the previous line has the ignore annotation.
     */
    private function has_ignore_annotation(string $content, int $line): bool
    {
        if ($line < 2) {
            return false;
        }

        $lines = preg_split('/\R/', $content);
        if (!is_array($lines) || !isset($lines[$line - 2])) {
            return false;
        }

        return false !== strpos($lines[$line - 2], '@spectrusguard-ignore');
    }

    /**
     * Detect user-input precursor tokens for variable function calls.
     *
     * @param array $tokens All tokens.
     * @param int   $index Current token index.
     * @return bool True when user input appears in the lookback window.
     */
    private function has_variable_function_user_input_precursor(array $tokens, int $index): bool
    {
        $start_lookback = max(0, $index - 50);
        for ($cursor = $index - 1; $cursor >= $start_lookback; $cursor--) {
            if (!is_array($tokens[$cursor])) {
                continue;
            }

            if (in_array($tokens[$cursor][1], $this->get_user_input_sources(), true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detect WordPress callback-array assignments for variable function calls.
     *
     * @param string $variable_name Variable token.
     * @param string $content File content.
     * @param int    $line Current line number.
     * @return bool True when the variable matches a callback-array pattern.
     */
    private function is_wordpress_callback_variable(string $variable_name, string $content, int $line): bool
    {
        $start_line = max(1, $line - 6);
        $window = $this->get_content_by_line_window($content, $start_line, 8);
        $assignment = preg_quote($variable_name, '/') . '\s*=\s*array\s*\(';
        $hooks = '(?:add_action|add_filter|apply_filters|do_action)\s*\([^;]*' . preg_quote($variable_name, '/') . '\b';

        return (bool) preg_match('/' . $assignment . '/i', $window)
            && (bool) preg_match('/' . $hooks . '/i', $window);
    }

    /**
     * Extract a bounded window of content by line number.
     *
     * @param string $content File content.
     * @param int    $start_line First line to include.
     * @param int    $length Number of lines to include.
     * @return string Extracted content window.
     */
    private function get_content_by_line_window(string $content, int $start_line, int $length): string
    {
        $lines = preg_split('/\R/', $content);
        if (!is_array($lines)) {
            return '';
        }

        return implode("\n", array_slice($lines, $start_line - 1, $length));
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
     * Get the argument snippet from tokens starting after a function call parenthesis.
     *
     * @param array $tokens All tokens.
     * @param int   $index Index of function name token.
     * @return string Argument snippet.
     */
    private function get_argument_snippet($tokens, $index)
    {
        $snippet = '';
        $tokens_count = count($tokens);
        $paren_index = -1;

        // Find the opening parenthesis
        for ($j = $index + 1; $j < $tokens_count; $j++) {
            $token = $tokens[$j];
            if (is_array($token) && $token[0] === T_WHITESPACE) {
                continue;
            }
            if ($token === '(' || (is_array($token) && $token[0] === '(')) {
                $paren_index = $j;
                break;
            }
            break; // Not a function call if anything else comes first
        }

        if ($paren_index === -1) {
            return $snippet;
        }

        $open_braces = 0;
        for ($j = $paren_index; $j < $tokens_count; $j++) {
            $token = $tokens[$j];
            if ($token === '(' || (is_array($token) && $token[0] === '(')) {
                $open_braces++;
            } elseif ($token === ')' || (is_array($token) && $token[0] === ')')) {
                $open_braces--;
            }

            // Append token text
            if (is_array($token)) {
                $snippet .= $token[1];
            } else {
                $snippet .= $token;
            }

            if ($open_braces === 0) {
                break;
            }
        }

        // Return everything inside the outer parentheses
        if (strlen($snippet) >= 2 && $snippet[0] === '(' && substr($snippet, -1) === ')') {
            $snippet = substr($snippet, 1, -1);
        }

        return trim($snippet);
    }

    /**
     * Check if a snippet contains user input superglobals.
     *
     * @param string $snippet Snippet code.
     * @return bool True if user input is present.
     */
    private function contains_user_input($snippet)
    {
        if (empty($snippet)) {
            return false;
        }

        foreach ($this->get_user_input_sources() as $input) {
            if (stripos($snippet, $input) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return supported user-input sources for taint checks.
     *
     * @return array User-input superglobals.
     */
    private function get_user_input_sources(): array
    {
        return array('$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER');
    }

    /**
     * Check if a variable is tainted by verifying user input in the context
     *
     * @param string $var_name Variable name (e.g. '$sql').
     * @param string $snippet Proximity context.
     * @param string $content Entire file content.
     * @return bool True if tainted.
     */
    private function is_variable_tainted($var_name, $snippet, $content = '')
    {
        return 'tainted' === $this->get_variable_taint_state($var_name, $snippet, $content);
    }

    /**
     * Resolve the taint state for a variable in a given context.
     *
     * @param string $var_name Variable name.
     * @param string $snippet Proximity snippet.
     * @param string $content Full file content.
     * @return string Taint state: safe, tainted or unknown.
     */
    private function get_variable_taint_state(string $var_name, string $snippet, string $content = ''): string
    {
        if ($this->is_safe_variable_name($var_name) || !$this->contains_user_input($snippet)) {
            return 'safe';
        }

        $source_context = $this->get_variable_source_context($var_name, $snippet, $content);
        $assignments = $this->extract_variable_assignments($var_name, $source_context);
        if (empty($assignments)) {
            return 'unknown';
        }

        foreach ($assignments as $assignment_expr) {
            if ($this->is_assignment_tainted($var_name, $assignment_expr, $source_context)) {
                return 'tainted';
            }
        }

        return 'safe';
    }

    /**
     * Determine whether a variable name is considered inherently safe.
     *
     * @param string $var_name Variable name.
     * @return bool True when the variable should be skipped.
     */
    private function is_safe_variable_name(string $var_name): bool
    {
        $safe_globals = array(
            '$wpdb', '$post', '$wp_query', '$wp', '$wp_roles', '$wp_locale', '$wp_rewrite',
            '$wp_taxonomies', '$wp_filter', '$wp_actions', '$wp_meta_keys', '$wp_styles', '$wp_scripts',
        );

        return in_array(strtolower($var_name), $safe_globals, true)
            || (bool) preg_match('/^\$[A-Z_][A-Z0-9_]*$/', $var_name);
    }

    /**
     * Select the best context to inspect variable assignments.
     *
     * @param string $var_name Variable name.
     * @param string $snippet Proximity snippet.
     * @param string $content Full file content.
     * @return string Best source context for assignment lookup.
     */
    private function get_variable_source_context(string $var_name, string $snippet, string $content): string
    {
        if ($this->has_variable_assignment($var_name, $snippet) || $this->is_empty_content($content)) {
            return $snippet;
        }

        return $content;
    }

    /**
     * Check whether a context contains an assignment for the given variable.
     *
     * @param string $var_name Variable name.
     * @param string $context Source context.
     * @return bool True when an assignment exists.
     */
    private function has_variable_assignment(string $var_name, string $context): bool
    {
        return (bool) preg_match('/' . preg_quote($var_name, '/') . '\s*(?:\.=|=>|=)/i', $context);
    }

    /**
     * Extract assignment expressions for a variable from a context.
     *
     * @param string $var_name Variable name.
     * @param string $context Source context.
     * @return array Assignment expressions.
     */
    private function extract_variable_assignments(string $var_name, string $context): array
    {
        if (!preg_match_all('/' . preg_quote($var_name, '/') . '\s*(?:\.=|=>|=)\s*([^;]+)/i', $context, $matches)) {
            return array();
        }

        return $matches[1];
    }

    /**
     * Check whether an assignment expression is tainted.
     *
     * @param string $var_name Variable name being resolved.
     * @param string $assignment_expr Assignment expression.
     * @param string $context Source context.
     * @return bool True when the assignment is tainted.
     */
    private function is_assignment_tainted(string $var_name, string $assignment_expr, string $context): bool
    {
        if ($this->contains_user_input($assignment_expr)) {
            return true;
        }

        if (!preg_match_all('/\$([a-zA-Z0-9_]+)/', $assignment_expr, $var_matches)) {
            return false;
        }

        foreach ($var_matches[1] as $other_var) {
            if ('$' . $other_var === $var_name) {
                continue;
            }

            if ($this->contains_user_input($this->find_variable_assignment('$' . $other_var, $context))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Find the first assignment expression for a related variable.
     *
     * @param string $var_name Variable name.
     * @param string $context Source context.
     * @return string Assignment expression or empty string.
     */
    private function find_variable_assignment(string $var_name, string $context): string
    {
        if (!preg_match('/' . preg_quote($var_name, '/') . '\s*(?:\.=|=>|=)\s*([^;]+)/i', $context, $matches)) {
            return '';
        }

        return isset($matches[1]) ? $matches[1] : '';
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern 1: base64_decode + eval/assert
        if (preg_match('/eval\s*\(\s*base64_decode\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'obfuscation',
                'severity' => SG_SEV_CRITICAL,
                'description' => 'Base64 + eval obfuscation detected',
                'line' => $line,
            );
        }

        // Pattern 2: str_rot13 + eval
        if (preg_match('/eval\s*\(\s*str_rot13\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'obfuscation',
                'severity' => SG_SEV_CRITICAL,
                'description' => 'ROT13 obfuscation with eval detected',
                'line' => $line,
            );
        }

        // Pattern 3: Long base64 strings (likely encoded malware)
        if (preg_match('/[a-zA-Z0-9+\/]{500,}/', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'obfuscation',
                'severity' => SG_SEV_MEDIUM,
                'description' => 'Extremely long base64 string detected (possible encoded payload)',
                'line' => $line,
            );
        }

        // Pattern 4: Hex encoded strings (multiple \x sequences)
        if (preg_match('/\\\\x[0-9a-fA-F]{2}(\\\\x[0-9a-fA-F]{2}){15,}/', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'obfuscation',
                'severity' => SG_SEV_HIGH,
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern 1: add_action/add_filter with dangerous hooks
        foreach ($this->dangerous_hooks as $hook) {
            $pattern = '/add_(action|filter)\s*\(\s*[\'"]\s*' . preg_quote($hook, '/') . '\s*[\'"]/i';
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'dangerous_hook',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => sprintf('Dangerous hook usage: %s (query manipulation)', $hook),
                    'line' => $line,
                );
            }
        }

        // Pattern 2: wp_head/wp_footer with base64_decode (spam injection)
        if (preg_match('/add_action\s*\(\s*[\'"](wp_head|wp_footer)[\'"].*base64/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'spam_injection',
                'severity' => SG_SEV_HIGH,
                'description' => 'Potential spam injection in wp_head/wp_footer with base64',
                'line' => $line,
            );
        }

        // Pattern 3: Conditional spam (hiding from logged-in users)
        if (preg_match('/!is_user_logged_in\s*\(\s*\).*add_action.*wp_footer/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'conditional_spam',
                'severity' => SG_SEV_HIGH,
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: echo/print with user input without sanitization
        $xss_patterns = array(
            '/echo\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/echo\s+["\'][^"\']*.\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/print\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
        );

        foreach ($xss_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                // Check if there's sanitization nearby
                $snippet = substr($content, max(0, $match[0][1] - 150), 300);
                $has_sanitization = preg_match('/(esc_html|esc_attr|esc_url|htmlspecialchars|sanitize_|wp_kses)/i', $snippet);

                if (!$has_sanitization) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'xss_vulnerability',
                        'severity' => SG_SEV_HIGH,
                        'description' => 'XSS: Unescaped user input in output',
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

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
                            'file' => $this->normalize_file_path($file_path),
                            'type' => 'hidden_spam',
                            'severity' => SG_SEV_HIGH,
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
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'suspicious_link',
                    'severity' => SG_SEV_MEDIUM,
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
        if ($this->is_empty_content($content)) {
            return $threats;
        }

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
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'input_execution_flow',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'User input directly flows to code execution (backdoor pattern)',
                    'line' => $line,
                );
            }
        }

        // Pattern: create_function with user input
        if (preg_match('/create_function\s*\(.*\$_(GET|POST|REQUEST)/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'deprecated_dangerous',
                'severity' => SG_SEV_CRITICAL,
                'description' => 'create_function (deprecated) used with user input',
                'line' => $line,
            );
        }

        return $threats;
    }


    /**
     * Detect SQL Injection vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_sql_injection($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern 1: $wpdb->query() (and other methods) with variable (not using prepare)
        if (preg_match_all('/\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\(\s*(\$[a-zA-Z0-9_]+)\s*\)/i', $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
            foreach ($matches as $match) {
                $method_name = $match[1][0];
                $var_name = $match[2][0];
                $offset = $match[0][1];
                $taint_state = 'safe';

                // Check for prepare() in a proximity (lookback window ±3000 chars, total 6000)
                $start = max(0, $offset - 3000);
                $snippet = substr($content, $start, 6000);

                if (!preg_match('/\$wpdb->prepare\s*\(/i', $snippet)) {
                    $taint_state = $this->get_variable_taint_state($var_name, $snippet, $content);
                    if ('safe' === $taint_state) {
                        continue;
                    }

                    // Find variable definition: $var_name = ...
                    $is_safe_static = false;
                    if (preg_match('/' . preg_quote($var_name, '/') . '\s*=\s*(["\'])(.*?)\1\s*;/s', $snippet, $def_match)) {
                        $def_val = $def_match[2];
                        // Check if the definition has variable interpolation or concatenation
                        $has_concat = (strpos($def_match[0], '.') !== false);
                        $has_var = preg_match('/\$[a-zA-Z_]/', $def_val);
                        if (!$has_concat && !$has_var) {
                            $is_safe_static = true;
                        }
                    }

                    if (!$is_safe_static && 'unknown' === $taint_state) {
                        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                        $threats[] = array(
                            'file' => $this->normalize_file_path($file_path),
                            'type' => 'sql_taint_unknown',
                            'severity' => SG_SEV_LOW,
                            'description' => 'SQL query uses a variable with unresolved taint context',
                            'line' => $line,
                        );
                        continue;
                    }

                    if (!$is_safe_static) {
                        // Check for sanitization functions in the snippet
                        $has_sanitization = preg_match('/(?:absint|intval|esc_sql|sanitize_key|sanitize_text_field|floatval|doubleval)\s*\(/i', $snippet);
                        if (!$has_sanitization) {
                            $line = substr_count(substr($content, 0, $offset), "\n") + 1;
                            $threats[] = array(
                                'file' => $this->normalize_file_path($file_path),
                                'type' => 'sql_injection',
                                'severity' => SG_SEV_CRITICAL,
                                'description' => sprintf('SQL Injection: Direct variable in query method %s() without prepare() or sanitization', $method_name),
                                'line' => $line,
                            );
                        }
                    }
                }
            }
        }

        // Pattern 1b: SQL string concatenation with variables
        if (preg_match('/\$sql\s*=\s*["\'][^"\']*(INSERT|SELECT|UPDATE|DELETE)[^"\']*.\s*\$/is', $content, $match, PREG_OFFSET_CAPTURE)) {
            // Check for sanitization functions in the surrounding context
            $start = max(0, $match[0][1] - 400);
            $snippet = substr($content, $start, 800);
            $has_sanitization = preg_match('/(?:absint|intval|esc_sql|sanitize_key|sanitize_text_field|floatval|doubleval)\s*\(/i', $snippet);

            if (!$has_sanitization) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'sql_injection',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'SQL Injection: Variable concatenation in SQL query without sanitization',
                    'line' => $line,
                );
            }
        }

        // Pattern 2: Direct $_GET/$_POST in SQL queries
        $sql_patterns = array(
            '/\$wpdb->(query|get_results|get_var|get_row|get_col)\s*\([^)]*\$_(GET|POST|REQUEST)\[/is',
            '/mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)\[/is',
            '/mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)\[/is',
        );

        foreach ($sql_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $start = max(0, $match[0][1] - 400);
                $snippet = substr($content, $start, 800);
                $has_sanitization = preg_match('/(?:absint|intval|esc_sql|sanitize_key|sanitize_text_field|floatval|doubleval)\s*\(/i', $snippet);

                if (!$has_sanitization) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'sql_injection',
                        'severity' => SG_SEV_CRITICAL,
                        'description' => 'SQL Injection: User input directly in SQL query without sanitization',
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect CSRF vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_csrf($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Search entire content for nonce verification helpers. If present, do not flag.
        $global_guards = array(
            'wp_verify_nonce',
            'check_ajax_referer',
            'wc_verify_nonce',
            'check_admin_referer',
            'woocommerce_checkout_process',
            'wc_nocache_headers',
        );

        foreach ($global_guards as $item) {
            if (stripos($content, $item) !== false) {
                return array();
            }
        }

        // Pattern: $_POST processing without wp_verify_nonce()
        if (preg_match('/if\s*\(\s*isset\s*\(\s*\$_POST\[/', $content, $match, PREG_OFFSET_CAPTURE)) {
            // Check for nonce verification in proximity
            $start = max(0, $match[0][1] - 200);
            $snippet = substr($content, $start, 800);

            if (!preg_match('/wp_verify_nonce\s*\(|check_ajax_referer\s*\(|wc_verify_nonce\s*\(|check_admin_referer\s*\(|rest_api_init|WC_REST/i', $snippet)) {
                // Check for explicit state changes to reduce noise on read-only form elements
                $has_state_change = preg_match(
                    '/(?:wp_insert_post|wp_update_post|wp_delete_post|update_option|add_option|delete_option|wp_insert_comment|wp_delete_comment|wp_create_user|wp_insert_user|wp_update_user|wp_delete_user|\$wpdb->(?:insert|update|delete|query)|update_user_meta|add_user_meta|delete_user_meta|update_post_meta|add_post_meta|delete_post_meta)/i',
                    $snippet
                );

                if ($has_state_change) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'csrf',
                        'severity' => SG_SEV_HIGH,
                        'description' => 'CSRF: Form processing without nonce verification on state-changing operation',
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect unsafe file upload vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_unsafe_file_upload($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: move_uploaded_file() without extension validation
        if (preg_match('/move_uploaded_file\s*\(/', $content, $match, PREG_OFFSET_CAPTURE)) {
            // Check for extension validation
            $start = max(0, $match[0][1] - 500);
            $snippet = substr($content, $start, 1500);

            $has_validation = preg_match('/wp_check_filetype|pathinfo\s*\([^)]*PATHINFO_EXTENSION|in_array\s*\([^)]*allowed|mime|extension/i', $snippet);

            if (!$has_validation) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'unsafe_file_upload',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Unsafe File Upload: No extension/type validation detected',
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect cryptocurrency mining scripts (JavaScript)
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_crypto_mining($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Common crypto mining keywords
        $mining_keywords = array(
            'miner',
            'crypto',
            'cryptonight',
            'CryptoMiner',
            'setThrottle',
            'hashrate',
            'pool',
            'coinhive',
            'minero',
            'deepMiner',
        );

        $matches = 0;
        $found_keywords = array();

        foreach ($mining_keywords as $keyword) {
            if (stripos($content, $keyword) !== false) {
                $matches++;
                $found_keywords[] = $keyword;
            }
        }

        // If 2+ mining keywords found, likely a crypto miner
        if ($matches >= 2) {
            $threats[] = array(
                'file' => $this->normalize_file_path($file_path),
                'type' => 'crypto_mining',
                'severity' => SG_SEV_CRITICAL,
                'description' => sprintf('Cryptocurrency mining script detected (keywords: %s)', implode(', ', $found_keywords)),
                'line' => 1,
            );
        }

        return $threats;
    }

    /**
     * Detect information disclosure (DB credentials, secrets)
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_information_disclosure($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Sensitive WordPress constants
        $sensitive_constants = array(
            'DB_PASSWORD',
            'DB_USER',
            'DB_HOST',
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
        );

        foreach ($sensitive_constants as $constant) {
            // Lookfor output functions with these constants
            if (preg_match('/(?:echo|print|var_dump|print_r)\s*[^;]*' . preg_quote($constant, '/') . '/i', $content, $match, PREG_OFFSET_CAPTURE)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'information_disclosure',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => sprintf('Info Disclosure: DB credentials exposed (%s)', $constant),
                    'line' => $line,
                );
                break;
            }
        }

        return $threats;
    }

    /**
     * Detect Local File Inclusion (LFI) vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_lfi($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern 1: include/require with user input
        $lfi_patterns = array(
            '/(?:include|require)(?:_once)?\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
        );

        foreach ($lfi_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                $start = max(0, $match[0][1] - 400);
                $snippet = substr($content, $start, 800);

                $is_safe = preg_match(
                    '/(?:plugin_basename|sanitize_key|basename|switch|in_array|array_key_exists|\$class_map|\$whitelist|\$allowed_files|\$allowed)\s*\(/i',
                    $snippet
                );

                if (!$is_safe) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'lfi',
                        'severity' => SG_SEV_CRITICAL,
                        'description' => 'LFI: User input in include/require',
                        'line' => $line,
                    );
                }
            }
        }

        // Pattern 2: include with concatenation
        if (preg_match('/(?:include|require)(?:_once)?\s*\(([^)]+\.\s*["\'][^"\']*\.php[^)]*)\)/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $expr = $match[1][0];
            // Permit LFI inclusions containing safe constants and path functions without variables
            if (strpos($expr, '$') !== false) {
                $start = max(0, $match[0][1] - 400);
                $snippet = substr($content, $start, 800);

                $is_safe = preg_match(
                    '/(?:plugin_basename|sanitize_key|basename|switch|in_array|array_key_exists|\$class_map|\$whitelist|\$allowed_files|\$allowed)\s*\(/i',
                    $snippet
                );

                if (!$is_safe) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'lfi',
                        'severity' => SG_SEV_HIGH,
                        'description' => 'LFI: Dynamic file inclusion with concatenation',
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect Path Traversal vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_path_traversal($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern 1: User input in file operations without sanitization
        $file_ops = array('file_get_contents', 'fopen', 'readfile', 'file', 'is_file', 'is_dir', 'scandir');

        foreach ($file_ops as $func) {
            $pattern = '/' . $func . '\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i';
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                // Check for path sanitization
                $start = max(0, $match[0][1] - 400);
                $snippet = substr($content, $start, 800);

                $has_sanitization = preg_match('/realpath|basename|pathinfo|str_replace.*\.\.|preg_replace.*\.\./i', $snippet);

                if (!$has_sanitization) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'path_traversal',
                        'severity' => SG_SEV_CRITICAL,
                        'description' => "Path Traversal: User input in {$func}() without sanitization",
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect Arbitrary File Write vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_arbitrary_file_write($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: file operations with user input
        if (preg_match('/file_put_contents\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 200);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'arbitrary_file_write',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Arbitrary File Write: file_put_contents with user input',
                    'line' => $line,
                );
            }
        }

        if (preg_match('/fwrite\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 200);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'arbitrary_file_write',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Arbitrary File Write: fwrite with user input',
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect Arbitrary File Delete vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_arbitrary_file_delete($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: file deletion with user input 
        if (preg_match('/unlink\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 200);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'arbitrary_file_delete',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Arbitrary File Delete: unlink with user input',
                    'line' => $line,
                );
            }
        }

        if (preg_match('/(?:rmdir|wp_delete_file)\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 200);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'arbitrary_file_delete',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Arbitrary File Delete: User-controlled path',
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect Email Header Injection vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_email_injection($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: wp_mail() with user input in headers without sanitization
        if (preg_match('/wp_mail\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            // Check if user input is used in email headers
            $start = $match[0][1];
            $snippet = substr($content, $start, 1000);

            // Look for user input in headers
            if (
                preg_match('/\$_(GET|POST|REQUEST|COOKIE)\[/i', $snippet) &&
                !preg_match('/sanitize_email|sanitize_text_field|str_replace.*\\\\r|str_replace.*\\\\n/i', $snippet)
            ) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'email_injection',
                    'severity' => SG_SEV_HIGH,
                    'description' => 'Email Header Injection: Unsanitized user input in wp_mail()',
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect SSRF (Server-Side Request Forgery) vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_ssrf($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: Remote requests with user input
        if (preg_match('/(?:wp_remote_get|wp_remote_post)\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 250);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'ssrf',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'SSRF: User-controlled URL in wp_remote request',
                    'line' => $line,
                );
            }
        }

        // cURL with user input
        if (preg_match('/curl_setopt.*CURLOPT_URL/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 250);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'ssrf',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'SSRF: User-controlled URL in cURL',
                    'line' => $line,
                );
            }
        }

        return $threats;
    }

    /**
     * Detect Command Injection vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_command_injection($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: Command execution with user input
        $cmd_patterns = array(
            '/shell_exec\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/exec\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/system\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/passthru\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/proc_open\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
            '/popen\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)\[/i',
        );

        foreach ($cmd_patterns as $pattern) {
            if (preg_match($pattern, $content, $match, PREG_OFFSET_CAPTURE)) {
                // Check for escapeshellcmd/escapeshellarg
                $start = max(0, $match[0][1] - 300);
                $snippet = substr($content, $start, 600);

                $has_escaping = preg_match('/escapeshellcmd|escapeshellarg/i', $snippet);

                if (!$has_escaping) {
                    $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                    $threats[] = array(
                        'file' => $this->normalize_file_path($file_path),
                        'type' => 'command_injection',
                        'severity' => SG_SEV_CRITICAL,
                        'description' => 'Command Injection: User input in system command',
                        'line' => $line,
                    );
                }
            }
        }

        return $threats;
    }

    /**
     * Detect Object Injection (Deserialization) vulnerabilities
     *
     * @param string $file_path File path.
     * @param string $content File content.
     * @return array Threats found.
     */
    private function detect_object_injection($file_path, $content)
    {
        $threats = array();
        if ($this->is_empty_content($content)) {
            return $threats;
        }

        // Pattern: unserialize with user input (check within 100 chars)
        if (preg_match('/unserialize\s*\(/i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $snippet = substr($content, $match[0][1], 150);
            if (preg_match('/\$_(GET|POST|REQUEST|COOKIE)/', $snippet)) {
                $line = substr_count(substr($content, 0, $match[0][1]), "\n") + 1;
                $threats[] = array(
                    'file' => $this->normalize_file_path($file_path),
                    'type' => 'object_injection',
                    'severity' => SG_SEV_CRITICAL,
                    'description' => 'Object Injection: unserialize() with user input',
                    'line' => $line,
                );
            }
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
        if (!defined('WP_CONTENT_DIR') || empty(WP_CONTENT_DIR)) {
            return false;
        }

        $plugins_dir = WP_CONTENT_DIR . '/plugins';
        $themes_dir = WP_CONTENT_DIR . '/themes';

        return (strpos($file_path, $plugins_dir) !== false || strpos($file_path, $themes_dir) !== false);
    }

    /**
     * Calculate the overall threat score for a list of threats.
     *
     * @param array $raw_threats Array of threat details.
     * @return int Calculated threat score.
     */
    private function calculate_threat_score(array $raw_threats): int
    {
        $score = 0;
        foreach ($raw_threats as $threat) {
            $score += $this->get_threat_weight($threat);
        }

        return $score;
    }

    /**
     * Return the scoring weight for a single threat.
     *
     * @param array $threat Threat details.
     * @return int Threat weight.
     */
    private function get_threat_weight(array $threat): int
    {
        $type = isset($threat['type']) ? $threat['type'] : '';
        $severity = isset($threat['severity']) ? strtolower((string) $threat['severity']) : '';
        $description = isset($threat['description']) ? (string) $threat['description'] : '';

        if ('dangerous_function' === $type) {
            return 'critical' === $severity ? 40 : ('medium' === $severity ? 5 : 10);
        }

        if ('variable_function' === $type) {
            return 'high' === $severity ? 15 : 10;
        }

        if ('obfuscation' === $type && false !== stripos($description, 'Base64 + eval')) {
            return 30;
        }

        $weights = array(
            'sql_injection' => 35,
            'csrf' => 20,
            'lfi' => 25,
            'input_execution_flow' => 45,
            'command_injection' => 45,
        );

        return isset($weights[$type]) ? $weights[$type] : 10;
    }

    /**
     * Get threat severity color for display
     *
     * @param string $severity Severity level.
     * @return string Color code.
     */
    public function get_severity_color($severity)
    {
        $severity_upper = strtoupper($severity);
        $colors = array(
            'CRITICAL' => '#dc3545',
            'HIGH' => '#fd7e14',
            'MEDIUM' => '#ffc107',
            'LOW' => '#28a745',
        );

        return isset($colors[$severity_upper]) ? $colors[$severity_upper] : '#6c757d';
    }
}
