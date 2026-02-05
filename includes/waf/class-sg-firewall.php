<?php
/**
 * SpectrusGuard Firewall Engine
 *
 * Core WAF (Web Application Firewall) engine that analyzes requests
 * and blocks malicious payloads using regex pattern matching.
 *
 * Uses Factory pattern to create rule matchers for different attack types.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load IP Detection Trait
require_once SG_PLUGIN_DIR . 'includes/traits/IpDetectionTrait.php';

/**
 * Class SG_Firewall
 *
 * Main firewall engine with Factory pattern for rule matchers.
 */
class SG_Firewall
{
    use IpDetectionTrait;

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Firewall rules loaded from JSON
     *
     * @var array
     */
    private $rules = array();

    /**
     * Whitelisted IPs
     *
     * @var array
     */
    private $whitelist_ips = array();

    /**
     * Whitelisted paths (partial matches allowed)
     *
     * @var array
     */
    private $whitelist_paths = array();

    /**
     * Attack type severity levels
     *
     * @var array
     */
    private static $severity_map = array(
        'sqli' => 'critical',
        'rce' => 'critical',
        'xss' => 'high',
        'traversal' => 'high',
        'lfi' => 'high',
        'upload' => 'medium',
        'spam' => 'low',
    );

    /**
     * Constructor
     *
     * @param SG_Logger $logger Logger instance.
     */
    public function __construct(SG_Logger $logger)
    {
        $this->logger = $logger;
        $this->load_rules();
        $this->load_whitelist();
    }

    /**
     * Load firewall rules from JSON file
     */
    private function load_rules()
    {
        // Try to load from PHP file first (faster)
        $rules_php = SG_PLUGIN_DIR . 'includes/waf/rules.php';
        if (file_exists($rules_php)) {
            $this->rules = require $rules_php;
            return;
        }

        $rules_file = SG_PLUGIN_DIR . 'includes/waf/rules.json';

        if (!file_exists($rules_file)) {
            $this->logger->log_debug('Rules file not found: ' . $rules_file, 'error');
            return;
        }

        $json_content = file_get_contents($rules_file);
        $rules = json_decode($json_content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->logger->log_debug('Invalid rules JSON: ' . json_last_error_msg(), 'error');
            return;
        }

        $this->rules = $rules;
    }

    /**
     * Load whitelist from settings
     */
    private function load_whitelist()
    {
        $settings = get_option('spectrus_shield_settings', array());

        $this->whitelist_ips = isset($settings['whitelist_ips'])
            ? (array) $settings['whitelist_ips']
            : array();

        // Default whitelisted paths (WordPress admin AJAX, REST, etc.)
        $this->whitelist_paths = array(
            '/wp-admin/admin-ajax.php',
            '/wp-json/spectrus-guard/',
            '/wp-cron.php',
        );

        // Allow custom whitelist paths from settings
        if (isset($settings['whitelist_paths'])) {
            $this->whitelist_paths = array_merge(
                $this->whitelist_paths,
                (array) $settings['whitelist_paths']
            );
        }
    }

    /**
     * Analyze the current request for malicious content
     *
     * Main entry point for the firewall.
     *
     * @return array|false Array with attack info if detected, false if clean.
     */
    public function analyze_request()
    {
        // Skip if whitelisted
        if ($this->is_whitelisted()) {
            return false;
        }

        // Collect all input data to analyze
        $request_data = $this->collect_request_data();

        // Run all checks
        $checks = array(
            'sqli' => 'check_sqli',
            'xss' => 'check_xss',
            'traversal' => 'check_traversal',
            'rce' => 'check_rce',
            'lfi' => 'check_lfi',
        );

        foreach ($checks as $type => $method) {
            $result = $this->$method($request_data);
            if ($result !== false) {
                return array(
                    'type' => $type,
                    'payload' => $result,
                    'severity' => self::$severity_map[$type] ?? 'medium',
                );
            }
        }

        return false;
    }

    /**
     * Collect all request data for analysis
     *
     * @return array
     */
    private function collect_request_data()
    {
        $data = array();

        // Query string parameters
        if (!empty($_GET)) {
            $data['get'] = $this->flatten_array($_GET);
        }

        // POST data
        if (!empty($_POST)) {
            $data['post'] = $this->flatten_array($_POST);
        }

        // Request URI
        if (isset($_SERVER['REQUEST_URI'])) {
            $data['uri'] = urldecode($_SERVER['REQUEST_URI']);
        }

        // Query string raw
        if (isset($_SERVER['QUERY_STRING'])) {
            $data['query_string'] = urldecode($_SERVER['QUERY_STRING']);
        }

        // Cookies (be careful here, may cause issues with sessions)
        // $data['cookies'] = $this->flatten_array( $_COOKIE );

        // Request body (for JSON/XML APIs)
        $raw_input = file_get_contents('php://input');
        if (!empty($raw_input)) {
            $data['raw_body'] = $raw_input;
        }

        return $data;
    }

    /**
     * Flatten a nested array into a single level array of values
     *
     * @param array  $array  Array to flatten.
     * @param string $prefix Key prefix (for recursion).
     * @return array
     */
    private function flatten_array($array, $prefix = '')
    {
        $result = array();

        foreach ($array as $key => $value) {
            $new_key = $prefix ? $prefix . '[' . $key . ']' : $key;

            if (is_array($value)) {
                $result = array_merge($result, $this->flatten_array($value, $new_key));
            } else {
                $result[$new_key] = $value;
            }
        }

        return $result;
    }

    /**
     * Check for SQL Injection patterns
     *
     * @param array $data Request data to check.
     * @return string|false Matched payload or false.
     */
    private function check_sqli($data)
    {
        if (empty($this->rules['sqli'])) {
            return false;
        }

        return $this->match_rules($data, $this->rules['sqli'], 'sqli');
    }

    /**
     * Check for XSS (Cross-Site Scripting) patterns
     *
     * @param array $data Request data to check.
     * @return string|false Matched payload or false.
     */
    private function check_xss($data)
    {
        if (empty($this->rules['xss'])) {
            return false;
        }

        return $this->match_rules($data, $this->rules['xss'], 'xss');
    }

    /**
     * Check for Path Traversal patterns
     *
     * @param array $data Request data to check.
     * @return string|false Matched payload or false.
     */
    private function check_traversal($data)
    {
        if (empty($this->rules['traversal'])) {
            return false;
        }

        return $this->match_rules($data, $this->rules['traversal'], 'traversal');
    }

    /**
     * Check for Remote Code Execution patterns
     *
     * @param array $data Request data to check.
     * @return string|false Matched payload or false.
     */
    private function check_rce($data)
    {
        if (empty($this->rules['rce'])) {
            return false;
        }

        return $this->match_rules($data, $this->rules['rce'], 'rce');
    }

    /**
     * Check for Local File Inclusion patterns
     *
     * @param array $data Request data to check.
     * @return string|false Matched payload or false.
     */
    private function check_lfi($data)
    {
        if (empty($this->rules['lfi'])) {
            return false;
        }

        return $this->match_rules($data, $this->rules['lfi'], 'lfi');
    }

    /**
     * Match rules against data
     *
     * Factory method that applies regex rules to all input data.
     *
     * @param array  $data  Data to check.
     * @param array  $rules Regex rules to apply.
     * @param string $type  Attack type for logging.
     * @return string|false Matched payload or false.
     */
    private function match_rules($data, $rules, $type)
    {
        foreach ($data as $key => $values) {
            // Handle both strings and arrays
            if (!is_array($values)) {
                $values = array($key => $values);
            }

            foreach ($values as $param_name => $value) {
                if (!is_string($value)) {
                    continue;
                }

                // Decode value multiple times to catch encoding tricks
                $decoded = $this->decode_value($value);

                foreach ($rules as $rule) {
                    // Suppress warnings for invalid regex patterns
                    if (@preg_match($rule, $decoded)) {
                        return $value;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Decode a value to catch encoding evasion techniques
     *
     * @param string $value Value to decode.
     * @return string Decoded value.
     */
    private function decode_value($value)
    {
        // URL decode (multiple passes for double/triple encoding)
        $decoded = $value;
        for ($i = 0; $i < 3; $i++) {
            $new_decoded = urldecode($decoded);
            if ($new_decoded === $decoded) {
                break;
            }
            $decoded = $new_decoded;
        }

        // HTML entity decode
        $decoded = html_entity_decode($decoded, ENT_QUOTES, 'UTF-8');

        // Handle null bytes
        $decoded = str_replace(chr(0), '', $decoded);

        // Handle unicode escapes
        $decoded = preg_replace_callback(
            '/\\\\u([0-9a-fA-F]{4})/',
            function ($matches) {
                return mb_convert_encoding(pack('H*', $matches[1]), 'UTF-8', 'UCS-2BE');
            },
            $decoded
        );

        return $decoded;
    }

    /**
     * Check if current request is whitelisted
     *
     * @return bool True if whitelisted, false otherwise.
     */
    public function is_whitelisted()
    {
        // Check IP whitelist
        $client_ip = $this->get_client_ip();
        if (in_array($client_ip, $this->whitelist_ips, true)) {
            return true;
        }

        // Check path whitelist
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        foreach ($this->whitelist_paths as $path) {
            if (strpos($request_uri, $path) !== false) {
                return true;
            }
        }

        // Check if user is logged in admin
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            if (function_exists('current_user_can') && current_user_can('manage_options')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the client IP address securely.
     *
     * Delegates to IpDetectionTrait::getClientIpSecure() with trusted proxies.
     *
     * @return string Client IP address.
     */
    public function get_client_ip()
    {
        return $this->getClientIpSecure($this->getTrustedProxiesFromSettings());
    }

    /**
     * Retrieves trusted proxies from plugin settings.
     *
     * @return array An array of trusted proxy IP addresses or CIDR ranges.
     */
    private function getTrustedProxiesFromSettings()
    {
        $settings = get_option('spectrus_shield_settings', array());
        return isset($settings['trusted_proxies']) ? (array) $settings['trusted_proxies'] : array();
    }

    /**
     * Check if an IP is within a given range (CIDR notation supported).
     *
     * @param string $ip    IP address to check.
     * @param string $range IP range (single IP or CIDR).
     * @return bool True if IP is in range.
     */
    private function ip_in_range($ip, $range)
    {
        if (strpos($range, '/') === false) {
            // Single IP comparison
            return $ip === $range;
        }

        // CIDR notation
        list($subnet, $bits) = explode('/', $range);

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - (int) $bits);

        $subnet_long &= $mask;

        return ($ip_long & $mask) === $subnet_long;
    }

    /**
     * Block the request and log the attack
     *
     * @param array $attack Attack information from analyze_request().
     */
    public function block_request($attack)
    {
        $ip = $this->get_client_ip();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

        // Log the attack
        $this->logger->log_attack(
            $attack['type'],
            $attack['payload'],
            $ip,
            $uri
        );

        // Set response headers
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            // Sanitize type for header (defense in depth - prevent HTTP Response Splitting)
            $safe_type = preg_replace('/[^a-zA-Z0-9_-]/', '', $attack['type']);
            header('X-SpectrusGuard-Block: ' . $safe_type);
            header('Connection: close');
        }

        // Display block page
        $this->display_block_page($attack);

        exit;
    }

    /**
     * Display the block page
     *
     * @param array $attack Attack information.
     */
    private function display_block_page($attack)
    {
        $incident_id = substr(md5(uniqid('', true)), 0, 12);

        $template_path = SG_PLUGIN_DIR . 'templates/views/block-page.php';

        if (file_exists($template_path)) {
            include $template_path;
        } else {
            // Fallback if template is missing
            echo '<!DOCTYPE html><html><head><title>Access Denied</title></head>';
            echo '<body><h1>Access Blocked</h1>';
            echo '<p>Incident ID: ' . esc_html($incident_id) . '</p>';
            echo '</body></html>';
        }
    }

    /**
     * Get severity level for an attack type
     *
     * @param string $type Attack type.
     * @return string Severity level.
     */
    public static function get_severity($type)
    {
        return self::$severity_map[$type] ?? 'medium';
    }

    /**
     * Add an IP to the whitelist
     *
     * @param string $ip IP address to whitelist.
     * @return bool True on success.
     */
    public function add_to_whitelist($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (!in_array($ip, $this->whitelist_ips, true)) {
            $this->whitelist_ips[] = $ip;

            $settings = get_option('spectrus_shield_settings', array());
            $settings['whitelist_ips'] = $this->whitelist_ips;
            update_option('spectrus_shield_settings', $settings);
        }

        return true;
    }

    /**
     * Remove an IP from the whitelist
     *
     * @param string $ip IP address to remove.
     * @return bool True on success.
     */
    public function remove_from_whitelist($ip)
    {
        $key = array_search($ip, $this->whitelist_ips, true);

        if ($key !== false) {
            unset($this->whitelist_ips[$key]);
            $this->whitelist_ips = array_values($this->whitelist_ips);

            $settings = get_option('spectrus_shield_settings', array());
            $settings['whitelist_ips'] = $this->whitelist_ips;
            update_option('spectrus_shield_settings', $settings);

            return true;
        }

        return false;
    }
}
