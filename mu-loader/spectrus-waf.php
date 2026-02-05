<?php
/**
 * SpectrusGuard WAF - Must-Use Plugin (DROP-IN)
 *
 * ⚠️ CRITICAL FILE: This file executes BEFORE WordPress loads!
 *
 * This file is automatically copied to wp-content/mu-plugins/ when the
 * SpectrusGuard plugin is activated. It intercepts malicious requests
 * before they can reach WordPress core or any other plugins.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct web access to this file
if (!defined('ABSPATH')) {
    // If we're being loaded directly (not by WordPress), we need to set up our own path
    // This should never happen, but just in case...
    exit('Direct access not allowed.');
}

/**
 * SpectrusGuard MU-Plugin Guard
 *
 * Early execution firewall that runs before WordPress initializes.
 */
class SpectrusGuard_MU_Guard
{

    /**
     * Path to the main SpectrusGuard plugin
     *
     * @var string
     */
    private $plugin_dir;

    /**
     * Path to the rules file
     *
     * @var string
     */
    private $rules_file;

    /**
     * Loaded rules
     *
     * @var array
     */
    private $rules = array();

    /**
     * Settings from options (cached)
     *
     * @var array|null
     */
    private $settings = null;

    /**
     * Constructor - Initialize and run the guard
     */
    public function __construct()
    {
        // Define paths
        // Define path to main plugin
        if (!defined('SG_CORE_PATH')) {
            define('SG_CORE_PATH', WP_CONTENT_DIR . '/plugins/SpectrusGuard/');
        }
        $this->plugin_dir = SG_CORE_PATH;
        $this->rules_file = $this->plugin_dir . 'includes/waf/rules.json';

        // Early exit conditions
        if ($this->should_skip()) {
            return;
        }

        // Check rescue mode FIRST (fail-safe)
        if ($this->is_rescue_mode()) {
            return;
        }

        // Load and check
        if ($this->load_rules()) {
            $this->analyze_and_block();
        }
    }

    /**
     * Check if we should skip the firewall entirely
     *
     * @return bool
     */
    private function should_skip()
    {
        // Skip for WP-CLI
        if (defined('WP_CLI') && WP_CLI) {
            return true;
        }

        // Skip for WP Cron
        if (defined('DOING_CRON') && DOING_CRON) {
            return true;
        }

        // Skip for admin-ajax.php (critical for plugin functionality)
        if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/admin-ajax.php') !== false) {
            return true;
        }

        // Skip for load-scripts.php (WordPress core functionality)
        if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/load-scripts.php') !== false) {
            return true;
        }

        // Skip if main plugin doesn't exist
        if (!file_exists($this->plugin_dir . 'spectrus-guard.php')) {
            return true;
        }

        // Skip if rules file doesn't exist
        if (!file_exists($this->rules_file)) {
            return true;
        }

        return false;
    }

    /**
     * Check if rescue mode is active
     *
     * Rescue mode allows bypassing the WAF in case of false positives.
     * This is the fail-safe mechanism.
     *
     * @return bool
     */
    private function is_rescue_mode()
    {
        // 1. Check for rescue key in URL
        $settings = $this->get_settings();
        $rescue_key = isset($settings['rescue_key']) ? $settings['rescue_key'] : '';

        if (!empty($rescue_key) && isset($_GET['spectrus_rescue'])) {
            if ($_GET['spectrus_rescue'] === $rescue_key) {
                // Set a cookie to maintain rescue mode for 1 hour
                setcookie('sg_rescue_mode', md5($rescue_key), time() + 3600, '/');
                return true;
            }
        }

        // 2. Check for rescue cookie
        if (isset($_COOKIE['sg_rescue_mode']) && !empty($rescue_key)) {
            if ($_COOKIE['sg_rescue_mode'] === md5($rescue_key)) {
                return true;
            }
        }

        // 3. Check for whitelisted IP
        $whitelist_ips = isset($settings['whitelist_ips']) ? (array) $settings['whitelist_ips'] : array();
        $client_ip = $this->get_client_ip();

        if (in_array($client_ip, $whitelist_ips, true)) {
            return true;
        }

        return false;
    }

    /**
     * Get settings from WordPress options
     *
     * Note: At this point, WordPress options API is available since ABSPATH is defined.
     *
     * @return array
     */
    private function get_settings()
    {
        if ($this->settings !== null) {
            return $this->settings;
        }

        // Try to get settings from options
        // Note: This requires the database to be available
        global $wpdb;

        if (!isset($wpdb) || !$wpdb) {
            $this->settings = array();
            return $this->settings;
        }

        $option_name = 'spectrus_shield_settings';
        $table_name = $wpdb->options;

        // Direct query since we're early in the load process
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT option_value FROM {$table_name} WHERE option_name = %s LIMIT 1",
                $option_name
            )
        );

        if ($row && !empty($row->option_value)) {
            $this->settings = maybe_unserialize($row->option_value);
        } else {
            $this->settings = array();
        }

        return $this->settings;
    }

    /**
     * Load firewall rules from JSON file or PHP cache
     *
     * @return bool True if rules loaded successfully
     */
    private function load_rules()
    {
        // Try to load from PHP file first (faster)
        $rules_php = $this->plugin_dir . 'includes/waf/rules.php';
        if (file_exists($rules_php)) {
            $this->rules = require $rules_php;
            return true;
        }

        if (!file_exists($this->rules_file)) {
            return false;
        }

        $json = file_get_contents($this->rules_file);
        $rules = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return false;
        }

        $this->rules = $rules;
        return true;
    }

    /**
     * Main analysis and blocking logic
     */
    private function analyze_and_block()
    {
        // Check if WAF is enabled
        $settings = $this->get_settings();
        if (isset($settings['waf_enabled']) && $settings['waf_enabled'] === false) {
            return;
        }

        // === GEO-BLOCKING CHECK (Sprint 9) ===
        // Check geo-blocking BEFORE pattern analysis
        $this->check_geo_blocking($settings);

        // Collect request data
        $request_data = $this->collect_request_data();

        // Check each attack type
        $attack_types = array('sqli', 'xss', 'traversal', 'rce', 'lfi');

        foreach ($attack_types as $type) {
            if (empty($this->rules[$type])) {
                continue;
            }

            $matched = $this->check_patterns($request_data, $this->rules[$type]);
            if ($matched !== false) {
                $this->block_request($type, $matched);
            }
        }
    }


    /**
     * Collect all request data for analysis
     *
     * @return array
     */
    private function collect_request_data()
    {
        $data = array();

        // GET parameters
        if (!empty($_GET)) {
            foreach ($_GET as $key => $value) {
                $data[] = $this->decode_value($key);
                if (is_array($value)) {
                    $data = array_merge($data, $this->flatten_values($value));
                } else {
                    $data[] = $this->decode_value($value);
                }
            }
        }

        // POST parameters
        if (!empty($_POST)) {
            foreach ($_POST as $key => $value) {
                $data[] = $this->decode_value($key);
                if (is_array($value)) {
                    $data = array_merge($data, $this->flatten_values($value));
                } else {
                    $data[] = $this->decode_value($value);
                }
            }
        }

        // Request URI
        if (isset($_SERVER['REQUEST_URI'])) {
            $data[] = $this->decode_value($_SERVER['REQUEST_URI']);
        }

        // Query string
        if (isset($_SERVER['QUERY_STRING'])) {
            $data[] = $this->decode_value($_SERVER['QUERY_STRING']);
        }

        // User Agent (for scanner detection)
        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $data[] = $_SERVER['HTTP_USER_AGENT'];
        }

        // Raw body for JSON/XML APIs
        $raw_input = file_get_contents('php://input');
        if (!empty($raw_input) && strlen($raw_input) < 100000) {
            $data[] = $this->decode_value($raw_input);
        }

        return $data;
    }

    /**
     * Flatten nested array values
     *
     * @param array $array Array to flatten.
     * @return array
     */
    private function flatten_values($array)
    {
        $result = array();
        foreach ($array as $value) {
            if (is_array($value)) {
                $result = array_merge($result, $this->flatten_values($value));
            } else {
                $result[] = $this->decode_value($value);
            }
        }
        return $result;
    }

    /**
     * Decode value to catch encoding evasion
     *
     * @param string $value Value to decode.
     * @return string
     */
    private function decode_value($value)
    {
        if (!is_string($value)) {
            return '';
        }

        // URL decode multiple times
        $decoded = $value;
        for ($i = 0; $i < 3; $i++) {
            $new = urldecode($decoded);
            if ($new === $decoded) {
                break;
            }
            $decoded = $new;
        }

        // HTML entity decode
        $decoded = html_entity_decode($decoded, ENT_QUOTES, 'UTF-8');

        // Remove null bytes
        $decoded = str_replace(chr(0), '', $decoded);

        return $decoded;
    }

    /**
     * Check patterns against data
     *
     * @param array $data     Data to check.
     * @param array $patterns Regex patterns.
     * @return string|false   Matched content or false.
     */
    private function check_patterns($data, $patterns)
    {
        foreach ($data as $value) {
            if (empty($value) || !is_string($value)) {
                continue;
            }

            foreach ($patterns as $pattern) {
                // Suppress warnings for invalid patterns
                if (@preg_match($pattern, $value)) {
                    return $value;
                }
            }
        }

        return false;
    }

    /**
     * Block the malicious request
     *
     * @param string $type    Attack type.
     * @param string $payload Matched payload.
     */
    private function block_request($type, $payload)
    {
        // Log the attack
        $this->log_attack($type, $payload);

        // Update stats
        $this->update_stats($type);

        // Set headers
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            // Sanitize type for header (defense in depth - prevent HTTP Response Splitting)
            $safe_type = preg_replace('/[^a-zA-Z0-9_-]/', '', strtoupper($type));
            header('X-SpectrusGuard-Blocked: ' . $safe_type);
            header('Connection: close');
        }

        // Display block page
        $this->display_block_page($type);

        exit;
    }

    /**
     * Log attack to file
     *
     * @param string $type    Attack type.
     * @param string $payload Matched payload.
     */
    private function log_attack($type, $payload)
    {
        $log_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
        $log_file = $log_dir . '/attacks.log';

        // Create log directory if needed
        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
            file_put_contents($log_dir . '/.htaccess', "Order deny,allow\nDeny from all");
            file_put_contents($log_dir . '/index.php', '<?php // Silence is golden');
        }

        // Prepare log entry
        $timestamp = date('Y-m-d H:i:s');
        $ip = $this->get_client_ip();
        $uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 200) : '';
        $payload = substr(str_replace(array("\n", "\r", "\t"), ' ', $payload), 0, 500);

        $log_line = sprintf(
            "[%s] [%s] IP: %s | URI: %s | Payload: %s | UA: %s\n",
            $timestamp,
            strtoupper($type),
            $ip,
            $uri,
            addslashes($payload),
            $user_agent
        );

        // Rotate log if too large (5MB)
        if (file_exists($log_file) && filesize($log_file) > 5242880) {
            rename($log_file, $log_file . '.' . date('Y-m-d-His') . '.bak');
        }

        file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Update attack statistics
     *
     * @param string $type Attack type.
     */
    private function update_stats($type)
    {
        global $wpdb;

        if (!isset($wpdb) || !$wpdb) {
            return;
        }

        $option_name = 'spectrus_shield_attack_stats';
        $table_name = $wpdb->options;

        // Get current stats
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT option_value FROM {$table_name} WHERE option_name = %s LIMIT 1",
                $option_name
            )
        );

        $stats = array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'lfi_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => array(),
        );

        if ($row && !empty($row->option_value)) {
            $stats = array_merge($stats, maybe_unserialize($row->option_value));
        }

        // Update counters
        $stats['total_blocked']++;
        $type_key = strtolower($type) . '_blocked';
        if (isset($stats[$type_key])) {
            $stats[$type_key]++;
        }
        $stats['last_attack'] = date('Y-m-d H:i:s');

        // Update daily stats
        $today = date('Y-m-d');
        if (!isset($stats['daily_stats'][$today])) {
            $stats['daily_stats'][$today] = 0;
        }
        $stats['daily_stats'][$today]++;

        // Prune old stats (keep 30 days)
        $cutoff = date('Y-m-d', strtotime('-30 days'));
        foreach ($stats['daily_stats'] as $date => $count) {
            if ($date < $cutoff) {
                unset($stats['daily_stats'][$date]);
            }
        }

        // Save stats
        $serialized = maybe_serialize($stats);
        if ($row) {
            $wpdb->update(
                $table_name,
                array('option_value' => $serialized),
                array('option_name' => $option_name)
            );
        } else {
            $wpdb->insert(
                $table_name,
                array(
                    'option_name' => $option_name,
                    'option_value' => $serialized,
                    'autoload' => 'no',
                )
            );
        }
    }

    /**
     * Check geo-blocking rules (Sprint 9)
     *
     * Implements fail-open: if no database is available, access is allowed.
     * Respects whitelist IPs (already checked in is_rescue_mode).
     *
     * @param array $settings Plugin settings
     */
    private function check_geo_blocking($settings)
    {
        // Check if geo-blocking is configured
        $blocked_countries = isset($settings['geo_blocked_countries']) ? (array) $settings['geo_blocked_countries'] : array();
        $block_tor = isset($settings['geo_block_tor']) ? (bool) $settings['geo_block_tor'] : false;

        // Early exit if nothing to block
        if (empty($blocked_countries) && !$block_tor) {
            return;
        }

        // Load geo engine if available
        $geo_engine_file = $this->plugin_dir . 'includes/geo/class-sg-geo-engine.php';
        if (!file_exists($geo_engine_file)) {
            // Fail-open: no geo module, allow access
            return;
        }

        require_once $geo_engine_file;

        if (!class_exists('SG_Geo_Engine')) {
            return;
        }

        $geo_engine = new SG_Geo_Engine();

        // Check if database is available
        if (!$geo_engine->is_database_installed()) {
            // Fail-open: no database, allow access
            return;
        }

        $client_ip = $this->get_client_ip();

        // 1. Check Tor exit nodes
        if ($block_tor && $geo_engine->is_tor_node($client_ip)) {
            $action = isset($settings['geo_action']) ? $settings['geo_action'] : '403';
            $this->log_geo_block($client_ip, 'TOR', $action);
            $this->execute_geo_action($action, 'TOR');
        }

        // 2. Check country blocking
        if (!empty($blocked_countries)) {
            $country = $geo_engine->get_country_iso($client_ip);

            if ($country && in_array($country, $blocked_countries, true)) {
                $action = isset($settings['geo_action']) ? $settings['geo_action'] : '403';
                $this->log_geo_block($client_ip, $country, $action);
                $this->execute_geo_action($action, $country);
            }
        }
    }

    /**
     * Execute the configured geo-blocking action
     *
     * @param string $action Action type (403, captcha, redirect)
     * @param string $country_code Country code or 'TOR'
     */
    private function execute_geo_action($action, $country_code)
    {
        switch ($action) {
            case 'captcha':
            // For now, fall through to 403
            // Future: implement CAPTCHA challenge
            case '403':
            default:
                header('HTTP/1.1 403 Forbidden');
                // Sanitize country code for header (defense in depth - prevent HTTP Response Splitting)
                $safe_country = preg_replace('/[^a-zA-Z0-9_-]/', '', strtolower($country_code));
                header('X-SpectrusGuard-Block: geo-' . $safe_country);
                echo '<!DOCTYPE html><html><head><title>Access Denied</title>';
                echo '<style>body{font-family:sans-serif;text-align:center;padding:50px;background:#1a1a2e;color:#fff;}';
                echo 'h1{color:#e94560;}</style></head><body>';
                echo '<h1>🛡️ Access Denied</h1>';
                echo '<p>Your access has been restricted by geographic security policy.</p>';
                echo '<p style="color:#666;font-size:12px;">SpectrusGuard Geo-Defense</p>';
                echo '</body></html>';
                exit;

            case 'redirect':
                // Redirect to a custom page (could be configurable)
                header('HTTP/1.1 302 Found');
                header('Location: /access-denied/');
                exit;
        }
    }

    /**
     * Log a geo-block event
     *
     * @param string $ip Client IP
     * @param string $country Country code or 'TOR'
     * @param string $action Action taken
     */
    private function log_geo_block($ip, $country, $action)
    {
        global $wpdb;

        if (!isset($wpdb) || !$wpdb) {
            return;
        }

        // Update geo-block statistics
        $stats_option = 'spectrus_geo_stats';
        $stats_row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1",
                $stats_option
            )
        );

        $stats = array();
        if ($stats_row && !empty($stats_row->option_value)) {
            $stats = maybe_unserialize($stats_row->option_value);
            if (!is_array($stats)) {
                $stats = array();
            }
        }

        // Increment country counter
        if (!isset($stats['countries'])) {
            $stats['countries'] = array();
        }
        if (!isset($stats['countries'][$country])) {
            $stats['countries'][$country] = 0;
        }
        $stats['countries'][$country]++;

        // Total blocks
        if (!isset($stats['total'])) {
            $stats['total'] = 0;
        }
        $stats['total']++;

        // Last block time
        $stats['last_block'] = time();

        // Save stats
        $serialized = maybe_serialize($stats);
        if ($stats_row) {
            $wpdb->update(
                $wpdb->options,
                array('option_value' => $serialized),
                array('option_name' => $stats_option)
            );
        } else {
            $wpdb->insert(
                $wpdb->options,
                array(
                    'option_name' => $stats_option,
                    'option_value' => $serialized,
                    'autoload' => 'no'
                )
            );
        }

        // Also log to main attack log if logging is enabled
        $log_attacks = isset($this->settings['log_attacks']) ? $this->settings['log_attacks'] : true;
        if ($log_attacks) {
            $this->log_attack('geo', $country . ' (' . $action . ')');
        }
    }

    /**
     * Get client IP address securely
     *
     * Only trusts proxy headers if request comes from a trusted proxy.
     *
     * @return string Client IP address
     */
    private function get_client_ip()
    {
        $remote_addr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Validate REMOTE_ADDR
        if (!filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            return '0.0.0.0';
        }

        // Get trusted proxies from settings
        $settings = get_option('spectrus_shield_settings', []);
        $trusted_proxies = isset($settings['trusted_proxies']) ? (array) $settings['trusted_proxies'] : [];

        // Add CloudFlare IPs if enabled
        if (!empty($settings['cloudflare_enabled'])) {
            $cf_ips = get_transient('sg_cloudflare_ip_ranges');
            if (is_array($cf_ips)) {
                $trusted_proxies = array_merge($trusted_proxies, $cf_ips);
            }
        }

        // If no trusted proxies, only trust REMOTE_ADDR
        if (empty($trusted_proxies)) {
            return $remote_addr;
        }

        // Check if request comes from a trusted proxy
        $is_trusted = false;
        foreach ($trusted_proxies as $proxy) {
            if ($this->ip_in_range_check($remote_addr, $proxy)) {
                $is_trusted = true;
                break;
            }
        }

        if (!$is_trusted) {
            return $remote_addr;
        }

        // Only now trust proxy headers
        $proxy_headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
        ];

        foreach ($proxy_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return $remote_addr;
    }

    /**
     * Check if IP is in range (CIDR supported)
     *
     * @param string $ip    IP to check
     * @param string $range Range (IP or CIDR)
     * @return bool
     */
    private function ip_in_range_check($ip, $range)
    {
        // IPv6 check
        if (strpos($range, ':') !== false) {
            return $this->ipv6_in_range($ip, $range);
        }

        // Single IP
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        // CIDR
        list($subnet, $bits) = explode('/', $range);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);

        if ($ip_long === false || $subnet_long === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);
        return ($ip_long & $mask) === ($subnet_long & $mask);
    }

    /**
     * Check if IPv6 is in range
     *
     * @param string $ip   IPv6 address
     * @param string $cidr CIDR range
     * @return bool
     */
    private function ipv6_in_range($ip, $cidr)
    {
        if (strpos($ip, ':') === false) {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        list($subnet, $bits) = explode('/', $cidr);
        $bits = (int) $bits;

        $ip_bin = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);

        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }

        $full_bytes = (int) floor($bits / 8);
        if (substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
            return false;
        }

        $remaining_bits = $bits % 8;
        if ($remaining_bits > 0 && $full_bytes < 16) {
            $mask = 0xFF << (8 - $remaining_bits);
            if ((ord($ip_bin[$full_bytes]) & $mask) !== (ord($subnet_bin[$full_bytes]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Display the block page
     *
     * @param string $type Attack type.
     */
    private function display_block_page($type)
    {
        $incident_id = substr(md5(uniqid('', true)), 0, 12);
        ?>
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="robots" content="noindex, nofollow">
            <title>Access Denied | SpectrusGuard Security</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1f3c 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #fff;
                    overflow: hidden;
                }

                .container {
                    text-align: center;
                    padding: 2rem;
                    max-width: 600px;
                    position: relative;
                    z-index: 1;
                }

                .shield-icon {
                    width: 120px;
                    height: 120px;
                    margin: 0 auto 1.5rem;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 3.5rem;
                    box-shadow: 0 20px 60px rgba(102, 126, 234, 0.4);
                    animation: float 3s ease-in-out infinite;
                }

                @keyframes float {

                    0%,
                    100% {
                        transform: translateY(0);
                    }

                    50% {
                        transform: translateY(-10px);
                    }
                }

                h1 {
                    font-size: 2.2rem;
                    margin-bottom: 0.75rem;
                    background: linear-gradient(135deg, #ff6b6b, #ff8e53);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                }

                .subtitle {
                    font-size: 1.1rem;
                    color: #a8a8b3;
                    margin-bottom: 1.5rem;
                    line-height: 1.6;
                }

                .details {
                    background: rgba(255, 255, 255, 0.05);
                    backdrop-filter: blur(10px);
                    border-radius: 12px;
                    padding: 1.25rem;
                    margin-bottom: 1.5rem;
                    border: 1px solid rgba(255, 255, 255, 0.1);
                }

                .details p {
                    color: #8888a8;
                    font-size: 0.9rem;
                    line-height: 1.6;
                }

                .incident-box {
                    background: rgba(255, 215, 0, 0.1);
                    border: 1px solid rgba(255, 215, 0, 0.3);
                    border-radius: 8px;
                    padding: 1rem;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.85rem;
                    color: #ffd700;
                    margin-bottom: 1.5rem;
                }

                .back-btn {
                    display: inline-block;
                    padding: 14px 32px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #fff;
                    text-decoration: none;
                    border-radius: 30px;
                    font-weight: 600;
                    font-size: 1rem;
                    transition: all 0.3s ease;
                    box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
                }

                .back-btn:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 15px 50px rgba(102, 126, 234, 0.5);
                }

                .bg-grid {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background-image:
                        linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
                    background-size: 50px 50px;
                    pointer-events: none;
                }

                .glow-orb {
                    position: fixed;
                    width: 400px;
                    height: 400px;
                    border-radius: 50%;
                    background: radial-gradient(circle, rgba(102, 126, 234, 0.15) 0%, transparent 70%);
                    pointer-events: none;
                }

                .glow-orb.top {
                    top: -200px;
                    right: -100px;
                }

                .glow-orb.bottom {
                    bottom: -200px;
                    left: -100px;
                    background: radial-gradient(circle, rgba(118, 75, 162, 0.15) 0%, transparent 70%);
                }
            </style>
        </head>

        <body>
            <div class="bg-grid"></div>
            <div class="glow-orb top"></div>
            <div class="glow-orb bottom"></div>

            <div class="container">
                <div class="shield-icon">🛡️</div>
                <h1>Access Blocked</h1>
                <p class="subtitle">
                    SpectrusGuard has detected potentially malicious activity in your request
                    and blocked it to protect this website.
                </p>

                <div class="details">
                    <p>
                        If you believe this is an error, please contact the website administrator
                        and provide the incident ID below. This helps us investigate and resolve
                        any false positives.
                    </p>
                </div>

                <div class="incident-box">
                    Incident ID:
                    <?php echo esc_html($incident_id); ?><br>
                    Threat Type:
                    <?php echo esc_html(strtoupper($type)); ?>
                </div>

                <a href="javascript:history.back()" class="back-btn">← Return to Safety</a>
            </div>
        </body>

        </html>
        <?php
    }
}

// Initialize the MU Guard
new SpectrusGuard_MU_Guard();
