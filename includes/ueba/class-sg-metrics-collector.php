<?php
/**
 * SpectrusGuard Metrics Collector
 *
 * Collects metrics for User and Entity Behavior Analytics.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Metrics_Collector
 *
 * Collects various metrics for behavior analysis.
 */
class SG_Metrics_Collector
{

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Constructor
     *
     * @param SG_Logger $logger Logger instance.
     */
    public function __construct(SG_Logger $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Collect login metrics for a user
     *
     * @param WP_User $user User object.
     * @return array Login metrics.
     */
    public function collect_login_metrics($user)
    {
        $metrics = array(
            'event_type' => 'login',
            'user_id' => $user->ID,
            'user_login' => $user->user_login,
            'user_role' => $this->get_user_primary_role($user->ID),
            'ip' => $this->get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'device_fingerprint' => $this->get_device_fingerprint(),
            'timestamp' => time(),
            'hour' => (int) date('H'),
            'day_of_week' => (int) date('w'), // 0 = Sunday, 6 = Saturday
            'success' => true,
        );

        // Add geo location if available
        if (class_exists('SG_Geo_Engine')) {
            $geo_engine = new SG_Geo_Engine();
            $country = $geo_engine->get_country_iso($metrics['ip']);
            if ($country) {
                $metrics['country'] = $country;
            }
        }

        // Add IP reputation
        $metrics['is_tor'] = $this->is_tor_exit_node($metrics['ip']);
        $metrics['is_vpn'] = $this->is_vpn($metrics['ip']);

        return $metrics;
    }

    /**
     * Collect request metrics
     *
     * @param int $user_id User ID.
     * @return array Request metrics.
     */
    public function collect_request_metrics($user_id)
    {
        $metrics = array(
            'event_type' => 'request',
            'user_id' => $user_id,
            'ip' => $this->get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field($_SERVER['HTTP_USER_AGENT']) : '',
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? esc_url_raw($_SERVER['REQUEST_URI']) : '',
            'request_method' => isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field($_SERVER['REQUEST_METHOD']) : 'GET',
            'timestamp' => time(),
            'hour' => (int) date('H'),
            'day_of_week' => (int) date('w'),
        );

        return $metrics;
    }

    /**
     * Get user's primary role
     *
     * @param int $user_id User ID.
     * @return string Primary role.
     */
    private function get_user_primary_role($user_id)
    {
        $user = get_userdata($user_id);
        if (!$user) {
            return 'subscriber';
        }

        $roles = $user->roles;
        return !empty($roles) ? $roles[0] : 'subscriber';
    }

    /**
     * Get client IP address
     *
     * @return string IP address.
     */
    public function get_client_ip()
    {
        // Only trust X-Forwarded-For if behind trusted proxy
        $trusted_proxies = $this->get_trusted_proxies();

        $ip = isset($_SERVER['REMOTE_ADDR']) ? filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP) : '0.0.0.0';

        // Check if we're behind a trusted proxy
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && in_array($ip, $trusted_proxies, true)) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        }

        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    /**
     * Get trusted proxy IPs
     *
     * @return array Trusted proxy IPs.
     */
    private function get_trusted_proxies()
    {
        $settings = get_option('spectrus_shield_settings', array());
        $proxies = isset($settings['trusted_proxies']) ? (array) $settings['trusted_proxies'] : array();

        // Default to localhost
        $proxies[] = '127.0.0.1';
        $proxies[] = '::1';

        return $proxies;
    }

    /**
     * Generate device fingerprint
     *
     * @return string Device fingerprint hash.
     */
    private function get_device_fingerprint()
    {
        $components = array(
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        );

        return md5(implode('|', $components));
    }

    /**
     * Check if IP is a Tor exit node
     *
     * @param string $ip IP address.
     * @return bool True if Tor exit node.
     */
    private function is_tor_exit_node($ip)
    {
        if (!class_exists('SG_Geo_Engine')) {
            return false;
        }

        $geo_engine = new SG_Geo_Engine();
        return $geo_engine->is_tor_exit_node($ip);
    }

    /**
     * Check if IP is a VPN (basic heuristic)
     *
     * @param string $ip IP address.
     * @return bool True if likely VPN.
     */
    private function is_vpn($ip)
    {
        // This is a simplified check. In production, use a VPN detection API
        // For now, we'll check if it's a known datacenter IP range

        $settings = get_option('spectrus_shield_settings', array());
        $known_vpn_ranges = isset($settings['known_vpn_ranges'])
            ? (array) $settings['known_vpn_ranges']
            : array();

        foreach ($known_vpn_ranges as $range) {
            if ($this->ip_in_range($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is in a CIDR range
     *
     * @param string $ip    IP address.
     * @param string $range CIDR range (e.g., "192.168.1.0/24").
     * @return bool True if IP is in range.
     */
    private function ip_in_range($ip, $range)
    {
        list($range, $netmask) = explode('/', $range, 2);

        $range_decimal = ip2long($range);
        $ip_decimal = ip2long($ip);
        $wildcard_decimal = pow(2, (32 - $netmask)) - 1;
        $netmask_decimal = ~$wildcard_decimal;

        return ($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal);
    }

    /**
     * Get recent failed login attempts for IP
     *
     * @param string $ip IP address.
     * @param int    $hours Hours to look back.
     * @return int Number of failed attempts.
     */
    public function get_failed_login_attempts($ip, $hours = 1)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';
        $cutoff = date('Y-m-d H:i:s', strtotime("-{$hours} hours"));

        $count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE event_type = 'login_failed'
                 AND ip = %s
                 AND timestamp > %s",
                $ip,
                $cutoff
            )
        );

        return (int) $count;
    }

    /**
     * Get successful login history for user
     *
     * @param int $user_id User ID.
     * @param int $limit   Limit.
     * @return array Login history.
     */
    public function get_login_history($user_id, $limit = 10)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table_name}
                 WHERE event_type = 'login'
                 AND user_id = %d
                 ORDER BY timestamp DESC
                 LIMIT %d",
                $user_id,
                $limit
            ),
            ARRAY_A
        );

        return $results ?: array();
    }

    /**
     * Get request rate for user (requests per minute)
     *
     * @param int $user_id User ID.
     * @param int $minutes Minutes to look back.
     * @return float Requests per minute.
     */
    public function get_request_rate($user_id, $minutes = 1)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';
        $cutoff = date('Y-m-d H:i:s', strtotime("-{$minutes} minutes"));

        $count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE event_type = 'request'
                 AND user_id = %d
                 AND timestamp > %s",
                $user_id,
                $cutoff
            )
        );

        return (int) $count / $minutes;
    }
}
