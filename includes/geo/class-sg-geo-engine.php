<?php
/**
 * SpectrusGuard Geo Engine
 *
 * Main geo-intelligence engine for country-based blocking.
 *
 * @package SpectrusGuard
 * @since   1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Geo_Engine
 *
 * Handles geo-blocking logic and IP intelligence.
 */
class SG_Geo_Engine
{
    /**
     * Path to MaxMind database
     *
     * @var string
     */
    private $db_path;

    /**
     * Path to Tor exit nodes list
     *
     * @var string
     */
    private $tor_db_path;

    /**
     * MaxMind reader instance
     *
     * @var SG_MaxMind_Reader|null
     */
    private $reader = null;

    /**
     * Cached Tor nodes
     *
     * @var array|null
     */
    private $tor_nodes = null;

    /**
     * Constructor
     */
    public function __construct()
    {
        $upload_dir = wp_upload_dir();
        $base_dir = $upload_dir['basedir'] . '/spectrus-guard/geoip';

        $this->db_path = $base_dir . '/GeoLite2-Country.mmdb';
        $this->tor_db_path = $base_dir . '/tor-exit-nodes.json';

        // Initialize reader if database exists
        if (file_exists($this->db_path)) {
            $this->initReader();
        }
    }

    /**
     * Initialize the MaxMind reader
     */
    private function initReader()
    {
        if ($this->reader !== null) {
            return;
        }

        try {
            require_once SG_PLUGIN_DIR . 'includes/geo/class-sg-maxmind-reader.php';
            $this->reader = new SG_MaxMind_Reader($this->db_path);
        } catch (Exception $e) {
            // Log error but don't crash
            if (class_exists('SG_Logger')) {
                $logger = new SG_Logger();
                $logger->log_debug('Geo Engine: Failed to load MaxMind DB - ' . $e->getMessage(), 'error');
            }
            $this->reader = null;
        }
    }

    /**
     * Get the ISO country code for an IP address
     *
     * @param string $ip IP address.
     * @return string|false Country ISO code or false on failure.
     */
    public function get_country_iso($ip)
    {
        if ($this->reader === null) {
            return false; // Fail-open: No DB means no blocking
        }

        // Validate IP
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Skip private/reserved IPs
        if ($this->is_private_ip($ip)) {
            return false;
        }

        try {
            $code = $this->reader->getCountryCode($ip);
            return $code ?: false;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Check if an IP is a private/reserved address
     *
     * @param string $ip IP address.
     * @return bool True if private/reserved.
     */
    private function is_private_ip($ip)
    {
        return !filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Determine if a request should be blocked based on geo rules
     *
     * @param string $ip IP address.
     * @return array|false Block info array or false if allowed.
     */
    public function should_block($ip)
    {
        // 1. Check IP whitelist first (always pass)
        if ($this->is_whitelisted($ip)) {
            return false;
        }

        // 2. Check Tor nodes (if enabled)
        $settings = $this->get_settings();
        if (!empty($settings['geo_block_tor']) && $this->is_tor_node($ip)) {
            $this->log_geo_block($ip, 'TOR', 'Tor Exit Node');
            return array(
                'blocked' => true,
                'reason' => 'tor_exit_node',
                'code' => 'TOR',
                'message' => __('Access denied: Tor exit node detected', 'spectrus-guard'),
            );
        }

        // 3. Get country code
        $country_code = $this->get_country_iso($ip);
        if (!$country_code) {
            return false; // Can't determine country, fail-open
        }

        // 4. Check against blocked countries
        $blocked_countries = isset($settings['geo_blocked_countries'])
            ? (array) $settings['geo_blocked_countries']
            : array();

        if (in_array($country_code, $blocked_countries, true)) {
            $this->log_geo_block($ip, $country_code, 'Country Blocked');
            return array(
                'blocked' => true,
                'reason' => 'country_blocked',
                'code' => $country_code,
                'message' => sprintf(
                    /* translators: %s: country code */
                    __('Access denied from your location (%s)', 'spectrus-guard'),
                    $country_code
                ),
            );
        }

        return false;
    }

    /**
     * Check if an IP is in the whitelist
     *
     * @param string $ip IP address.
     * @return bool True if whitelisted.
     */
    private function is_whitelisted($ip)
    {
        $settings = $this->get_settings();
        $whitelist = isset($settings['whitelist_ips'])
            ? (array) $settings['whitelist_ips']
            : array();

        return in_array($ip, $whitelist, true);
    }

    /**
     * Check if an IP is a Tor exit node
     *
     * @param string $ip IP address.
     * @return bool True if Tor node.
     */
    public function is_tor_node($ip)
    {
        $nodes = $this->get_tor_nodes();
        if (empty($nodes)) {
            return false;
        }

        return in_array($ip, $nodes, true);
    }

    /**
     * Get cached Tor exit nodes
     *
     * @return array List of Tor exit node IPs.
     */
    private function get_tor_nodes()
    {
        if ($this->tor_nodes !== null) {
            return $this->tor_nodes;
        }

        // Try transient first (Fastest, Memory/DB)
        $cached = get_transient('spectrus_tor_nodes');
        if ($cached !== false && is_array($cached)) {
            $this->tor_nodes = $cached;
            return $this->tor_nodes;
        }

        // Fallback to JSON file
        if (file_exists($this->tor_db_path)) {
            $content = file_get_contents($this->tor_db_path);
            if ($content !== false) {
                $nodes = json_decode($content, true);
                if (is_array($nodes)) {
                    $this->tor_nodes = $nodes;
                    // Populate transient for next time
                    set_transient('spectrus_tor_nodes', $nodes, 86400); // 24 hours
                    return $this->tor_nodes;
                }
            }
        }

        $this->tor_nodes = array();
        return $this->tor_nodes;
    }

    /**
     * Update Tor exit nodes list from official source
     *
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    public function update_tor_nodes()
    {
        $url = 'https://check.torproject.org/torbulkexitlist';

        $response = wp_remote_get($url, array(
            'timeout' => 30,
            'sslverify' => true,
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        if (empty($body)) {
            return new WP_Error('empty_response', __('Empty response from Tor Project', 'spectrus-guard'));
        }

        // Parse IPs (one per line)
        $lines = explode("\n", $body);
        $ips = array();

        foreach ($lines as $line) {
            $line = trim($line);
            if (!empty($line) && filter_var($line, FILTER_VALIDATE_IP)) {
                $ips[] = $line;
            }
        }

        if (empty($ips)) {
            return new WP_Error('no_ips', __('No valid IPs found in Tor list', 'spectrus-guard'));
        }

        // Ensure directory exists
        $dir = dirname($this->tor_db_path);
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }

        // Save to JSON file (Persistent storage)
        $saved = file_put_contents($this->tor_db_path, json_encode($ips));
        if ($saved === false) {
            return new WP_Error('save_failed', __('Failed to save Tor nodes list', 'spectrus-guard'));
        }

        // Update transient (Cache)
        set_transient('spectrus_tor_nodes', $ips, 86400); // 24 hours

        // Update last update time
        update_option('sg_last_tor_update', time());

        // Clear cache
        $this->tor_nodes = null;

        return true;
    }

    /**
     * Get plugin settings
     *
     * @return array Settings.
     */
    private function get_settings()
    {
        static $settings = null;
        if ($settings === null) {
            $settings = get_option('spectrus_shield_settings', array());
        }
        return $settings;
    }

    /**
     * Log a geo-block event
     *
     * @param string $ip      IP address.
     * @param string $code    Country code or TOR.
     * @param string $reason  Reason for block.
     */
    private function log_geo_block($ip, $code, $reason)
    {
        $log_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
        $log_file = $log_dir . '/geo-blocks.log';

        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
            file_put_contents($log_dir . '/.htaccess', "Order deny,allow\nDeny from all");
        }

        $timestamp = current_time('Y-m-d H:i:s');
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field($_SERVER['REQUEST_URI']) : '';

        $log_line = sprintf(
            "[%s] [GEO:%s] IP: %s | URI: %s | Reason: %s\n",
            $timestamp,
            $code,
            $ip,
            $uri,
            $reason
        );

        file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);

        // Update stats
        $this->update_geo_stats($code);
    }

    /**
     * Update geo-blocking statistics
     *
     * @param string $code Country code.
     */
    private function update_geo_stats($code)
    {
        $stats = get_option('sg_geo_stats', array(
            'total_blocked' => 0,
            'by_country' => array(),
            'last_block' => null,
        ));

        $stats['total_blocked']++;
        $stats['last_block'] = current_time('mysql');

        if (!isset($stats['by_country'][$code])) {
            $stats['by_country'][$code] = 0;
        }
        $stats['by_country'][$code]++;

        update_option('sg_geo_stats', $stats);
    }

    /**
     * Check if the MaxMind database is installed
     *
     * @return bool True if installed.
     */
    public function is_database_installed()
    {
        return file_exists($this->db_path);
    }

    /**
     * Check if database is available (Alias for is_database_installed)
     *
     * Fixes crash in MU-Plugin which calls this method.
     *
     * @return bool
     */
    public function is_database_available()
    {
        return $this->is_database_installed();
    }

    /**
     * Get database info
     *
     * @return array Database info.
     */
    public function get_database_info()
    {
        $info = array(
            'installed' => $this->is_database_installed(),
            'path' => $this->db_path,
            'size' => 0,
            'modified' => null,
            'tor_nodes_count' => 0,
            'last_tor_update' => get_option('sg_last_tor_update', null),
        );

        if ($info['installed']) {
            $info['size'] = filesize($this->db_path);
            $info['modified'] = filemtime($this->db_path);
        }

        // Check file for count (or could check transient)
        if (file_exists($this->tor_db_path)) {
            $nodes = $this->get_tor_nodes();
            $info['tor_nodes_count'] = count($nodes);
        }

        return $info;
    }

    /**
     * Get the path where the database should be stored
     *
     * @return string Path.
     */
    public function get_database_path()
    {
        return $this->db_path;
    }

    /**
     * Get geo-blocking statistics
     *
     * @return array Statistics.
     */
    public function get_stats()
    {
        return get_option('sg_geo_stats', array(
            'total_blocked' => 0,
            'by_country' => array(),
            'last_block' => null,
        ));
    }
}
