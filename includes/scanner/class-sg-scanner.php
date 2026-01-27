<?php
/**
 * SpectrusGuard Scanner - Main Orchestrator
 *
 * Coordinates all scanning operations: core integrity, heuristics, and malware detection.
 * Uses transients for caching results and supports batch processing.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Scanner
 *
 * Main scanner orchestrator that coordinates all security scans.
 */
class SG_Scanner
{

    /**
     * Checksum scanner instance
     *
     * @var SG_Checksum
     */
    private $checksum;

    /**
     * Heuristics scanner instance
     *
     * @var SG_Heuristics
     */
    private $heuristics;

    /**
     * Scan results
     *
     * @var array
     */
    private $results = array();

    /**
     * Transient key for cached results
     *
     * @var string
     */
    const RESULTS_TRANSIENT = 'spectrus_shield_scan_results';

    /**
     * Transient expiration (24 hours)
     *
     * @var int
     */
    const CACHE_EXPIRATION = DAY_IN_SECONDS;

    /**
     * Severity levels
     */
    const SEVERITY_CRITICAL = 'critical';
    const SEVERITY_HIGH = 'high';
    const SEVERITY_MEDIUM = 'medium';
    const SEVERITY_LOW = 'low';
    const SEVERITY_INFO = 'info';

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->load_dependencies();
    }

    /**
     * Load scanner dependencies
     */
    private function load_dependencies()
    {
        require_once SG_PLUGIN_DIR . 'includes/scanner/class-sg-checksum.php';
        require_once SG_PLUGIN_DIR . 'includes/scanner/class-sg-heuristics.php';
        require_once SG_PLUGIN_DIR . 'includes/scanner/signatures.php';

        $this->checksum = new SG_Checksum();
        $this->heuristics = new SG_Heuristics();
    }

    /**
     * Run a full security scan
     *
     * @param bool $force_fresh Force fresh scan, ignore cache.
     * @return array Scan results.
     */
    public function run_full_scan($force_fresh = false)
    {
        // Check for cached results
        if (!$force_fresh) {
            $cached = get_transient(self::RESULTS_TRANSIENT);
            if (false !== $cached) {
                return $cached;
            }
        }

        $start_time = microtime(true);

        $this->results = array(
            'scan_time' => current_time('mysql'),
            'duration' => 0,
            'summary' => array(
                'total_issues' => 0,
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0,
            ),
            'core_integrity' => array(),
            'uploads_php' => array(),
            'suspicious' => array(),
            'malware' => array(),
        );

        // Run all scans
        $this->scan_core_integrity();
        $this->scan_uploads_directory();
        $this->scan_suspicious_files();
        $this->scan_for_malware();

        // Calculate totals
        $this->calculate_summary();

        // Record duration
        $this->results['duration'] = round(microtime(true) - $start_time, 2);

        // Cache results
        set_transient(self::RESULTS_TRANSIENT, $this->results, self::CACHE_EXPIRATION);

        // Update last scan time option
        update_option('spectrus_shield_last_scan', current_time('mysql'));

        return $this->results;
    }

    /**
     * Scan core WordPress files for modifications
     */
    private function scan_core_integrity()
    {
        $modified_files = $this->checksum->verify_core_files();

        foreach ($modified_files as $file) {
            $this->results['core_integrity'][] = array(
                'file' => $file['file'],
                'status' => $file['status'], // 'modified', 'missing', 'unknown'
                'severity' => $this->get_core_file_severity($file),
                'message' => $this->get_core_file_message($file),
            );
        }
    }

    /**
     * Scan uploads directory for PHP files
     */
    private function scan_uploads_directory()
    {
        $php_files = $this->heuristics->scan_uploads_for_php();

        foreach ($php_files as $file) {
            $this->results['uploads_php'][] = array(
                'file' => $file,
                'severity' => self::SEVERITY_CRITICAL,
                'message' => __('PHP file found in uploads directory - potential backdoor', 'spectrus-guard'),
            );
        }
    }

    /**
     * Scan for suspicious files and permissions
     */
    private function scan_suspicious_files()
    {
        // Hidden files
        $hidden_files = $this->heuristics->scan_hidden_files();
        foreach ($hidden_files as $file) {
            $this->results['suspicious'][] = array(
                'file' => $file,
                'type' => 'hidden',
                'severity' => self::SEVERITY_MEDIUM,
                'message' => __('Hidden file detected', 'spectrus-guard'),
            );
        }

        // Dangerous permissions
        $perm_issues = $this->heuristics->scan_dangerous_permissions();
        foreach ($perm_issues as $file) {
            $this->results['suspicious'][] = array(
                'file' => $file['file'],
                'type' => 'permissions',
                'severity' => self::SEVERITY_HIGH,
                'message' => sprintf(
                    /* translators: %s: file permissions */
                    __('Dangerous permissions: %s', 'spectrus-guard'),
                    $file['permissions']
                ),
            );
        }
    }

    /**
     * Scan for known malware signatures
     */
    private function scan_for_malware()
    {
        $signatures = sg_get_malware_signatures();
        $directories = array(
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads',
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $matches = $this->heuristics->scan_for_signatures($dir, $signatures);

            foreach ($matches as $match) {
                $this->results['malware'][] = array(
                    'file' => $match['file'],
                    'signature' => $match['signature'],
                    'line' => $match['line'],
                    'severity' => self::SEVERITY_CRITICAL,
                    'message' => sprintf(
                        /* translators: %s: malware signature name */
                        __('Malware signature detected: %s', 'spectrus-guard'),
                        $match['signature']
                    ),
                );
            }
        }
    }

    /**
     * Calculate summary totals
     */
    private function calculate_summary()
    {
        $all_issues = array_merge(
            $this->results['core_integrity'],
            $this->results['uploads_php'],
            $this->results['suspicious'],
            $this->results['malware']
        );

        foreach ($all_issues as $issue) {
            $this->results['summary']['total_issues']++;

            $severity = $issue['severity'] ?? self::SEVERITY_LOW;
            if (isset($this->results['summary'][$severity])) {
                $this->results['summary'][$severity]++;
            }
        }
    }

    /**
     * Get severity for core file issue
     *
     * @param array $file File data.
     * @return string Severity level.
     */
    private function get_core_file_severity($file)
    {
        // Critical files
        $critical_patterns = array(
            'wp-config.php',
            'wp-includes/version.php',
            'wp-includes/class-wp.php',
            'wp-admin/includes/file.php',
        );

        foreach ($critical_patterns as $pattern) {
            if (strpos($file['file'], $pattern) !== false) {
                return self::SEVERITY_CRITICAL;
            }
        }

        if ($file['status'] === 'modified') {
            return self::SEVERITY_HIGH;
        }

        return self::SEVERITY_MEDIUM;
    }

    /**
     * Get message for core file issue
     *
     * @param array $file File data.
     * @return string Message.
     */
    private function get_core_file_message($file)
    {
        switch ($file['status']) {
            case 'modified':
                return __('Core file has been modified from original', 'spectrus-guard');
            case 'missing':
                return __('Core file is missing', 'spectrus-guard');
            case 'unknown':
                return __('Unknown file in WordPress core directory', 'spectrus-guard');
            default:
                return __('File integrity issue detected', 'spectrus-guard');
        }
    }

    /**
     * Get cached scan results
     *
     * @return array|false Results or false if no cache.
     */
    public function get_cached_results()
    {
        return get_transient(self::RESULTS_TRANSIENT);
    }

    /**
     * Clear cached results
     *
     * @return bool True on success.
     */
    public function clear_cache()
    {
        return delete_transient(self::RESULTS_TRANSIENT);
    }

    /**
     * Get last scan time
     *
     * @return string|null Last scan time or null.
     */
    public function get_last_scan_time()
    {
        return get_option('spectrus_shield_last_scan', null);
    }

    /**
     * Check if a fresh scan is needed
     *
     * @return bool True if scan is older than cache expiration.
     */
    public function needs_fresh_scan()
    {
        $last_scan = $this->get_last_scan_time();

        if (!$last_scan) {
            return true;
        }

        $last_scan_time = strtotime($last_scan);
        return (time() - $last_scan_time) > self::CACHE_EXPIRATION;
    }

    /**
     * Schedule automatic scans
     */
    public function schedule_daily_scan()
    {
        if (!wp_next_scheduled('spectrus_shield_daily_scan')) {
            wp_schedule_event(time(), 'daily', 'spectrus_shield_daily_scan');
        }
    }

    /**
     * Unschedule automatic scans
     */
    public function unschedule_scans()
    {
        wp_clear_scheduled_hook('spectrus_shield_daily_scan');
    }

    /**
     * Get results formatted for display
     *
     * @return array Formatted results.
     */
    public function get_display_results()
    {
        $results = $this->get_cached_results();

        if (!$results) {
            return array(
                'has_results' => false,
                'message' => __('No scan results available. Run a scan to check your site.', 'spectrus-guard'),
            );
        }

        return array(
            'has_results' => true,
            'scan_time' => $results['scan_time'],
            'duration' => $results['duration'],
            'summary' => $results['summary'],
            'issues' => $this->flatten_issues($results),
        );
    }

    /**
     * Flatten all issues into a single array for display
     *
     * @param array $results Scan results.
     * @return array Flattened issues.
     */
    private function flatten_issues($results)
    {
        $issues = array();

        // Core integrity
        foreach ($results['core_integrity'] as $issue) {
            $issue['category'] = 'core';
            $issues[] = $issue;
        }

        // Uploads PHP
        foreach ($results['uploads_php'] as $issue) {
            $issue['category'] = 'uploads';
            $issues[] = $issue;
        }

        // Suspicious
        foreach ($results['suspicious'] as $issue) {
            $issue['category'] = 'suspicious';
            $issues[] = $issue;
        }

        // Malware
        foreach ($results['malware'] as $issue) {
            $issue['category'] = 'malware';
            $issues[] = $issue;
        }

        // Sort by severity
        usort($issues, function ($a, $b) {
            $order = array(
                self::SEVERITY_CRITICAL => 0,
                self::SEVERITY_HIGH => 1,
                self::SEVERITY_MEDIUM => 2,
                self::SEVERITY_LOW => 3,
                self::SEVERITY_INFO => 4,
            );
            return ($order[$a['severity']] ?? 5) - ($order[$b['severity']] ?? 5);
        });

        return $issues;
    }
}
