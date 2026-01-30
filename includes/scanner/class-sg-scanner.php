<?php
/**
 * SpectrusGuard Scanner - Main Orchestrator
 *
 * Coordinates all scanning operations: core integrity, heuristics, and malware detection.
 * Uses transients for caching results and supports batch processing.
 *
 * @package SpectrusGuard
 * @since   3.0.0
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
     * Maximum files per directory to scan
     *
     * @var int
     */
    const MAX_FILES_PER_DIR = 5000;

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
     * Whitelist instance
     *
     * @var SG_Whitelist|null
     */
    private $whitelist;

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
     * Transient key for scan progress
     *
     * @var string
     */
    const PROGRESS_TRANSIENT = 'spectrus_shield_scan_progress';

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

        // Initialize whitelist if class exists
        if (class_exists('SG_Whitelist')) {
            $this->whitelist = new SG_Whitelist();
        }
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

        // Initialize progress tracking
        $this->update_progress(0, __('Initializing scanner...', 'spectrus-guard'));

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

        // Run all scans with progress updates
        $this->update_progress(5, __('Starting security scan...', 'spectrus-guard'));
        $this->scan_core_integrity();

        $this->update_progress(30, __('Checking uploads directory...', 'spectrus-guard'));
        $this->scan_uploads_directory();

        $this->update_progress(55, __('Analyzing suspicious files...', 'spectrus-guard'));
        $this->scan_suspicious_files();

        $this->update_progress(80, __('Scanning for malware signatures...', 'spectrus-guard'));
        $this->scan_for_malware();

        // Calculate totals
        $this->update_progress(95, __('Calculating summary...', 'spectrus-guard'));
        $this->calculate_summary();

        // Record duration
        $this->update_progress(98, __('Finalizing scan...', 'spectrus-guard'));
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
        $this->update_progress(8, __('Fetching WordPress core checksums...', 'spectrus-guard'));
        $modified_files = $this->checksum->verify_core_files();

        $this->update_progress(15, sprintf(__('Verifying %d core files...', 'spectrus-guard'), count($modified_files)));
        $checked = 0;
        foreach ($modified_files as $file) {
            $checked++;
            if ($checked % 10 === 0) {
                $this->update_progress(15 + min(10, ($checked / count($modified_files)) * 10), sprintf(__('Checking core files... (%d/%d)', 'spectrus-guard'), $checked, count($modified_files)));
            }

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
        $this->update_progress(32, __('Scanning uploads directory for PHP files...', 'spectrus-guard'));
        $php_files = $this->heuristics->scan_uploads_for_php();

        $this->update_progress(40, sprintf(__('Found %d PHP files in uploads', 'spectrus-guard'), count($php_files)));
        $checked = 0;
        foreach ($php_files as $file) {
            $checked++;
            if ($checked % 5 === 0) {
                $this->update_progress(40 + min(10, ($checked / max(1, count($php_files))) * 10), sprintf(__('Analyzing uploads... (%d/%d)', 'spectrus-guard'), $checked, count($php_files)));
            }

            // Check if file is whitelisted
            $file_hash = file_exists($file) ? hash_file('sha256', $file) : null;
            if ($this->whitelist && $this->whitelist->check($file, $file_hash)) {
                // Skip whitelisted files
                continue;
            }

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
        $this->update_progress(58, __('Scanning for hidden files...', 'spectrus-guard'));
        $hidden_files = $this->heuristics->scan_hidden_files();
        $this->update_progress(62, sprintf(__('Found %d hidden files', 'spectrus-guard'), count($hidden_files)));

        $checked = 0;
        foreach ($hidden_files as $file) {
            $checked++;
            if ($checked % 10 === 0) {
                $this->update_progress(62 + min(5, ($checked / max(1, count($hidden_files))) * 5), sprintf(__('Checking hidden files... (%d/%d)', 'spectrus-guard'), $checked, count($hidden_files)));
            }

            $this->results['suspicious'][] = array(
                'file' => $file,
                'type' => 'hidden',
                'severity' => self::SEVERITY_MEDIUM,
                'message' => __('Hidden file detected', 'spectrus-guard'),
            );
        }

        // Dangerous permissions
        $this->update_progress(68, __('Checking file permissions...', 'spectrus-guard'));
        $perm_issues = $this->heuristics->scan_dangerous_permissions();
        $this->update_progress(72, sprintf(__('Found %d files with dangerous permissions', 'spectrus-guard'), count($perm_issues)));

        $checked = 0;
        foreach ($perm_issues as $file) {
            $checked++;
            if ($checked % 10 === 0) {
                $this->update_progress(72 + min(5, ($checked / max(1, count($perm_issues))) * 5), sprintf(__('Checking permissions... (%d/%d)', 'spectrus-guard'), $checked, count($perm_issues)));
            }

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
        $this->update_progress(82, __('Loading malware signatures database...', 'spectrus-guard'));
        $signatures = sg_get_malware_signatures();

        $directories = array(
            WP_CONTENT_DIR . '/plugins' => __('plugins', 'spectrus-guard'),
            WP_CONTENT_DIR . '/themes' => __('themes', 'spectrus-guard'),
            WP_CONTENT_DIR . '/uploads' => __('uploads', 'spectrus-guard'),
        );

        $plugin_dir = $this->get_plugin_dir();
        $total_dirs = count($directories);
        $current_dir = 0;

        foreach ($directories as $dir => $dir_name) {
            $current_dir++;
            $this->update_progress(82 + (($current_dir - 1) * 5), sprintf(__('Scanning %s directory for malware...', 'spectrus-guard'), $dir_name));

            if (!is_dir($dir)) {
                continue;
            }

            $matches = $this->heuristics->scan_for_signatures($dir, $signatures);

            $this->update_progress(82 + (($current_dir - 1) * 5) + 2, sprintf(__('Found %d potential malware patterns in %s', 'spectrus-guard'), count($matches), $dir_name));

            $checked = 0;
            foreach ($matches as $match) {
                $checked++;
                if ($checked % 5 === 0) {
                    $this->update_progress(82 + (($current_dir - 1) * 5) + 2 + min(3, ($checked / max(1, count($matches))) * 3), sprintf(__('Analyzing patterns... (%d/%d)', 'spectrus-guard'), $checked, count($matches)));
                }

                // Skip files in this plugin's directory (self-exclusion)
                $full_path = ABSPATH . ltrim($match['file'], '/');
                if ($this->is_plugin_file($full_path)) {
                    continue;
                }

                // Check if file is whitelisted
                $file_hash = file_exists($full_path) ? hash_file('sha256', $full_path) : null;
                if ($this->whitelist && $this->whitelist->check($full_path, $file_hash)) {
                    // Skip whitelisted files
                    continue;
                }

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
     * Update scan progress
     *
     * @param int    $percentage Progress percentage (0-100).
     * @param string $message    Current activity message.
     */
    private function update_progress($percentage, $message)
    {
        set_transient(self::PROGRESS_TRANSIENT, array(
            'percentage' => min(100, max(0, $percentage)),
            'message' => $message,
            'timestamp' => current_time('mysql'),
        ), 300); // 5 minutes expiration
    }

    /**
     * Clear progress tracking
     */
    public function clear_progress()
    {
        delete_transient(self::PROGRESS_TRANSIENT);
    }

    /**
     * Get current progress
     *
     * @return array|null Progress data or null.
     */
    public function get_progress()
    {
        return get_transient(self::PROGRESS_TRANSIENT);
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
     * Get plugin directory path for exclusion
     *
     * @return string Plugin directory path.
     */
    private function get_plugin_dir()
    {
        return trailingslashit(SG_PLUGIN_DIR);
    }

    /**
     * Check if file is in plugin directory
     *
     * @param string $file_path File path to check.
     * @return bool True if file is in plugin directory.
     */
    private function is_plugin_file($file_path)
    {
        $plugin_dir = $this->get_plugin_dir();

        // Check if file path starts with plugin directory
        return strpos($file_path, $plugin_dir) === 0;
    }

    /**
     * Get all PHP files in WordPress installation
     *
     * @return array Array of PHP file paths.
     */
    private function get_all_php_files()
    {
        $php_files = array();
        $directories = array(
            ABSPATH . 'wp-content/plugins/',
            ABSPATH . 'wp-content/themes/',
            ABSPATH . 'wp-content/mu-plugins/',
            ABSPATH . 'wp-content/uploads/',
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $php_files = array_merge($php_files, $this->scan_directory_for_php($dir));
        }

        return $php_files;
    }

    /**
     * Scan a directory recursively for PHP files
     *
     * @param string $directory Directory to scan.
     * @return array Array of PHP file paths.
     */
    private function scan_directory_for_php($directory)
    {
        $php_files = array();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        $count = 0;
        foreach ($iterator as $file) {
            if (++$count > self::MAX_FILES_PER_DIR) {
                break;
            }

            if (!$file->isFile()) {
                continue;
            }

            $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));

            // Solo archivos PHP y variantes ofuscadas
            if (!in_array($extension, array('php', 'phtml', 'php5', 'php7', 'phps'), true)) {
                continue;
            }

            $php_files[] = $file->getPathname();
        }

        return $php_files;
    }

    /**
     * Clear cached results
     *
     * @return bool True on success.
     */
    public function clear_cache()
    {
        delete_transient(self::PROGRESS_TRANSIENT);
        return delete_transient(self::RESULTS_TRANSIENT);
    }

    /**
     * Get cached scan results
     *
     * @return array|false Cached results or false.
     */
    private function get_cached_results()
    {
        return get_transient(self::RESULTS_TRANSIENT);
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
