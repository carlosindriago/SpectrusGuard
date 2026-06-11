<?php
/**
 * Page Controller: Security Scanner
 *
 * Handles the scanner page functionality including running scans,
 * displaying results, and managing threats.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Scanner
{
    /**
     * @var SG_Loader Plugin loader instance
     */
    private $loader;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Plugin loader instance
     */
    public function __construct($loader)
    {
        $this->loader = $loader;
        $this->register_ajax_handlers();
    }

    /**
     * Register AJAX handlers
     */
    private function register_ajax_handlers()
    {
        add_action('wp_ajax_sg_get_scan_results', array($this, 'ajax_get_scan_results'));
        add_action('wp_ajax_sg_get_scan_progress', array($this, 'ajax_get_scan_progress'));
        add_action('wp_ajax_sg_delete_threat', array($this, 'ajax_delete_threat'));
        add_action('wp_ajax_sg_quarantine_threat', array($this, 'ajax_quarantine_threat'));
        add_action('wp_ajax_sg_list_quarantine', array($this, 'ajax_list_quarantine'));
        add_action('wp_ajax_sg_restore_quarantine', array($this, 'ajax_restore_quarantine'));
        add_action('wp_ajax_sg_delete_quarantine', array($this, 'ajax_delete_quarantine'));
        add_action('wp_ajax_sg_whitelist_file', array($this, 'ajax_whitelist_file'));
        add_action('wp_ajax_sg_remove_whitelist', array($this, 'ajax_remove_whitelist'));
        add_action('wp_ajax_sg_list_whitelist', array($this, 'ajax_list_whitelist'));
    }

    /**
     * Render the scanner page
     *
     * Loads the scanner view template with scan results data.
     */
    public function render()
    {
        $scanner = $this->loader->get_scanner();
        $saved = $scanner && method_exists($scanner, 'get_scan_results') ? $scanner->get_scan_results() : array();
        $suppressed_hashes = $scanner && method_exists($scanner, 'get_suppressed_hashes') ? $scanner->get_suppressed_hashes() : array();

        $saved_threats = isset($saved['threats']) && is_array($saved['threats']) ? $saved['threats'] : array();
        $prepared_threats = $this->prepare_threats_for_display($saved_threats, $suppressed_hashes);

        $data = array(
            'scan' => $saved,
            'threats' => $prepared_threats,
            'suppressed_hashes' => $suppressed_hashes,
        );

        // Load view template
        $this->render_view('scanner/page.php', $data);
    }

    /**
     * AJAX: Get latest scan results and suppressed hashes.
     *
     * @return void
     */
    public function ajax_get_scan_results(): void
    {
        check_ajax_referer('sg_run_scan_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')), 403);
        }

        $scanner = $this->loader->get_scanner();
        if (!$scanner || !method_exists($scanner, 'get_scan_results')) {
            wp_send_json_error(array('message' => __('Scanner not available.', 'spectrus-guard')));
        }

        $saved = $scanner->get_scan_results();
        $suppressed_hashes = method_exists($scanner, 'get_suppressed_hashes') ? $scanner->get_suppressed_hashes() : array();
        $saved_threats = isset($saved['threats']) && is_array($saved['threats']) ? $saved['threats'] : array();

        wp_send_json_success(array(
            'scan' => $saved,
            'threats' => $this->prepare_threats_for_display($saved_threats, $suppressed_hashes),
            'suppressed_hashes' => is_array($suppressed_hashes) ? array_values($suppressed_hashes) : array(),
        ));
    }

    /**
     * Prepare threats for safe display and sorting.
     *
     * @param array $threats Threat list.
     * @param array $suppressed_hashes Suppressed hashes.
     * @return array Prepared threats list.
     */
    private function prepare_threats_for_display(array $threats, array $suppressed_hashes): array
    {
        $suppressed_lookup = array_fill_keys(array_values($suppressed_hashes), true);
        $prepared = array();

        foreach ($threats as $threat) {
            if (!is_array($threat)) {
                continue;
            }

            $hash = $this->compute_threat_hash($threat);
            $severity = isset($threat['severity']) ? (string) $threat['severity'] : '';
            $type = isset($threat['type']) ? (string) $threat['type'] : '';

            $threat['hash'] = $hash;
            $threat['suppressed'] = isset($suppressed_lookup[$hash]);
            $threat['type_label'] = $this->threat_type_to_label($type);
            $threat['severity_weight'] = $this->get_severity_weight($severity);

            $prepared[] = $threat;
        }

        usort($prepared, array($this, 'compare_threats'));

        return $prepared;
    }

    /**
     * Compare threats for sorting (severity desc, score desc).
     *
     * @param array $a Threat A.
     * @param array $b Threat B.
     * @return int Comparison result.
     */
    private function compare_threats(array $a, array $b): int
    {
        $a_weight = isset($a['severity_weight']) ? (int) $a['severity_weight'] : 0;
        $b_weight = isset($b['severity_weight']) ? (int) $b['severity_weight'] : 0;

        if ($a_weight !== $b_weight) {
            return $b_weight <=> $a_weight;
        }

        $a_score = isset($a['score']) ? (int) $a['score'] : 0;
        $b_score = isset($b['score']) ? (int) $b['score'] : 0;

        return $b_score <=> $a_score;
    }

    /**
     * Compute deterministic threat hash (file|type|line).
     *
     * @param array $threat Threat data.
     * @return string Hash.
     */
    private function compute_threat_hash(array $threat): string
    {
        $file = isset($threat['file']) ? (string) $threat['file'] : '';
        $type = isset($threat['type']) ? (string) $threat['type'] : '';
        $line = isset($threat['line']) ? (int) $threat['line'] : 0;

        return md5($file . '|' . $type . '|' . $line);
    }

    /**
     * Convert internal threat type to a readable label.
     *
     * @param string $type Internal type.
     * @return string Readable label.
     */
    private function threat_type_to_label(string $type): string
    {
        $map = array(
            'sql_injection' => __('SQL Injection', 'spectrus-guard'),
            'csrf' => __('CSRF', 'spectrus-guard'),
            'lfi' => __('LFI', 'spectrus-guard'),
            'obfuscation' => __('Ofuscación', 'spectrus-guard'),
            'dangerous_function' => __('Dangerous Function', 'spectrus-guard'),
            'variable_function' => __('Variable Function', 'spectrus-guard'),
            'input_execution_flow' => __('Input Execution Flow', 'spectrus-guard'),
            'command_injection' => __('Command Injection', 'spectrus-guard'),
        );

        if (isset($map[$type])) {
            return $map[$type];
        }

        $label = str_replace('_', ' ', $type);
        return ucwords($label);
    }

    /**
     * Convert severity constant to a sorting weight.
     *
     * @param string $severity Severity value.
     * @return int Weight.
     */
    private function get_severity_weight(string $severity): int
    {
        $severity = strtolower($severity);

        $map = array(
            'critical' => 50,
            'high' => 40,
            'medium' => 30,
            'low' => 20,
            'info' => 10,
        );

        return isset($map[$severity]) ? (int) $map[$severity] : 0;
    }

    /**
     * Render a view template with data
     *
     * @param string $template Template file name relative to views directory
     * @param array  $data     Data to pass to the template
     */
    private function render_view($template, $data = array())
    {
        $view_file = SG_PLUGIN_DIR . 'includes/admin/views/' . $template;

        if (!file_exists($view_file)) {
            wp_die(__('View file not found: ', 'spectrus-guard') . esc_html($template));
        }

        // Extract data variables for use in template
        extract($data, EXTR_SKIP);

        // Load template
        include $view_file;
    }

    /**
     * AJAX: Run security scan
     *
     * Initiates a full security scan and returns results when complete.
     */
    public function ajax_run_scan()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get scanner instance
        $scanner = $this->loader->get_scanner();
        if (!$scanner) {
            wp_send_json_error(array('message' => __('Scanner not available.', 'spectrus-guard')));
        }

        // Check if scanner is already running to prevent duplicate scans
        $scan_lock = get_transient('spectrus_guard_scan_lock');
        if ($scan_lock) {
            wp_send_json_error(array('message' => __('A scan is already in progress. Please wait.', 'spectrus-guard')));
        }

        // Set scan lock for 5 minutes
        set_transient('spectrus_guard_scan_lock', true, 300);

        try {
            // Clear old cache first
            $scanner->clear_cache();

            // Run fresh scan (this will take time)
            $results = $scanner->run_full_scan(true);

            // Clear progress
            $scanner->clear_progress();

            // Clear scan lock
            delete_transient('spectrus_guard_scan_lock');

            wp_send_json_success(array(
                'message' => __('Scan completed successfully.', 'spectrus-guard'),
                'results' => $scanner->get_display_results(),
                'complete' => true,
            ));
        } catch (Exception $e) {
            // Clear progress on error
            $scanner->clear_progress();

            // Clear scan lock on error
            delete_transient('spectrus_guard_scan_lock');

            // Log error
            error_log('SpectrusGuard Scan Error: ' . $e->getMessage());

            wp_send_json_error(array(
                'message' => __('Scan failed: ', 'spectrus-guard') . $e->getMessage(),
                'debug' => $e->getMessage(),
            ));
        }
    }

    /**
     * AJAX: Get scan progress
     *
     * Returns the current progress of an ongoing scan.
     */
    public function ajax_get_scan_progress()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get scanner instance
        $scanner = $this->loader->get_scanner();
        if (!$scanner) {
            wp_send_json_error(array('message' => __('Scanner not available.', 'spectrus-guard')));
        }

        // Get progress data
        $progress = $scanner->get_progress();

        if ($progress) {
            wp_send_json_success($progress);
        } else {
            wp_send_json_success(array(
                'percentage' => 0,
                'message' => '',
            ));
        }
    }

    /**
     * AJAX: Delete threat file
     *
     * Deletes a file identified as a security threat.
     */
    public function ajax_delete_threat()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get and validate file path
        $file_path = isset($_POST['file_path']) ? sanitize_text_field($_POST['file_path']) : '';
        if (empty($file_path)) {
            wp_send_json_error(array('message' => __('File path is required', 'spectrus-guard')));
        }

        // Construct full path
        $full_path = ABSPATH . ltrim($file_path, '/');

        // Security check: must be within ABSPATH
        $real_path = realpath($full_path);
        $real_abspath = realpath(ABSPATH);
        if ($real_path && $real_abspath && strpos($real_path, $real_abspath) !== 0) {
            wp_send_json_error(array('message' => __('Invalid file path', 'spectrus-guard')));
        }

        // Check if file exists
        if (!file_exists($full_path)) {
            wp_send_json_error(array('message' => __('File not found', 'spectrus-guard')));
        }

        // Prevent deleting this plugin's files
        $plugin_dir = ABSPATH . 'wp-content/plugins/SpectrusGuard/';
        if (strpos($full_path, $plugin_dir) === 0) {
            wp_send_json_error(array('message' => __('Cannot delete plugin files', 'spectrus-guard')));
        }

        // Delete file
        if (unlink($full_path)) {
            wp_send_json_success(array(
                'message' => __('File deleted successfully', 'spectrus-guard'),
                'file' => $file_path,
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to delete file', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: Quarantine threat file
     *
     * Moves a file identified as a security threat to quarantine.
     */
    public function ajax_quarantine_threat()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get and validate file path
        $file_path = isset($_POST['file_path']) ? sanitize_text_field($_POST['file_path']) : '';
        if (empty($file_path)) {
            wp_send_json_error(array('message' => __('File path is required', 'spectrus-guard')));
        }

        // Construct full path
        $full_path = ABSPATH . ltrim($file_path, '/');
        $basename = basename($full_path);
        $extension = pathinfo($basename, PATHINFO_EXTENSION);

        // Security check: must be within ABSPATH
        $real_path = realpath($full_path);
        $real_abspath = realpath(ABSPATH);
        if ($real_path && $real_abspath && strpos($real_path, $real_abspath) !== 0) {
            wp_send_json_error(array('message' => __('Invalid file path', 'spectrus-guard')));
        }

        // Check if file exists
        if (!file_exists($full_path)) {
            wp_send_json_error(array('message' => __('File not found', 'spectrus-guard')));
        }

        // Prevent quarantining this plugin's files
        $plugin_dir = ABSPATH . 'wp-content/plugins/SpectrusGuard/';
        if (strpos($full_path, $plugin_dir) === 0) {
            wp_send_json_error(array('message' => __('Cannot quarantine plugin files', 'spectrus-guard')));
        }

        // Create quarantine directory if it doesn't exist
        $quarantine_dir = WP_CONTENT_DIR . '/spectrus-quarantine/';
        if (!is_dir($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);

            // Protect with .htaccess
            $htaccess = $quarantine_dir . '/.htaccess';
            if (!file_exists($htaccess)) {
                file_put_contents($htaccess, "Order deny,allow\nDeny from all");
            }

            // Add index.php
            $index = $quarantine_dir . '/index.php';
            if (!file_exists($index)) {
                file_put_contents($index, '<?php // Silence is golden');
            }
        }

        // Generate unique quarantine filename
        $timestamp = date('Y-m-d_H-i-s');
        $quarantine_name = $basename . '.quarantine-' . $timestamp;
        $quarantine_path = $quarantine_dir . $quarantine_name;

        // Move file to quarantine
        if (rename($full_path, $quarantine_path)) {
            wp_send_json_success(array(
                'message' => __('File quarantined successfully', 'spectrus-guard'),
                'file' => $file_path,
                'quarantine_name' => $quarantine_name,
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to quarantine file', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: List all quarantined files
     *
     * Returns a list of all files currently in quarantine.
     */
    public function ajax_list_quarantine()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        $quarantine_dir = WP_CONTENT_DIR . '/spectrus-quarantine/';

        // Check if directory exists
        if (!is_dir($quarantine_dir)) {
            wp_send_json_success(array(
                'files' => array(),
                'message' => __('No quarantine directory found', 'spectrus-guard')
            ));
        }

        // Get all .quarantine-* files
        $files = array();
        $iterator = new DirectoryIterator($quarantine_dir);

        foreach ($iterator as $fileinfo) {
            if ($fileinfo->isFile() && strpos($fileinfo->getFilename(), '.quarantine-') !== false) {
                $filename = $fileinfo->getFilename();

                // Parse filename to extract original info
                // Format: originalname.php.quarantine-YYYY-MM-DD_HH-MM-SS
                if (preg_match('/^(.+)\.quarantine-(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$/', $filename, $matches)) {
                    $original_name = $matches[1];
                    $timestamp = $matches[2];
                    $quarantine_date = str_replace('_', ' ', $timestamp);
                    $file_size = size_format($fileinfo->getSize(), 2);

                    $files[] = array(
                        'quarantine_name' => $filename,
                        'original_name' => $original_name,
                        'date' => $quarantine_date,
                        'size' => $file_size,
                        'path' => $quarantine_dir . $filename,
                    );
                }
            }
        }

        // Sort by date (newest first)
        usort($files, function ($a, $b) {
            return strcmp($b['date'], $a['date']);
        });

        wp_send_json_success(array(
            'files' => $files,
            'count' => count($files)
        ));
    }

    /**
     * AJAX: Restore file from quarantine
     *
     * Restores a quarantined file to its original location.
     */
    public function ajax_restore_quarantine()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get quarantine filename
        $quarantine_name = isset($_POST['quarantine_name']) ? sanitize_text_field($_POST['quarantine_name']) : '';
        if (empty($quarantine_name)) {
            wp_send_json_error(array('message' => __('Quarantine name is required', 'spectrus-guard')));
        }

        $quarantine_dir = WP_CONTENT_DIR . '/spectrus-quarantine/';
        $quarantine_path = $quarantine_dir . $quarantine_name;

        // Security check
        if (strpos($quarantine_name, '.quarantine-') === false) {
            wp_send_json_error(array('message' => __('Invalid quarantine file', 'spectrus-guard')));
        }

        // Check if file exists
        if (!file_exists($quarantine_path)) {
            wp_send_json_error(array('message' => __('Quarantined file not found', 'spectrus-guard')));
        }

        // Extract original filename and path
        // Format: originalname.php.quarantine-YYYY-MM_DD_HH-MM-SS
        if (preg_match('/^(.+)\.quarantine-\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$/', $quarantine_name, $matches)) {
            $original_filename = $matches[1];

            // Try to find original location from common locations
            $possible_locations = array(
                ABSPATH . 'wp-content/uploads/' . $original_filename,
                ABSPATH . 'wp-content/plugins/' . $original_filename,
                ABSPATH . 'wp-content/themes/' . $original_filename,
            );

            $restore_path = null;
            foreach ($possible_locations as $location) {
                if (file_exists($location) || is_dir(dirname($location))) {
                    $restore_path = $location;
                    break;
                }
            }

            // If no known location, use uploads as default
            if (!$restore_path) {
                $restore_path = ABSPATH . 'wp-content/uploads/' . $original_filename;
            }

            // Restore file
            if (rename($quarantine_path, $restore_path)) {
                // Clear scan cache so restored files appear in next scan
                $scanner = $this->loader->get_scanner();
                if ($scanner) {
                    $scanner->clear_cache();
                }

                wp_send_json_success(array(
                    'message' => __('File restored successfully', 'spectrus-guard'),
                    'file' => $original_filename,
                    'restore_path' => str_replace(ABSPATH, '', $restore_path)
                ));
            } else {
                wp_send_json_error(array('message' => __('Failed to restore file', 'spectrus-guard')));
            }
        } else {
            wp_send_json_error(array('message' => __('Invalid quarantine filename format', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: Delete quarantined file permanently
     *
     * Permanently deletes a file from quarantine.
     */
    public function ajax_delete_quarantine()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get quarantine filename
        $quarantine_name = isset($_POST['quarantine_name']) ? sanitize_text_field($_POST['quarantine_name']) : '';
        if (empty($quarantine_name)) {
            wp_send_json_error(array('message' => __('Quarantine name is required', 'spectrus-guard')));
        }

        $quarantine_dir = WP_CONTENT_DIR . '/spectrus-quarantine/';
        $quarantine_path = $quarantine_dir . $quarantine_name;

        // Security check
        if (strpos($quarantine_name, '.quarantine-') === false) {
            wp_send_json_error(array('message' => __('Invalid quarantine file', 'spectrus-guard')));
        }

        // Check if file exists
        if (!file_exists($quarantine_path)) {
            wp_send_json_error(array('message' => __('Quarantined file not found', 'spectrus-guard')));
        }

        // Delete file permanently
        if (unlink($quarantine_path)) {
            // Clear scan cache for consistency
            $scanner = $this->loader->get_scanner();
            if ($scanner) {
                $scanner->clear_cache();
            }

            wp_send_json_success(array(
                'message' => __('File deleted permanently', 'spectrus-guard'),
                'file' => $quarantine_name
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to delete file', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: Whitelist file
     *
     * Adds a file to the whitelist with explicit user confirmation.
     */
    public function ajax_whitelist_file()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get and validate file path
        $file_path = isset($_POST['file_path']) ? sanitize_text_field($_POST['file_path']) : '';
        if (empty($file_path)) {
            wp_send_json_error(array('message' => __('File path is required', 'spectrus-guard')));
        }

        // Get notes
        $notes = isset($_POST['notes']) ? sanitize_textarea_field($_POST['notes']) : '';

        // Construct full path
        $full_path = ABSPATH . ltrim($file_path, '/');

        // Security check: must be within ABSPATH
        $real_path = realpath($full_path);
        $real_abspath = realpath(ABSPATH);
        if ($real_path && $real_abspath && strpos($real_path, $real_abspath) !== 0) {
            wp_send_json_error(array('message' => __('Invalid file path', 'spectrus-guard')));
        }

        // Check if file exists
        if (!file_exists($full_path)) {
            wp_send_json_error(array('message' => __('File not found', 'spectrus-guard')));
        }

        // Calculate file hash
        $file_hash = hash_file('sha256', $full_path);

        // Get whitelist instance
        if (!class_exists('SG_Whitelist')) {
            wp_send_json_error(array('message' => __('Whitelist module not available', 'spectrus-guard')));
        }

        $whitelist = new SG_Whitelist();

        // Add to whitelist
        $whitelist_id = $whitelist->add($full_path, $file_hash, $notes);

        if ($whitelist_id) {
            // Clear scan cache
            $scanner = $this->loader->get_scanner();
            if ($scanner) {
                $scanner->clear_cache();
            }

            wp_send_json_success(array(
                'message' => __('File added to whitelist successfully', 'spectrus-guard'),
                'file' => $file_path,
                'whitelist_id' => $whitelist_id
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to add file to whitelist', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: Remove file from whitelist
     *
     * Removes a file from the whitelist.
     */
    public function ajax_remove_whitelist()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get whitelist ID
        $whitelist_id = isset($_POST['whitelist_id']) ? intval($_POST['whitelist_id']) : 0;
        if ($whitelist_id <= 0) {
            wp_send_json_error(array('message' => __('Invalid whitelist ID', 'spectrus-guard')));
        }

        // Get whitelist instance
        if (!class_exists('SG_Whitelist')) {
            wp_send_json_error(array('message' => __('Whitelist module not available', 'spectrus-guard')));
        }

        $whitelist = new SG_Whitelist();

        // Remove from whitelist
        if ($whitelist->remove($whitelist_id)) {
            // Clear scan cache
            $scanner = $this->loader->get_scanner();
            if ($scanner) {
                $scanner->clear_cache();
            }

            wp_send_json_success(array(
                'message' => __('File removed from whitelist successfully', 'spectrus-guard'),
                'whitelist_id' => $whitelist_id
            ));
        } else {
            wp_send_json_error(array('message' => __('Failed to remove file from whitelist', 'spectrus-guard')));
        }
    }

    /**
     * AJAX: List all whitelisted files
     *
     * Returns a list of all whitelisted files.
     */
    public function ajax_list_whitelist()
    {
        // Verify nonce
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        // Get whitelist instance
        if (!class_exists('SG_Whitelist')) {
            wp_send_json_error(array('message' => __('Whitelist module not available', 'spectrus-guard')));
        }

        $whitelist = new SG_Whitelist();

        // Get all whitelisted files
        $files = $whitelist->get_all();

        wp_send_json_success(array(
            'files' => $files,
            'count' => count($files)
        ));
    }
}
