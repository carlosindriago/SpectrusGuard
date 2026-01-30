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
        add_action('wp_ajax_sg_run_scan', array($this, 'ajax_run_scan'));
        add_action('wp_ajax_sg_get_scan_progress', array($this, 'ajax_get_scan_progress'));
        add_action('wp_ajax_sg_delete_threat', array($this, 'ajax_delete_threat'));
        add_action('wp_ajax_sg_quarantine_threat', array($this, 'ajax_quarantine_threat'));
    }

    /**
     * Render the scanner page
     *
     * Loads the scanner view template with scan results data.
     */
    public function render()
    {
        $scanner = $this->loader->get_scanner();
        $results = $scanner ? $scanner->get_display_results() : null;
        $last_scan = $scanner ? $scanner->get_last_scan_time() : null;

        // Prepare data for view
        $data = array(
            'results' => $results,
            'last_scan' => $last_scan,
        );

        // Load view template
        $this->render_view('scanner/page.php', $data);
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
}
