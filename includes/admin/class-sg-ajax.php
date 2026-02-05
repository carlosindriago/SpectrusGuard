<?php
/**
 * SpectrusGuard AJAX Handler
 *
 * Handles all AJAX requests for buttons and actions in the dashboard.
 *
 * @package SpectrusGuard
 * @since   3.0.4
 */

if (!defined('ABSPATH')) {
    exit;
}

class SG_Ajax
{
    /**
     * Initialize hooks
     */
    public function init()
    {
        add_action('wp_ajax_sg_delete_file', array($this, 'handle_delete_file'));
        add_action('wp_ajax_sg_whitelist_file', array($this, 'handle_whitelist_file'));
        add_action('wp_ajax_sg_quarantine_file', array($this, 'handle_quarantine_file'));
        add_action('wp_ajax_sg_list_quarantine', array($this, 'handle_list_quarantine'));
        add_action('wp_ajax_sg_restore_quarantine', array($this, 'handle_restore_quarantine'));
        add_action('wp_ajax_sg_delete_quarantine', array($this, 'handle_delete_quarantine'));

        // Chart.js data endpoints
        add_action('wp_ajax_sg_get_chart_data', array($this, 'handle_get_chart_data'));
        add_action('wp_ajax_sg_get_threat_summary', array($this, 'handle_get_threat_summary'));
        add_action('wp_ajax_sg_search_logs', array($this, 'handle_search_logs'));
    }

    /**
     * Validate file path to prevent path traversal attacks
     *
     * @param string $filePath Raw file path from user input
     * @return string|null Valid absolute path or null if invalid
     */
    private function validateFilePath(string $filePath): ?string
    {
        // First, try the path as-is
        $realPath = @realpath($filePath);

        // If not found, try prepending ABSPATH
        if ($realPath === false) {
            $realPath = @realpath(ABSPATH . ltrim($filePath, '/'));
        }

        // Still not found
        if ($realPath === false) {
            return null;
        }

        // Security check: ensure file is within allowed directories
        $allowedPaths = [
            realpath(ABSPATH),
            realpath(WP_CONTENT_DIR),
        ];

        foreach ($allowedPaths as $allowed) {
            if ($allowed !== false && strpos($realPath, $allowed) === 0) {
                return $realPath;
            }
        }

        // Path is outside allowed directories
        return null;
    }

    /**
     * Handle File Deletion
     */
    public function handle_delete_file()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $raw_path = isset($_POST['file']) ? sanitize_text_field($_POST['file']) : '';
        $original_file_path = $raw_path; // Keep original for report update

        // Validate path to prevent path traversal
        $file_path = $this->validateFilePath($raw_path);
        if ($file_path === null) {
            wp_send_json_error('Invalid file path');
        }

        // Attempt delete
        if (@unlink($file_path)) {
            // Update the scan report to remove this item so it doesn't reappear until next scan
            $this->remove_from_report($original_file_path);
            wp_send_json_success('File deleted successfully');
        } else {
            wp_send_json_error('Could not delete file. Permission denied?');
        }
    }

    /**
     * Handle Quarantine Actions
     */
    public function handle_quarantine_file()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $raw_path = isset($_POST['file']) ? sanitize_text_field($_POST['file']) : '';
        $original_file_path = $raw_path;

        // Validate path to prevent path traversal
        $file_path = $this->validateFilePath($raw_path);
        if ($file_path === null) {
            wp_send_json_error('Invalid file path');
        }

        // Setup Quarantine Directory
        $upload_dir = wp_upload_dir();
        $quarantine_dir = $upload_dir['basedir'] . '/spectrus-quarantine';

        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
        }

        // Secure Quarantine Directory
        if (!file_exists($quarantine_dir . '/.htaccess')) {
            file_put_contents($quarantine_dir . '/.htaccess', "Order Deny,Allow\nDeny from all");
        }
        if (!file_exists($quarantine_dir . '/index.php')) {
            file_put_contents($quarantine_dir . '/index.php', '<?php // Silence is golden');
        }

        // Generate destination name
        // IMPROVED: Base64 encode full path to preserve location for restore
        // Format: encoded_path.timestamp.sgq
        $encoded_path = base64_encode($file_path);
        // Clean base64 output for filename safety (replace /, +)
        $safe_encoded = str_replace(array('/', '+'), array('_', '-'), $encoded_path);
        $new_name = $safe_encoded . '.' . time() . '.sgq';
        $dest_path = $quarantine_dir . '/' . $new_name;

        if (@rename($file_path, $dest_path)) {
            $this->remove_from_report($original_file_path);
            wp_send_json_success('File quarantined successfully');
        } else {
            wp_send_json_error('Could not move file to quarantine');
        }
    }

    /**
     * List Quarantined Files
     */
    public function handle_list_quarantine()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $upload_dir = wp_upload_dir();
        $quarantine_dir = $upload_dir['basedir'] . '/spectrus-quarantine';

        $files = array();

        // Ensure directory exists
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
        }

        if (file_exists($quarantine_dir)) {
            $scanned = scandir($quarantine_dir);

            foreach ($scanned as $item) {
                if ($item === '.' || $item === '..' || $item === '.htaccess' || $item === 'index.php') {
                    continue;
                }

                $full_path = $quarantine_dir . '/' . $item;
                $size = size_format(filesize($full_path));
                $date = date('Y-m-d H:i:s', filemtime($full_path));

                // Parse filename
                if (strpos($item, '.sgq') !== false) {
                    // New format: encoded.time.sgq
                    $parts = explode('.', $item);
                    $encoded = $parts[0];
                    // Restore standard base64
                    $base64 = str_replace(array('_', '-'), array('/', '+'), $encoded);
                    $original_path = base64_decode($base64);
                    // Add full path as tooltip?
                    $display_name = $original_path;
                } else {
                    // Legacy/Fallback format: basename.time.quarantined
                    $parts = explode('.', $item);
                    $original_name = $parts[0]; // Simple logic
                    $original_name = str_replace(array('.quarantined'), '', $item);
                    $original_name = preg_replace('/\.\d+$/', '', $original_name);
                    $display_name = $original_name . ' (Unknown Loc)';
                }

                $files[] = array(
                    'quarantine_name' => $item,
                    'original_name' => $display_name,
                    'date' => $date,
                    'size' => $size
                );
            }
        }

        wp_send_json_success(array('files' => $files));
    }

    /**
     * Restore File
     */
    public function handle_restore_quarantine()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');
        if (!current_user_can('manage_options'))
            wp_send_json_error('Unauthorized');

        $q_name = isset($_POST['quarantine_name']) ? sanitize_file_name($_POST['quarantine_name']) : '';
        if (!$q_name)
            wp_send_json_error('Missing filename');

        $upload_dir = wp_upload_dir();
        $quarantine_path = $upload_dir['basedir'] . '/spectrus-quarantine/' . $q_name;

        if (!file_exists($quarantine_path)) {
            wp_send_json_error('File not found in quarantine');
        }

        // Determine destination
        if (strpos($q_name, '.sgq') !== false) {
            $parts = explode('.', $q_name);
            $encoded = $parts[0];
            $base64 = str_replace(array('_', '-'), array('/', '+'), $encoded);
            $dest_path = base64_decode($base64);
        } else {
            wp_send_json_error('Cannot automatically restore legacy quarantine file. Please manually move it from uploads/spectrus-quarantine.');
            return;
        }

        // Ensure directory exists
        $dest_dir = dirname($dest_path);
        if (!file_exists($dest_dir)) {
            wp_mkdir_p($dest_dir);
        }

        if (@rename($quarantine_path, $dest_path)) {
            wp_send_json_success(array('message' => 'File restored successfully'));
        } else {
            wp_send_json_error('Could not restore file (Permission error?)');
        }
    }

    /**
     * Delete Permanently
     */
    public function handle_delete_quarantine()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');
        if (!current_user_can('manage_options'))
            wp_send_json_error('Unauthorized');

        $q_name = isset($_POST['quarantine_name']) ? sanitize_file_name($_POST['quarantine_name']) : '';
        if (!$q_name)
            wp_send_json_error('Missing filename');

        $upload_dir = wp_upload_dir();
        $quarantine_path = $upload_dir['basedir'] . '/spectrus-quarantine/' . $q_name;

        if (file_exists($quarantine_path)) {
            if (@unlink($quarantine_path)) {
                wp_send_json_success(array('message' => 'File permanently deleted'));
            } else {
                wp_send_json_error('Could not delete file');
            }
        } else {
            wp_send_json_error('File not found');
        }
    }

    /**
     * Handle Whitelisting
     */
    public function handle_whitelist_file()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $file_path = isset($_POST['file']) ? sanitize_text_field($_POST['file']) : '';

        if (empty($file_path)) {
            wp_send_json_error('Invalid file');
        }

        $whitelist = get_option('spectrus_guard_whitelist', array());

        if (!in_array($file_path, $whitelist)) {
            $whitelist[] = $file_path;
            update_option('spectrus_guard_whitelist', $whitelist);
        }

        // Also remove from current report UI
        $this->remove_from_report($file_path);

        wp_send_json_success('File whitelisted');
    }

    /**
     * Remove item from current scan report so UI stays consistent
     */
    private function remove_from_report($file_path)
    {
        $report = get_option('spectrus_guard_scan_report', array());

        // The report structure is complex ($report['malware'] etc).
        // Iterate references to remove
        $categories = ['malware', 'uploads_php', 'core_integrity', 'suspicious', 'advanced_threats'];
        $modified = false;

        foreach ($categories as $cat) {
            if (!empty($report[$cat])) {
                foreach ($report[$cat] as $key => $item) {
                    $item_file = $item['file'] ?? '';
                    // Robust match: Exact match OR basename match (handle relative vs absolute mismatches)
                    if ($item_file === $file_path || basename($item_file) === basename($file_path)) {
                        unset($report[$cat][$key]);
                        $modified = true;
                    }
                }
                // Re-index array
                $report[$cat] = array_values($report[$cat]);
            }
        }

        if ($modified) {
            update_option('spectrus_guard_scan_report', $report, false);
        }
    }

    /**
     * Handle Chart.js data request
     *
     * Returns hourly threat data for visualization.
     */
    public function handle_get_chart_data()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $date = isset($_POST['date']) ? sanitize_text_field($_POST['date']) : date('Y-m-d');

        // Load parser
        require_once SG_PLUGIN_DIR . 'includes/admin/class-sg-log-parser.php';

        $parser = new SG_Log_Parser();
        $logger = new SG_Logger();
        $logFile = $logger->getSecurityLogPath();

        $data = $parser->getStatsForChart($logFile, $date);

        wp_send_json_success($data);
    }

    /**
     * Handle threat summary request
     *
     * Returns aggregated threat data across multiple days.
     */
    public function handle_get_threat_summary()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $days = isset($_POST['days']) ? absint($_POST['days']) : 7;
        $days = min($days, 30); // Max 30 days

        require_once SG_PLUGIN_DIR . 'includes/admin/class-sg-log-parser.php';

        $parser = new SG_Log_Parser();
        $logger = new SG_Logger();

        $data = $parser->getThreatSummary($logger->getLogDirectory(), $days);

        wp_send_json_success($data);
    }

    /**
     * Handle log search request
     */
    public function handle_search_logs()
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $query = isset($_POST['query']) ? sanitize_text_field($_POST['query']) : '';
        $limit = isset($_POST['limit']) ? absint($_POST['limit']) : 50;

        if (empty($query)) {
            wp_send_json_error('Search query required');
        }

        require_once SG_PLUGIN_DIR . 'includes/admin/class-sg-log-parser.php';

        $parser = new SG_Log_Parser();
        $logger = new SG_Logger();

        $results = $parser->search($logger->getSecurityLogPath(), $query, $limit);

        wp_send_json_success([
            'results' => $results,
            'count' => count($results),
        ]);
    }
}
