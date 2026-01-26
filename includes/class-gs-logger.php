<?php
/**
 * GhostShield Logger
 *
 * Handles logging of security events to files and database.
 * Creates protected log files that are not publicly accessible.
 *
 * @package GhostShield
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class GS_Logger
 *
 * Security event logger with file and database support.
 */
class GS_Logger
{

    /**
     * Log directory path
     *
     * @var string
     */
    private $log_dir;

    /**
     * Main attack log file path
     *
     * @var string
     */
    private $attack_log_file;

    /**
     * Debug log file path
     *
     * @var string
     */
    private $debug_log_file;

    /**
     * Maximum log file size in bytes (5MB)
     *
     * @var int
     */
    private $max_log_size = 5242880;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->log_dir = WP_CONTENT_DIR . '/ghost-shield-logs';
        $this->attack_log_file = $this->log_dir . '/attacks.log';
        $this->debug_log_file = $this->log_dir . '/debug.log';

        $this->ensure_log_directory();
    }

    /**
     * Ensure log directory exists and is protected
     */
    private function ensure_log_directory()
    {
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
        }

        // Protect with .htaccess
        $htaccess_file = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess_file)) {
            file_put_contents($htaccess_file, "Order deny,allow\nDeny from all");
        }

        // Protect with index.php
        $index_file = $this->log_dir . '/index.php';
        if (!file_exists($index_file)) {
            file_put_contents($index_file, '<?php // Silence is golden');
        }
    }

    /**
     * Log an attack event
     *
     * @param string $type    Attack type (sqli, xss, traversal, rce, etc.).
     * @param string $payload The malicious payload detected.
     * @param string $ip      Attacker IP address.
     * @param string $uri     Request URI.
     * @param array  $extra   Additional data to log.
     */
    public function log_attack($type, $payload, $ip, $uri, $extra = array())
    {
        $timestamp = current_time('Y-m-d H:i:s');

        $log_entry = array(
            'timestamp' => $timestamp,
            'type' => strtoupper($type),
            'ip' => $ip,
            'uri' => $uri,
            'payload' => $this->sanitize_payload($payload),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 200) : '',
            'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'UNKNOWN',
        );

        // Merge extra data
        if (!empty($extra)) {
            $log_entry = array_merge($log_entry, $extra);
        }

        // Format log line
        $log_line = sprintf(
            "[%s] [%s] IP: %s | URI: %s | Payload: %s | UA: %s\n",
            $log_entry['timestamp'],
            $log_entry['type'],
            $log_entry['ip'],
            $log_entry['uri'],
            $log_entry['payload'],
            $log_entry['user_agent']
        );

        // Rotate log if needed
        $this->maybe_rotate_log($this->attack_log_file);

        // Write to file
        file_put_contents($this->attack_log_file, $log_line, FILE_APPEND | LOCK_EX);

        // Update statistics
        $this->update_stats($type);

        // Fire action for observers (notifications, etc.)
        do_action('ghost_shield_attack_logged', $log_entry);
    }

    /**
     * Log a debug message
     *
     * @param string $message Debug message.
     * @param string $level   Log level (info, warning, error).
     */
    public function log_debug($message, $level = 'info')
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }

        $timestamp = current_time('Y-m-d H:i:s');
        $log_line = sprintf("[%s] [%s] %s\n", $timestamp, strtoupper($level), $message);

        $this->maybe_rotate_log($this->debug_log_file);
        file_put_contents($this->debug_log_file, $log_line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Sanitize payload for safe logging
     *
     * @param string $payload Raw payload.
     * @return string Sanitized payload.
     */
    private function sanitize_payload($payload)
    {
        // Limit length
        $payload = substr($payload, 0, 500);

        // Remove newlines and tabs
        $payload = str_replace(array("\n", "\r", "\t"), ' ', $payload);

        // Escape special characters
        $payload = addslashes($payload);

        return $payload;
    }

    /**
     * Rotate log file if it exceeds maximum size
     *
     * @param string $log_file Log file path.
     */
    private function maybe_rotate_log($log_file)
    {
        if (!file_exists($log_file)) {
            return;
        }

        if (filesize($log_file) >= $this->max_log_size) {
            $backup_file = $log_file . '.' . date('Y-m-d-His') . '.bak';
            rename($log_file, $backup_file);

            // Keep only last 5 backup files
            $this->cleanup_old_backups(dirname($log_file), basename($log_file));
        }
    }

    /**
     * Clean up old backup log files
     *
     * @param string $dir      Directory path.
     * @param string $basename Original log filename.
     */
    private function cleanup_old_backups($dir, $basename)
    {
        $pattern = $dir . '/' . $basename . '.*.bak';
        $backups = glob($pattern);

        if (count($backups) > 5) {
            // Sort by modification time
            usort($backups, function ($a, $b) {
                return filemtime($a) - filemtime($b);
            });

            // Delete oldest backups
            $to_delete = array_slice($backups, 0, count($backups) - 5);
            foreach ($to_delete as $file) {
                unlink($file);
            }
        }
    }

    /**
     * Update attack statistics
     *
     * @param string $type Attack type.
     */
    private function update_stats($type)
    {
        $stats = get_option('ghost_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => array(),
        ));

        // Increment counters
        $stats['total_blocked']++;

        $type_key = strtolower($type) . '_blocked';
        if (isset($stats[$type_key])) {
            $stats[$type_key]++;
        }

        $stats['last_attack'] = current_time('mysql');

        // Update daily stats (keep last 30 days)
        $today = current_time('Y-m-d');
        if (!isset($stats['daily_stats'][$today])) {
            $stats['daily_stats'][$today] = 0;
        }
        $stats['daily_stats'][$today]++;

        // Prune old daily stats
        $cutoff = date('Y-m-d', strtotime('-30 days'));
        foreach ($stats['daily_stats'] as $date => $count) {
            if ($date < $cutoff) {
                unset($stats['daily_stats'][$date]);
            }
        }

        update_option('ghost_shield_attack_stats', $stats);
    }

    /**
     * Get recent attack logs
     *
     * @param int $limit Maximum number of entries to return.
     * @return array Array of log entries.
     */
    public function get_logs($limit = 100)
    {
        if (!file_exists($this->attack_log_file)) {
            return array();
        }

        $logs = array();
        $lines = file($this->attack_log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if (empty($lines)) {
            return array();
        }

        // Get last $limit lines (most recent)
        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);

        foreach ($lines as $line) {
            // Parse log line
            if (preg_match('/\[([^\]]+)\] \[([^\]]+)\] IP: ([^\|]+) \| URI: ([^\|]+) \| Payload: ([^\|]+) \| UA: (.*)/', $line, $matches)) {
                $logs[] = array(
                    'timestamp' => trim($matches[1]),
                    'type' => trim($matches[2]),
                    'ip' => trim($matches[3]),
                    'uri' => trim($matches[4]),
                    'payload' => trim($matches[5]),
                    'user_agent' => trim($matches[6]),
                );
            }
        }

        return $logs;
    }

    /**
     * Clear all logs
     *
     * @return bool True on success, false on failure.
     */
    public function clear_logs()
    {
        $cleared = true;

        if (file_exists($this->attack_log_file)) {
            $cleared = unlink($this->attack_log_file);
        }

        // Also clear backup files
        $backups = glob($this->attack_log_file . '.*.bak');
        foreach ($backups as $backup) {
            unlink($backup);
        }

        return $cleared;
    }

    /**
     * Get attack statistics
     *
     * @return array
     */
    public function get_stats()
    {
        return get_option('ghost_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => array(),
        ));
    }

    /**
     * Get log file path
     *
     * @return string
     */
    public function get_log_path()
    {
        return $this->attack_log_file;
    }
}
