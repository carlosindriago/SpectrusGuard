<?php
/**
 * SpectrusGuard Logger
 *
 * PSR-3 compliant centralized audit logging system.
 * Handles security events with structured JSON context,
 * file rotation, and protected storage.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 * @since   3.1.0 PSR-3 compliance, JSON context, generators
 */

declare(strict_types=1);

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Logger
 *
 * Security event logger with PSR-3 log levels and JSON structured context.
 */
class SG_Logger
{
    /**
     * PSR-3 Log Levels
     */
    public const EMERGENCY = 'emergency';
    public const ALERT = 'alert';
    public const CRITICAL = 'critical';
    public const ERROR = 'error';
    public const WARNING = 'warning';
    public const NOTICE = 'notice';
    public const INFO = 'info';
    public const DEBUG = 'debug';

    /**
     * Log directory path
     */
    private string $logDir;

    /**
     * Security log file path (dated)
     */
    private string $securityLogFile;

    /**
     * Attack log file path (legacy compatibility)
     */
    private string $attackLogFile;

    /**
     * Debug log file path
     */
    private string $debugLogFile;

    /**
     * Maximum log file size in bytes (5MB)
     */
    private const MAX_LOG_SIZE = 5242880;

    /**
     * Maximum backup files to keep
     */
    private const MAX_BACKUPS = 5;

    /**
     * Constructor
     *
     * @param string $customPath Optional custom log directory path.
     */
    public function __construct(string $customPath = '')
    {
        $this->logDir = $customPath ?: WP_CONTENT_DIR . '/spectrus-guard-logs';
        $this->securityLogFile = $this->logDir . '/security-' . date('Y-m-d') . '.log';
        $this->attackLogFile = $this->logDir . '/attacks.log';
        $this->debugLogFile = $this->logDir . '/debug.log';

        $this->ensureLogDirectory();
    }

    /**
     * Log a message with PSR-3 level
     *
     * @param string $level   PSR-3 log level.
     * @param string $message Log message.
     * @param array  $context Additional context data (will be JSON encoded).
     */
    public function log(string $level, string $message, array $context = []): void
    {
        $timestamp = function_exists('current_time')
            ? current_time('Y-m-d H:i:s')
            : date('Y-m-d H:i:s');

        $contextJson = !empty($context) ? ' ' . json_encode($context, JSON_UNESCAPED_SLASHES) : '';

        $entry = sprintf(
            "[%s] [%s]: %s%s" . PHP_EOL,
            $timestamp,
            strtoupper($level),
            $message,
            $contextJson
        );

        $this->writeToFile($this->securityLogFile, $entry);
    }

    /**
     * System is unusable
     */
    public function emergency(string $message, array $context = []): void
    {
        $this->log(self::EMERGENCY, $message, $context);
    }

    /**
     * Action must be taken immediately
     */
    public function alert(string $message, array $context = []): void
    {
        $this->log(self::ALERT, $message, $context);
    }

    /**
     * Critical conditions (security breaches, attacks)
     */
    public function critical(string $message, array $context = []): void
    {
        $this->log(self::CRITICAL, $message, $context);
    }

    /**
     * Runtime errors
     */
    public function error(string $message, array $context = []): void
    {
        $this->log(self::ERROR, $message, $context);
    }

    /**
     * Exceptional occurrences that are not errors
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log(self::WARNING, $message, $context);
    }

    /**
     * Normal but significant events
     */
    public function notice(string $message, array $context = []): void
    {
        $this->log(self::NOTICE, $message, $context);
    }

    /**
     * Interesting events
     */
    public function info(string $message, array $context = []): void
    {
        $this->log(self::INFO, $message, $context);
    }

    /**
     * Detailed debug information
     */
    public function debug(string $message, array $context = []): void
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }
        $this->log(self::DEBUG, $message, $context);
    }

    /**
     * Log an attack event (legacy compatibility + enhanced)
     *
     * @param string $type    Attack type (sqli, xss, traversal, rce, etc.).
     * @param string $payload The malicious payload detected.
     * @param string $ip      Attacker IP address.
     * @param string $uri     Request URI.
     * @param array  $extra   Additional data to log.
     */
    public function log_attack(string $type, string $payload, string $ip, string $uri, array $extra = []): void
    {
        $context = array_merge([
            'type' => strtoupper($type),
            'ip' => $ip,
            'uri' => $uri,
            'payload' => $this->sanitizePayload($payload),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 200) : '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN',
        ], $extra);

        // Log to new PSR-3 format
        $this->critical('Attack blocked: ' . strtoupper($type), $context);

        // Also write to legacy attacks.log for backward compatibility
        $this->writeLegacyAttackLog($context);

        // Update statistics
        $this->updateStats($type);

        // Fire action for observers
        do_action('spectrus_shield_attack_logged', $context);
    }

    /**
     * Log debug message (legacy compatibility)
     *
     * @param string $message Debug message.
     * @param string $level   Log level (info, warning, error).
     */
    public function log_debug(string $message, string $level = 'info'): void
    {
        if (!defined('WP_DEBUG') || !WP_DEBUG) {
            return;
        }

        $this->log($level, $message);

        // Also write to legacy debug.log
        $timestamp = function_exists('current_time')
            ? current_time('Y-m-d H:i:s')
            : date('Y-m-d H:i:s');

        $logLine = sprintf("[%s] [%s] %s" . PHP_EOL, $timestamp, strtoupper($level), $message);
        $this->writeToFile($this->debugLogFile, $logLine);
    }

    /**
     * Write to legacy attacks.log format
     */
    private function writeLegacyAttackLog(array $context): void
    {
        $timestamp = function_exists('current_time')
            ? current_time('Y-m-d H:i:s')
            : date('Y-m-d H:i:s');

        $logLine = sprintf(
            "[%s] [%s] IP: %s | URI: %s | Payload: %s | UA: %s" . PHP_EOL,
            $timestamp,
            $context['type'],
            $context['ip'],
            $context['uri'],
            $context['payload'],
            $context['user_agent']
        );

        $this->writeToFile($this->attackLogFile, $logLine);
    }

    /**
     * Write entry to log file with rotation
     */
    private function writeToFile(string $filePath, string $entry): void
    {
        $this->maybeRotateLog($filePath);
        file_put_contents($filePath, $entry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Ensure log directory exists and is protected
     */
    private function ensureLogDirectory(): void
    {
        if (!file_exists($this->logDir)) {
            if (function_exists('wp_mkdir_p')) {
                wp_mkdir_p($this->logDir);
            } else {
                mkdir($this->logDir, 0755, true);
            }
        }

        // Protect with .htaccess
        $htaccessFile = $this->logDir . '/.htaccess';
        if (!file_exists($htaccessFile)) {
            file_put_contents($htaccessFile, "Order deny,allow\nDeny from all");
        }

        // Protect with index.php
        $indexFile = $this->logDir . '/index.php';
        if (!file_exists($indexFile)) {
            file_put_contents($indexFile, '<?php // Silence is golden');
        }
    }

    /**
     * Sanitize payload for safe logging
     */
    private function sanitizePayload(string $payload): string
    {
        $payload = substr($payload, 0, 500);
        $payload = str_replace(["\n", "\r", "\t"], ' ', $payload);
        return addslashes($payload);
    }

    /**
     * Rotate log file if it exceeds maximum size
     */
    private function maybeRotateLog(string $logFile): void
    {
        if (!file_exists($logFile)) {
            return;
        }

        if (filesize($logFile) >= self::MAX_LOG_SIZE) {
            $backupFile = $logFile . '.' . date('Y-m-d-His') . '.bak';
            rename($logFile, $backupFile);
            $this->cleanupOldBackups(dirname($logFile), basename($logFile));
        }
    }

    /**
     * Clean up old backup log files
     */
    private function cleanupOldBackups(string $dir, string $basename): void
    {
        $pattern = $dir . '/' . $basename . '.*.bak';
        $backups = glob($pattern);

        if ($backups && count($backups) > self::MAX_BACKUPS) {
            usort($backups, fn($a, $b) => filemtime($a) - filemtime($b));
            $toDelete = array_slice($backups, 0, count($backups) - self::MAX_BACKUPS);
            foreach ($toDelete as $file) {
                @unlink($file);
            }
        }
    }

    /**
     * Update attack statistics
     */
    private function updateStats(string $type): void
    {
        $stats = get_option('spectrus_shield_attack_stats', [
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => [],
        ]);

        $stats['total_blocked']++;

        $typeKey = strtolower($type) . '_blocked';
        if (isset($stats[$typeKey])) {
            $stats[$typeKey]++;
        }

        $stats['last_attack'] = function_exists('current_time')
            ? current_time('mysql')
            : date('Y-m-d H:i:s');

        // Update daily stats
        $today = function_exists('current_time')
            ? current_time('Y-m-d')
            : date('Y-m-d');

        if (!isset($stats['daily_stats'][$today])) {
            $stats['daily_stats'][$today] = 0;
        }
        $stats['daily_stats'][$today]++;

        // Prune old daily stats (keep 30 days)
        $cutoff = date('Y-m-d', strtotime('-30 days'));
        foreach ($stats['daily_stats'] as $date => $count) {
            if ($date < $cutoff) {
                unset($stats['daily_stats'][$date]);
            }
        }

        update_option('spectrus_shield_attack_stats', $stats);
    }

    /**
     * Get recent attack logs (legacy method)
     *
     * @param int $limit Maximum number of entries to return.
     * @return array Array of log entries.
     */
    public function get_logs(int $limit = 100): array
    {
        if (!file_exists($this->attackLogFile)) {
            return [];
        }

        $lines = file($this->attackLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (empty($lines)) {
            return [];
        }

        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);
        $logs = [];

        foreach ($lines as $line) {
            if (preg_match('/\[([^\]]+)\] \[([^\]]+)\] IP: ([^\|]+) \| URI: ([^\|]+) \| Payload: ([^\|]+) \| UA: (.*)/', $line, $matches)) {
                $logs[] = [
                    'timestamp' => trim($matches[1]),
                    'type' => trim($matches[2]),
                    'ip' => trim($matches[3]),
                    'uri' => trim($matches[4]),
                    'payload' => trim($matches[5]),
                    'user_agent' => trim($matches[6]),
                ];
            }
        }

        return $logs;
    }

    /**
     * Clear all logs
     */
    public function clear_logs(): bool
    {
        $cleared = true;

        foreach ([$this->attackLogFile, $this->securityLogFile] as $logFile) {
            if (file_exists($logFile) && !@unlink($logFile)) {
                $cleared = false;
            }

            // Also clear backups
            $backups = glob($logFile . '.*.bak');
            if ($backups) {
                foreach ($backups as $backup) {
                    @unlink($backup);
                }
            }
        }

        return $cleared;
    }

    /**
     * Get attack statistics
     */
    public function get_stats(): array
    {
        return get_option('spectrus_shield_attack_stats', [
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => [],
        ]);
    }

    /**
     * Get log file path (legacy)
     */
    public function get_log_path(): string
    {
        return $this->attackLogFile;
    }

    /**
     * Get security log path (new PSR-3 format)
     */
    public function getSecurityLogPath(): string
    {
        return $this->securityLogFile;
    }

    /**
     * Get log directory path
     */
    public function getLogDirectory(): string
    {
        return $this->logDir;
    }
}
