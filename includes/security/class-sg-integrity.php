<?php
/**
 * SpectrusGuard Integrity Checker
 *
 * Self-protection system to detect unauthorized modifications.
 * Implements Software Supply Chain Security with local and remote attestation.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

declare(strict_types=1);

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Integrity
 *
 * Verifies plugin file integrity against known good hashes.
 */
class SG_Integrity
{
    /**
     * Plugin version for manifest matching
     */
    private const PLUGIN_VERSION = SG_VERSION;

    /**
     * Remote manifest URL (GitHub raw)
     */
    private const REMOTE_MANIFEST_URL = 'https://raw.githubusercontent.com/carlosindriago/SpectrusGuard/main/integrity.json';

    /**
     * Hash algorithm used
     */
    private const HASH_ALGORITHM = 'sha256';

    /**
     * Cache key for remote manifest
     */
    private const REMOTE_CACHE_KEY = 'sg_remote_integrity_manifest';

    /**
     * Cache duration (24 hours)
     */
    private const CACHE_DURATION = DAY_IN_SECONDS;

    /**
     * Option key for integrity status
     */
    private const STATUS_OPTION = 'sg_integrity_status';

    /**
     * Critical files that MUST be monitored
     * If any of these are modified, it's a high-severity alert
     *
     * @var array<string>
     */
    private const CRITICAL_FILES = [
        'spectrus-guard.php',
        'mu-loader/spectrus-waf.php',
        'includes/waf/class-sg-firewall.php',
        'includes/hardening/class-sg-api-guard.php',
        'includes/hardening/class-sg-ghost-cloak.php',
        'includes/hardening/class-sg-ghost-rescue.php',
        'includes/admin/class-sg-ajax.php',
        'includes/admin/class-sg-admin.php',
        'includes/security/class-sg-integrity.php',
        'uninstall.php',
    ];

    /**
     * High-risk files (important but not core security)
     *
     * @var array<string>
     */
    private const HIGH_RISK_FILES = [
        'includes/class-sg-loader.php',
        'includes/scanner/class-sg-scanner.php',
        'includes/scanner/class-sg-heuristic.php',
        'includes/ueba/class-sg-ueba-engine.php',
        'includes/ueba/class-sg-response-engine.php',
    ];

    /**
     * Logger instance
     *
     * @var SG_Logger|null
     */
    private ?SG_Logger $logger;

    /**
     * Settings
     *
     * @var array
     */
    private array $settings;

    /**
     * Constructor
     *
     * @param SG_Logger|null $logger Logger instance
     */
    public function __construct(?SG_Logger $logger = null)
    {
        $this->logger = $logger;
        $this->settings = get_option('spectrus_shield_settings', []);
    }

    /**
     * Initialize the integrity system
     * Called on plugin load
     */
    public function init(): void
    {
        // Run integrity check on admin init (not every page load)
        if (is_admin() && !wp_doing_ajax()) {
            add_action('admin_init', [$this, 'scheduled_check'], 1);
        }

        // Add CLI command for manual verification
        if (defined('WP_CLI') && WP_CLI) {
            \WP_CLI::add_command('spectrus integrity', [$this, 'cli_verify']);
        }
    }

    /**
     * Scheduled integrity check (runs once per day)
     */
    public function scheduled_check(): void
    {
        $last_check = get_transient('sg_last_integrity_check');

        if ($last_check !== false) {
            return; // Already checked today
        }

        // Perform the check
        $result = $this->verify_local_integrity();

        // Cache for 24 hours
        set_transient('sg_last_integrity_check', time(), self::CACHE_DURATION);

        // Store result
        update_option(self::STATUS_OPTION, [
            'status' => $result['passed'] ? 'ok' : 'compromised',
            'last_check' => current_time('mysql'),
            'details' => $result,
        ]);

        // If compromised, trigger alert
        if (!$result['passed']) {
            $this->trigger_integrity_alert($result);
        }
    }

    /**
     * Get list of all files to monitor
     *
     * @return array<string, string> File path => risk level
     */
    public function get_monitored_files(): array
    {
        $files = [];

        foreach (self::CRITICAL_FILES as $file) {
            $files[$file] = 'critical';
        }

        foreach (self::HIGH_RISK_FILES as $file) {
            $files[$file] = 'high';
        }

        return $files;
    }

    /**
     * Generate integrity manifest for current files
     *
     * @return array Manifest data
     */
    public function generate_manifest(): array
    {
        $manifest = [
            'version' => self::PLUGIN_VERSION,
            'generated' => gmdate('c'),
            'algorithm' => self::HASH_ALGORITHM,
            'files' => [],
        ];

        $monitored = $this->get_monitored_files();

        foreach ($monitored as $file => $risk_level) {
            $full_path = SG_PLUGIN_DIR . $file;

            if (file_exists($full_path)) {
                $hash = hash_file(self::HASH_ALGORITHM, $full_path);
                $manifest['files'][$file] = [
                    'hash' => $hash,
                    'risk' => $risk_level,
                    'size' => filesize($full_path),
                ];
            }
        }

        return $manifest;
    }

    /**
     * Save manifest to integrity.json
     *
     * @return bool Success
     */
    public function save_manifest(): bool
    {
        $manifest = $this->generate_manifest();
        $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $path = SG_PLUGIN_DIR . 'integrity.json';
        $result = file_put_contents($path, $json, LOCK_EX);

        return $result !== false;
    }

    /**
     * Load local manifest
     *
     * @return array|null Manifest or null if not found
     */
    public function get_local_manifest(): ?array
    {
        $path = SG_PLUGIN_DIR . 'integrity.json';

        if (!file_exists($path)) {
            return null;
        }

        $content = file_get_contents($path);
        $manifest = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return null;
        }

        return $manifest;
    }

    /**
     * Verify local file integrity
     *
     * @return array Verification result
     */
    public function verify_local_integrity(): array
    {
        $manifest = $this->get_local_manifest();

        if ($manifest === null) {
            return [
                'passed' => false,
                'error' => 'Manifest not found',
                'checked' => 0,
                'failed' => [],
                'missing' => [],
            ];
        }

        $result = [
            'passed' => true,
            'checked' => 0,
            'failed' => [],
            'missing' => [],
            'manifest_version' => $manifest['version'] ?? 'unknown',
        ];

        foreach ($manifest['files'] as $file => $expected) {
            $full_path = SG_PLUGIN_DIR . $file;
            $result['checked']++;

            if (!file_exists($full_path)) {
                $result['missing'][] = $file;
                $result['passed'] = false;
                continue;
            }

            $expected_hash = is_array($expected) ? $expected['hash'] : $expected;
            $actual_hash = hash_file(self::HASH_ALGORITHM, $full_path);

            if ($actual_hash !== $expected_hash) {
                $result['failed'][] = [
                    'file' => $file,
                    'expected' => substr($expected_hash, 0, 16) . '...',
                    'actual' => substr($actual_hash, 0, 16) . '...',
                    'risk' => is_array($expected) ? ($expected['risk'] ?? 'unknown') : 'unknown',
                ];
                $result['passed'] = false;
            }
        }

        return $result;
    }

    /**
     * Fetch and verify against remote manifest (GitHub)
     *
     * @return array Verification result
     */
    public function verify_remote_integrity(): array
    {
        // Check if remote attestation is enabled
        if (empty($this->settings['integrity_remote_check'])) {
            return [
                'passed' => true,
                'skipped' => true,
                'reason' => 'Remote attestation disabled',
            ];
        }

        // Try to get cached remote manifest
        $remote_manifest = get_transient(self::REMOTE_CACHE_KEY);

        if ($remote_manifest === false) {
            // Fetch from GitHub
            $response = wp_remote_get(self::REMOTE_MANIFEST_URL, [
                'timeout' => 10,
                'sslverify' => true,
                'headers' => [
                    'Accept' => 'application/json',
                    'User-Agent' => 'SpectrusGuard/' . self::PLUGIN_VERSION,
                ],
            ]);

            if (is_wp_error($response)) {
                return [
                    'passed' => false,
                    'error' => 'Failed to fetch remote manifest: ' . $response->get_error_message(),
                ];
            }

            $body = wp_remote_retrieve_body($response);
            $remote_manifest = json_decode($body, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                return [
                    'passed' => false,
                    'error' => 'Invalid remote manifest JSON',
                ];
            }

            // Cache for 24 hours
            set_transient(self::REMOTE_CACHE_KEY, $remote_manifest, self::CACHE_DURATION);
        }

        // Compare local manifest with remote
        $local_manifest = $this->get_local_manifest();

        if ($local_manifest === null) {
            return [
                'passed' => false,
                'error' => 'Local manifest not found',
            ];
        }

        // Version check
        if (($remote_manifest['version'] ?? '') !== ($local_manifest['version'] ?? '')) {
            return [
                'passed' => false,
                'error' => 'Version mismatch',
                'local_version' => $local_manifest['version'] ?? 'unknown',
                'remote_version' => $remote_manifest['version'] ?? 'unknown',
            ];
        }

        // Compare file hashes
        $mismatches = [];
        foreach ($remote_manifest['files'] as $file => $remote_data) {
            $remote_hash = is_array($remote_data) ? $remote_data['hash'] : $remote_data;
            $local_data = $local_manifest['files'][$file] ?? null;
            $local_hash = is_array($local_data) ? ($local_data['hash'] ?? '') : ($local_data ?? '');

            if ($local_hash !== $remote_hash) {
                $mismatches[] = $file;
            }
        }

        if (!empty($mismatches)) {
            return [
                'passed' => false,
                'error' => 'Manifest tampering detected',
                'mismatched_files' => $mismatches,
            ];
        }

        return [
            'passed' => true,
            'verified_files' => count($remote_manifest['files']),
        ];
    }

    /**
     * Trigger integrity alert
     *
     * @param array $result Verification result
     */
    private function trigger_integrity_alert(array $result): void
    {
        // Log the event
        if ($this->logger) {
            $this->logger->log('critical', 'INTEGRITY ALERT: Plugin files have been modified', [
                'component' => 'integrity',
                'failed_files' => $result['failed'] ?? [],
                'missing_files' => $result['missing'] ?? [],
            ]);
        }

        // Store compromised status
        update_option('sg_integrity_compromised', true);

        // Add persistent admin notice
        add_action('admin_notices', function () use ($result) {
            $failed_count = count($result['failed'] ?? []);
            $missing_count = count($result['missing'] ?? []);
            ?>
            <div class="notice notice-error" style="border-left-color: #dc2626; background: #fef2f2;">
                <p style="font-size: 14px;">
                    <strong style="color: #dc2626;">🚨
                        <?php esc_html_e('SpectrusGuard Integrity Alert', 'spectrus-guard'); ?>
                    </strong>
                </p>
                <p>
                    <?php
                    printf(
                        esc_html__('Critical security files have been modified! %1$d file(s) failed verification, %2$d file(s) missing.', 'spectrus-guard'),
                        $failed_count,
                        $missing_count
                    );
                    ?>
                </p>
                <p>
                    <strong>
                        <?php esc_html_e('This could indicate:', 'spectrus-guard'); ?>
                    </strong>
                    <?php esc_html_e('Malware injection, unauthorized plugin modification, or plugin file corruption.', 'spectrus-guard'); ?>
                </p>
                <p>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-settings&tab=integrity')); ?>"
                        class="button button-primary">
                        <?php esc_html_e('View Details', 'spectrus-guard'); ?>
                    </a>
                    <a href="https://github.com/carlosindriago/SpectrusGuard/releases" target="_blank" class="button">
                        <?php esc_html_e('Download Official Version', 'spectrus-guard'); ?>
                    </a>
                </p>
            </div>
            <?php
        });

        // Send email notification if enabled
        if (!empty($this->settings['integrity_email_alert'])) {
            $this->send_alert_email($result);
        }
    }

    /**
     * Send alert email to admin
     *
     * @param array $result Verification result
     */
    private function send_alert_email(array $result): void
    {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');

        $subject = sprintf(
            '🚨 [%s] SpectrusGuard Integrity Alert',
            $site_name
        );

        $message = sprintf(
            "CRITICAL SECURITY ALERT\n\n" .
            "SpectrusGuard has detected unauthorized modifications to its core files.\n\n" .
            "Site: %s\n" .
            "Time: %s\n\n" .
            "Files with modified hashes: %d\n" .
            "Missing files: %d\n\n" .
            "This could indicate:\n" .
            "- Malware was injected into the plugin\n" .
            "- Someone modified the plugin files\n" .
            "- File corruption occurred\n\n" .
            "RECOMMENDED ACTIONS:\n" .
            "1. Download the official version from GitHub\n" .
            "2. Compare the modified files\n" .
            "3. Run a full malware scan\n" .
            "4. Check your server access logs\n\n" .
            "GitHub Repository: https://github.com/carlosindriago/SpectrusGuard\n\n" .
            "---\n" .
            "SpectrusGuard Security Suite",
            home_url(),
            current_time('mysql'),
            count($result['failed'] ?? []),
            count($result['missing'] ?? [])
        );

        wp_mail($admin_email, $subject, $message);
    }

    /**
     * Get current integrity status
     *
     * @return array Status data
     */
    public function get_status(): array
    {
        $status = get_option(self::STATUS_OPTION, [
            'status' => 'unknown',
            'last_check' => null,
            'details' => null,
        ]);

        return $status;
    }

    /**
     * Force a fresh integrity check
     *
     * @return array Verification result
     */
    public function force_check(): array
    {
        // Clear cache
        delete_transient('sg_last_integrity_check');
        delete_transient(self::REMOTE_CACHE_KEY);

        // Run local check
        $local_result = $this->verify_local_integrity();

        // Run remote check if enabled
        $remote_result = $this->verify_remote_integrity();

        $combined = [
            'local' => $local_result,
            'remote' => $remote_result,
            'passed' => $local_result['passed'] && ($remote_result['passed'] ?? true),
            'timestamp' => current_time('mysql'),
        ];

        // Update status
        update_option(self::STATUS_OPTION, [
            'status' => $combined['passed'] ? 'ok' : 'compromised',
            'last_check' => $combined['timestamp'],
            'details' => $combined,
        ]);

        // Reset compromised flag if passed
        if ($combined['passed']) {
            delete_option('sg_integrity_compromised');
        }

        return $combined;
    }

    /**
     * WP-CLI command for integrity verification
     *
     * @param array $args Command arguments
     * @param array $assoc_args Associative arguments
     */
    public function cli_verify(array $args, array $assoc_args): void
    {
        \WP_CLI::log('SpectrusGuard Integrity Checker');
        \WP_CLI::log('================================');

        // Generate fresh manifest if requested
        if (!empty($assoc_args['generate'])) {
            \WP_CLI::log('Generating new manifest...');
            if ($this->save_manifest()) {
                \WP_CLI::success('Manifest saved to integrity.json');
            } else {
                \WP_CLI::error('Failed to save manifest');
            }
            return;
        }

        // Run verification
        $result = $this->verify_local_integrity();

        \WP_CLI::log(sprintf('Checked: %d files', $result['checked']));

        if ($result['passed']) {
            \WP_CLI::success('All files passed integrity verification');
        } else {
            \WP_CLI::error('Integrity check FAILED');

            if (!empty($result['failed'])) {
                \WP_CLI::log('Modified files:');
                foreach ($result['failed'] as $failure) {
                    \WP_CLI::log(sprintf('  - %s [%s]', $failure['file'], $failure['risk']));
                }
            }

            if (!empty($result['missing'])) {
                \WP_CLI::log('Missing files:');
                foreach ($result['missing'] as $file) {
                    \WP_CLI::log(sprintf('  - %s', $file));
                }
            }
        }

        // Remote check
        if (!empty($assoc_args['remote'])) {
            \WP_CLI::log('');
            \WP_CLI::log('Remote Attestation...');
            $remote = $this->verify_remote_integrity();

            if ($remote['passed']) {
                \WP_CLI::success('Remote attestation passed');
            } else {
                \WP_CLI::error('Remote attestation failed: ' . ($remote['error'] ?? 'Unknown error'));
            }
        }
    }
}
