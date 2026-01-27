<?php
/**
 * SpectrusGuard Checksum Verification
 *
 * Verifies WordPress core file integrity by comparing local files
 * against official checksums from the WordPress.org API.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Checksum
 *
 * Core file integrity verification using WordPress.org checksums API.
 */
class SG_Checksum
{

    /**
     * WordPress.org checksums API endpoint
     *
     * @var string
     */
    const API_ENDPOINT = 'https://api.wordpress.org/core/checksums/1.0/';

    /**
     * Cached checksums
     *
     * @var array|null
     */
    private $checksums = null;

    /**
     * Transient key for cached checksums
     *
     * @var string
     */
    const CHECKSUMS_TRANSIENT = 'spectrus_shield_wp_checksums';

    /**
     * Fetch checksums from WordPress.org API
     *
     * @return array|WP_Error Checksums array or error.
     */
    public function fetch_checksums()
    {
        // Check cache first
        $cached = get_transient(self::CHECKSUMS_TRANSIENT);
        if (false !== $cached) {
            $this->checksums = $cached;
            return $cached;
        }

        global $wp_version, $wp_local_package;

        // Build API URL
        $url = add_query_arg(
            array(
                'version' => $wp_version,
                'locale' => get_locale(),
            ),
            self::API_ENDPOINT
        );

        // Make request
        $response = wp_remote_get($url, array(
            'timeout' => 30,
            'headers' => array(
                'Accept' => 'application/json',
            ),
        ));

        // Check for errors
        if (is_wp_error($response)) {
            // Try without locale
            $url = add_query_arg('version', $wp_version, self::API_ENDPOINT);
            $response = wp_remote_get($url, array('timeout' => 30));

            if (is_wp_error($response)) {
                return $response;
            }
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return new WP_Error('json_error', __('Invalid response from WordPress.org API', 'spectrus-guard'));
        }

        if (empty($data['checksums'])) {
            // API might return checksums for en_US only
            if (get_locale() !== 'en_US') {
                $url = add_query_arg(
                    array(
                        'version' => $wp_version,
                        'locale' => 'en_US',
                    ),
                    self::API_ENDPOINT
                );
                $response = wp_remote_get($url, array('timeout' => 30));

                if (!is_wp_error($response)) {
                    $body = wp_remote_retrieve_body($response);
                    $data = json_decode($body, true);
                }
            }
        }

        if (empty($data['checksums'])) {
            return new WP_Error('no_checksums', __('No checksums available for this WordPress version', 'spectrus-guard'));
        }

        $this->checksums = $data['checksums'];

        // Cache for 24 hours
        set_transient(self::CHECKSUMS_TRANSIENT, $this->checksums, DAY_IN_SECONDS);

        return $this->checksums;
    }

    /**
     * Verify all core files against checksums
     *
     * @return array Array of files with issues.
     */
    public function verify_core_files()
    {
        $issues = array();

        // Get checksums
        $checksums = $this->fetch_checksums();

        if (is_wp_error($checksums)) {
            return array(
                array(
                    'file' => 'API Error',
                    'status' => 'error',
                    'error' => $checksums->get_error_message(),
                ),
            );
        }

        // Check each file
        foreach ($checksums as $file => $expected_hash) {
            $file_path = ABSPATH . $file;

            // Skip wp-content files (they're customizable)
            if (strpos($file, 'wp-content/') === 0) {
                continue;
            }

            // Check if file exists
            if (!file_exists($file_path)) {
                $issues[] = array(
                    'file' => $file,
                    'status' => 'missing',
                );
                continue;
            }

            // Calculate hash
            $actual_hash = md5_file($file_path);

            // Compare
            if ($actual_hash !== $expected_hash) {
                $issues[] = array(
                    'file' => $file,
                    'status' => 'modified',
                    'expected_hash' => $expected_hash,
                    'actual_hash' => $actual_hash,
                );
            }
        }

        // Also check for unknown files in core directories
        $unknown = $this->find_unknown_core_files($checksums);
        $issues = array_merge($issues, $unknown);

        return $issues;
    }

    /**
     * Find files in core directories that shouldn't be there
     *
     * @param array $checksums Official checksums.
     * @return array Unknown files.
     */
    private function find_unknown_core_files($checksums)
    {
        $unknown = array();

        // Directories to check
        $core_dirs = array(
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
        );

        foreach ($core_dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }

                // Skip non-PHP files for now
                if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) !== 'php') {
                    continue;
                }

                // Get relative path
                $relative_path = str_replace(ABSPATH, '', $file->getPathname());
                $relative_path = str_replace('\\', '/', $relative_path); // Windows compatibility

                // Check if it's in the checksums list
                if (!isset($checksums[$relative_path])) {
                    // Check if it's a known exception
                    if (!$this->is_known_exception($relative_path)) {
                        $unknown[] = array(
                            'file' => $relative_path,
                            'status' => 'unknown',
                        );
                    }
                }
            }
        }

        return $unknown;
    }

    /**
     * Check if a file is a known exception (not a threat)
     *
     * @param string $file Relative file path.
     * @return bool True if exception.
     */
    private function is_known_exception($file)
    {
        $exceptions = array(
            'wp-admin/install.php',      // Can be removed after install
            'wp-admin/upgrade.php',      // Migration file
            'wp-config.php',             // User-created
            '.htaccess',                 // Server config
            'object-cache.php',          // Caching plugins
            'advanced-cache.php',        // Caching plugins
            'db.php',                    // DB plugins
        );

        foreach ($exceptions as $exception) {
            if (strpos($file, $exception) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify a single file
     *
     * @param string $file Relative file path.
     * @return array|null Result or null if not in checksums.
     */
    public function verify_single_file($file)
    {
        if (null === $this->checksums) {
            $this->fetch_checksums();
        }

        if (is_wp_error($this->checksums)) {
            return null;
        }

        if (!isset($this->checksums[$file])) {
            return null;
        }

        $file_path = ABSPATH . $file;

        if (!file_exists($file_path)) {
            return array(
                'file' => $file,
                'status' => 'missing',
            );
        }

        $actual_hash = md5_file($file_path);
        $expected_hash = $this->checksums[$file];

        if ($actual_hash === $expected_hash) {
            return array(
                'file' => $file,
                'status' => 'ok',
            );
        }

        return array(
            'file' => $file,
            'status' => 'modified',
            'expected_hash' => $expected_hash,
            'actual_hash' => $actual_hash,
        );
    }

    /**
     * Get the count of core files to check
     *
     * @return int Number of files.
     */
    public function get_core_file_count()
    {
        if (null === $this->checksums) {
            $this->fetch_checksums();
        }

        if (is_wp_error($this->checksums)) {
            return 0;
        }

        return count($this->checksums);
    }

    /**
     * Clear cached checksums
     *
     * @return bool True on success.
     */
    public function clear_cache()
    {
        $this->checksums = null;
        return delete_transient(self::CHECKSUMS_TRANSIENT);
    }
}
