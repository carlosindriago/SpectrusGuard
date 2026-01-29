<?php
/**
 * SpectrusGuard Geo Updater
 *
 * Handles downloading and updating MaxMind GeoLite2 database.
 *
 * @package SpectrusGuard
 * @since   1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Geo_Updater
 *
 * Downloads and updates geo databases.
 */
class SG_Geo_Updater
{
    /**
     * MaxMind download URL template
     *
     * @var string
     */
    const MAXMIND_DOWNLOAD_URL = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz';

    /**
     * Base directory for geo data
     *
     * @var string
     */
    private $base_dir;

    /**
     * Path to the mmdb file
     *
     * @var string
     */
    private $db_path;

    /**
     * Path to the progress file
     *
     * @var string
     */
    private $progress_file;

    /**
     * Constructor
     */
    public function __construct()
    {
        $upload_dir = wp_upload_dir();
        $this->base_dir = $upload_dir['basedir'] . '/spectrus-guard/geoip';
        $this->db_path = $this->base_dir . '/GeoLite2-Country.mmdb';
        $this->progress_file = $this->base_dir . '/download_progress.json';
    }

    /**
     * Update progress file for polling
     *
     * @param string $status Status: downloading, extracting, complete, error
     * @param int    $progress Progress percentage 0-100
     * @param string $message Human-readable message
     * @param string $error Optional error message
     */
    private function update_progress($status, $progress, $message, $error = '')
    {
        // Ensure directory exists
        if (!file_exists($this->base_dir)) {
            wp_mkdir_p($this->base_dir);
        }

        $data = array(
            'status' => $status,
            'progress' => $progress,
            'message' => $message,
            'timestamp' => time(),
        );

        if ($error) {
            $data['error'] = $error;
        }

        file_put_contents($this->progress_file, json_encode($data));
    }

    /**
     * Clear progress file
     */
    private function clear_progress()
    {
        if (file_exists($this->progress_file)) {
            @unlink($this->progress_file);
        }
    }

    /**
     * Get progress file path for AJAX polling
     *
     * @return string Path to the progress file.
     */
    public function get_progress_file_path()
    {
        return $this->progress_file;
    }

    /**
     * Download and install MaxMind database
     *
     * @param string $license_key MaxMind license key.
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    public function download_database($license_key)
    {
        // Initialize progress
        $this->update_progress('starting', 0, __('Initializing download...', 'spectrus-guard'));

        if (empty($license_key)) {
            $this->update_progress('error', 0, __('MaxMind license key is required', 'spectrus-guard'));
            return new WP_Error(
                'missing_key',
                __('MaxMind license key is required', 'spectrus-guard')
            );
        }

        // Ensure directory exists
        $this->update_progress('downloading', 5, __('Preparing download directory...', 'spectrus-guard'));
        if (!file_exists($this->base_dir)) {
            $created = wp_mkdir_p($this->base_dir);
            if (!$created) {
                $this->update_progress('error', 0, __('Could not create geo database directory', 'spectrus-guard'));
                return new WP_Error(
                    'mkdir_failed',
                    __('Could not create geo database directory', 'spectrus-guard')
                );
            }

            // Protect directory
            file_put_contents($this->base_dir . '/.htaccess', "Order deny,allow\nDeny from all");
            file_put_contents($this->base_dir . '/index.php', '<?php // Silence is golden');
        }

        // Build download URL
        $url = sprintf(self::MAXMIND_DOWNLOAD_URL, urlencode($license_key));

        // Download the file
        $this->update_progress('downloading', 10, __('Connecting to MaxMind servers...', 'spectrus-guard'));
        $temp_file = $this->base_dir . '/temp-geolite2.tar.gz';

        $this->update_progress('downloading', 15, __('Downloading GeoLite2 database (~5MB)...', 'spectrus-guard'));
        $response = wp_remote_get($url, array(
            'timeout' => 120,
            'stream' => true,
            'filename' => $temp_file,
            'sslverify' => true,
        ));

        if (is_wp_error($response)) {
            $error_message = $response->get_error_message();
            $this->update_progress('error', 0, __('Download failed', 'spectrus-guard'), $error_message);
            @unlink($temp_file);
            return $response;
        }

        $this->update_progress('downloading', 60, __('Download complete, verifying response...', 'spectrus-guard'));
        $response_code = wp_remote_retrieve_response_code($response);
        if ($response_code !== 200) {
            @unlink($temp_file);

            if ($response_code === 401) {
                $this->update_progress('error', 0, __('Invalid license key', 'spectrus-guard'));
                return new WP_Error(
                    'invalid_key',
                    __('Invalid MaxMind license key', 'spectrus-guard')
                );
            }

            $error_msg = sprintf(__('Download failed with status code: %d', 'spectrus-guard'), $response_code);
            $this->update_progress('error', 0, $error_msg);
            return new WP_Error(
                'download_failed',
                $error_msg
            );
        }

        // Extract the tar.gz file
        $this->update_progress('extracting', 70, __('Extracting database archive...', 'spectrus-guard'));
        $result = $this->extract_database($temp_file);

        // Clean up temp file
        @unlink($temp_file);

        if (is_wp_error($result)) {
            $this->update_progress('error', 0, __('Extraction failed', 'spectrus-guard'), $result->get_error_message());
            return $result;
        }

        // Save license key (encrypted) for future updates
        $this->update_progress('complete', 90, __('Saving configuration...', 'spectrus-guard'));
        $this->save_license_key($license_key);

        // Update last update time
        update_option('sg_geoip_last_update', time());

        $this->update_progress('complete', 100, __('GeoIP database installed successfully!', 'spectrus-guard'));
        return true;
    }

    /**
     * Extract the database from tar.gz archive
     *
     * @param string $tar_file Path to tar.gz file.
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    private function extract_database($tar_file)
    {
        if (!file_exists($tar_file)) {
            return new WP_Error('file_not_found', __('Downloaded file not found', 'spectrus-guard'));
        }

        // Try using PharData if available
        if (class_exists('PharData')) {
            try {
                // Extract tar.gz
                $phar = new PharData($tar_file);
                $phar->decompress(); // Creates .tar file

                $tar_path = str_replace('.tar.gz', '.tar', $tar_file);

                if (file_exists($tar_path)) {
                    $tar = new PharData($tar_path);
                    $tar->extractTo($this->base_dir, null, true);

                    // Find and move the mmdb file
                    $found = $this->find_and_move_mmdb();

                    // Cleanup
                    @unlink($tar_path);
                    $this->cleanup_extracted_dirs();

                    if (!$found) {
                        return new WP_Error('mmdb_not_found', __('MMDB file not found in archive', 'spectrus-guard'));
                    }

                    return true;
                }
            } catch (Exception $e) {
                return new WP_Error('extract_failed', $e->getMessage());
            }
        }

        // Fallback: Try shell commands
        if ($this->can_use_shell()) {
            return $this->extract_with_shell($tar_file);
        }

        return new WP_Error(
            'no_extract_method',
            __('No extraction method available. Please install PharData or enable shell commands.', 'spectrus-guard')
        );
    }

    /**
     * Find the mmdb file in extracted directories and move it
     *
     * @return bool True if found and moved.
     */
    private function find_and_move_mmdb()
    {
        // MaxMind puts the file in a directory like GeoLite2-Country_YYYYMMDD/
        $dirs = glob($this->base_dir . '/GeoLite2-Country_*', GLOB_ONLYDIR);

        foreach ($dirs as $dir) {
            $mmdb_file = $dir . '/GeoLite2-Country.mmdb';
            if (file_exists($mmdb_file)) {
                // Move to final location
                $moved = rename($mmdb_file, $this->db_path);
                return $moved;
            }
        }

        return false;
    }

    /**
     * Cleanup extracted directories
     */
    private function cleanup_extracted_dirs()
    {
        $dirs = glob($this->base_dir . '/GeoLite2-Country_*', GLOB_ONLYDIR);
        foreach ($dirs as $dir) {
            $this->recursive_delete($dir);
        }
    }

    /**
     * Recursively delete a directory
     *
     * @param string $dir Directory path.
     */
    private function recursive_delete($dir)
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), array('.', '..'));
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->recursive_delete($path) : unlink($path);
        }
        rmdir($dir);
    }

    /**
     * Check if shell commands can be used
     *
     * @return bool True if shell available.
     */
    private function can_use_shell()
    {
        if (!function_exists('exec')) {
            return false;
        }

        $disabled = explode(',', ini_get('disable_functions'));
        if (in_array('exec', array_map('trim', $disabled))) {
            return false;
        }

        // Check if tar is available
        exec('which tar 2>&1', $output, $return);
        return $return === 0;
    }

    /**
     * Extract using shell commands
     *
     * @param string $tar_file Path to tar.gz file.
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    private function extract_with_shell($tar_file)
    {
        $escaped_file = escapeshellarg($tar_file);
        $escaped_dir = escapeshellarg($this->base_dir);

        exec("tar -xzf {$escaped_file} -C {$escaped_dir} 2>&1", $output, $return);

        if ($return !== 0) {
            return new WP_Error('shell_extract_failed', implode("\n", $output));
        }

        $found = $this->find_and_move_mmdb();
        $this->cleanup_extracted_dirs();

        if (!$found) {
            return new WP_Error('mmdb_not_found', __('MMDB file not found in archive', 'spectrus-guard'));
        }

        return true;
    }

    /**
     * Save license key (encrypted)
     *
     * @param string $license_key License key.
     */
    private function save_license_key($license_key)
    {
        // Simple obfuscation (not true encryption, but prevents casual viewing)
        $encoded = base64_encode($license_key);
        update_option('sg_maxmind_license', $encoded);
    }

    /**
     * Get saved license key
     *
     * @return string|null License key or null.
     */
    public function get_license_key()
    {
        $encoded = get_option('sg_maxmind_license', '');
        if (empty($encoded)) {
            return null;
        }
        return base64_decode($encoded);
    }

    /**
     * Check if database needs update (older than 7 days)
     *
     * @return bool True if update needed.
     */
    public function needs_update()
    {
        if (!file_exists($this->db_path)) {
            return true;
        }

        $last_update = get_option('sg_geoip_last_update', 0);
        $week_ago = time() - (7 * DAY_IN_SECONDS);

        return $last_update < $week_ago;
    }

    /**
     * Schedule automatic updates via WP-Cron
     */
    public function schedule_updates()
    {
        if (!wp_next_scheduled('sg_geoip_weekly_update')) {
            wp_schedule_event(time(), 'weekly', 'sg_geoip_weekly_update');
        }
    }

    /**
     * Unschedule automatic updates
     */
    public function unschedule_updates()
    {
        wp_clear_scheduled_hook('sg_geoip_weekly_update');
    }

    /**
     * Perform automatic update (called by WP-Cron)
     *
     * @return bool|WP_Error Result.
     */
    public function auto_update()
    {
        $license_key = $this->get_license_key();
        if (empty($license_key)) {
            return new WP_Error('no_license', __('No license key configured', 'spectrus-guard'));
        }

        return $this->download_database($license_key);
    }

    /**
     * Get update status info
     *
     * @return array Status info.
     */
    public function get_status()
    {
        $db_exists = file_exists($this->db_path);

        return array(
            'installed' => $db_exists,
            'db_path' => $this->db_path,
            'db_size' => $db_exists ? size_format(filesize($this->db_path)) : null,
            'last_update' => get_option('sg_geoip_last_update', null),
            'has_license' => !empty($this->get_license_key()),
            'needs_update' => $this->needs_update(),
        );
    }

    /**
     * Get path to database file
     *
     * @return string Database file path.
     */
    public function get_database_path()
    {
        return $this->db_path;
    }
}
