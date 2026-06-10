<?php
/**
 * SpectrusGuard Trusted Paths Helper
 *
 * Centralizes logic for path exclusions and clean directory traversal.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Trusted_Paths
 *
 * Handles file filtering, skipping dependency and testing directories.
 */
class SG_Trusted_Paths
{
    /**
     * Excluded directory names during traversal.
     *
     * @var array
     */
    private static $excluded_directories = array(
        'vendor',
        'node_modules',
        'bower_components',
        'tests',
        'test',
        'docs',
        '.git',
        '.github'
    );

    /**
     * Check if a path contains excluded directory segments.
     *
     * @param string $path Path to check.
     * @return bool True if the path contains excluded directories.
     */
    public static function is_path_excluded(string $path): bool
    {
        $normalized_path = str_replace('\\', '/', $path);
        
        // Remove trailing slashes for clean exploding
        $clean_path = rtrim($normalized_path, '/');
        $segments = explode('/', $clean_path);

        foreach ($segments as $segment) {
            if (in_array(strtolower($segment), self::$excluded_directories, true)) {
                return true;
            }
        }

        // Exclude core WordPress standard directories and specific WooCommerce vendor folders
        if (strpos($normalized_path, '/wp-includes/') !== false ||
            strpos($normalized_path, '/wp-admin/') !== false ||
            strpos($normalized_path, '/woocommerce/vendor/') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Check if a path is a vendor path or standard bypassed folder.
     *
     * @param string $path Path to check.
     * @return bool True if vendor path.
     */
    public static function is_vendor_path(string $path): bool
    {
        return self::is_path_excluded($path);
    }

    /**
     * Check if a path belongs to a known/standard WordPress plugin.
     *
     * @param string $path Path to check.
     * @return bool True if known plugin.
     */
    public static function is_known_plugin(string $path): bool
    {
        $normalized_path = str_replace('\\', '/', $path);

        $known_plugins = array(
            'woocommerce',
            'contact-form-7',
            'jetpack',
            'elementor',
            'elementor-pro',
            'wpforms-lite',
            'wpforms',
            'mailchimp-for-wp',
            'yoast-seo-premium',
            'wordpress-seo',
            'woocommerce-gateway-stripe',
            'woocommerce-payments',
            'gravityforms',
            'learnpress',
            'buddypress',
            'bbpress',
            'easy-digital-downloads',
            'the-events-calendar',
            'akismet'
        );

        foreach ($known_plugins as $plugin) {
            if (strpos($normalized_path, '/plugins/' . $plugin . '/') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if a file name has a PHP extension.
     *
     * @param string $filename Filename to check.
     * @return bool True if PHP file.
     */
    public static function is_php_file(string $filename): bool
    {
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        return in_array($extension, array('php', 'phtml', 'php5', 'php7', 'phps'), true);
    }

    /**
     * Check if a path is inside the current plugin directory.
     *
     * @param string $path Path to check.
     * @return bool True if it belongs to SpectrusGuard.
     */
    public static function is_plugin_file(string $path): bool
    {
        if (defined('SG_PLUGIN_DIR')) {
            $plugin_dir = str_replace('\\', '/', SG_PLUGIN_DIR);
            $normalized_path = str_replace('\\', '/', $path);
            return strpos($normalized_path, $plugin_dir) === 0;
        }
        return false;
    }

    /**
     * Check if a path is a plugin or theme file.
     *
     * @param string $path Path to check.
     * @return bool True if plugin or theme.
     */
    public static function is_plugin_or_theme_file(string $path): bool
    {
        $normalized_path = str_replace('\\', '/', $path);
        return strpos($normalized_path, '/wp-content/plugins/') !== false ||
               strpos($normalized_path, '/wp-content/themes/') !== false;
    }

    /**
     * Walk directory recursively, filtering excluded paths.
     *
     * @param string $directory Directory to walk.
     * @param int    $max_files Maximum files to collect.
     * @return array Array of PHP file paths.
     */
    public static function get_php_files_in_directory(string $directory, int $max_files = 5000): array
    {
        $files = array();
        self::traverse_directory($directory, $files, $max_files);
        return $files;
    }

    /**
     * Recursive helper to walk directory and filter path exclusions.
     *
     * @param string $dir       Current directory.
     * @param array  $files     Collected files.
     * @param int    $max_files Max files limit.
     */
    private static function traverse_directory(string $dir, array &$files, int $max_files)
    {
        if (count($files) >= $max_files) {
            return;
        }

        $dir = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR;
        if (!is_dir($dir)) {
            return;
        }

        $handle = opendir($dir);
        if (!$handle) {
            return;
        }

        while (false !== ($entry = readdir($handle))) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $full_path = $dir . $entry;

            if (is_dir($full_path)) {
                // If directory is excluded, do not recurse into it
                if (self::is_path_excluded($full_path)) {
                    continue;
                }
                self::traverse_directory($full_path, $files, $max_files);
            } else {
                if (self::is_php_file($entry)) {
                    // Check if file itself is excluded
                    if (!self::is_path_excluded($full_path)) {
                        $files[] = str_replace('\\', '/', $full_path);
                    }
                }
            }

            if (count($files) >= $max_files) {
                break;
            }
        }

        closedir($handle);
    }
}
