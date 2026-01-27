<?php
/**
 * GhostShield URL Cloaker
 *
 * Rewrites WordPress URLs to hide fingerprints that reveal WordPress usage.
 * Uses output buffering to rewrite URLs in HTML and .htaccess rules
 * to handle incoming requests to the cloaked URLs.
 *
 * @package GhostShield
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class GS_URL_Cloaker
 *
 * Rewrites WordPress URLs to generic paths to hide WordPress fingerprints.
 */
class GS_URL_Cloaker
{

    /**
     * URL mappings (original => cloaked)
     *
     * @var array
     */
    private $url_mappings = array();

    /**
     * Whether cloaking is enabled
     *
     * @var bool
     */
    private $enabled = false;

    /**
     * Site URL without protocol
     *
     * @var string
     */
    private $site_domain = '';

    /**
     * Constructor
     *
     * @param array $settings Plugin settings.
     */
    public function __construct($settings = array())
    {
        $this->enabled = !empty($settings['url_cloaking_enabled']);

        if (!$this->enabled) {
            return;
        }

        // Don't run in admin
        if (is_admin()) {
            return;
        }

        // Set up URL mappings
        $this->setup_mappings();

        // Get site domain for relative URL handling
        $this->site_domain = wp_parse_url(home_url(), PHP_URL_HOST);

        // Start output buffering (hook early)
        add_action('template_redirect', array($this, 'start_output_buffer'), 1);

        // Also rewrite in script/style loaders for early assets
        add_filter('script_loader_src', array($this, 'cloak_asset_url'), 10000);
        add_filter('style_loader_src', array($this, 'cloak_asset_url'), 10000);

        // Handle srcset in images
        add_filter('wp_calculate_image_srcset', array($this, 'cloak_srcset'), 10000);
    }

    /**
     * Set up URL mappings
     */
    private function setup_mappings()
    {
        // Get content dir name (usually 'wp-content')
        $content_dir = basename(WP_CONTENT_DIR);

        // Mappings: original path => cloaked path
        $this->url_mappings = array(
            '/' . $content_dir . '/plugins/' => '/assets/plugins/',
            '/' . $content_dir . '/themes/' => '/assets/themes/',
            '/' . $content_dir . '/uploads/' => '/assets/media/',
            '/wp-includes/' => '/assets/core/',
        );

        // Allow filtering for custom mappings
        $this->url_mappings = apply_filters('ghostshield_url_mappings', $this->url_mappings);
    }

    /**
     * Start output buffering
     */
    public function start_output_buffer()
    {
        ob_start(array($this, 'rewrite_output'));
    }

    /**
     * Rewrite URLs in the output buffer
     *
     * @param string $html HTML output.
     * @return string Modified HTML.
     */
    public function rewrite_output($html)
    {
        if (empty($html)) {
            return $html;
        }

        // Don't process if it's not HTML
        if (stripos($html, '<html') === false && stripos($html, '<!DOCTYPE') === false) {
            return $html;
        }

        // Apply URL mappings
        foreach ($this->url_mappings as $original => $cloaked) {
            // Replace in HTML attributes (src, href, srcset, etc.)
            $html = str_replace($original, $cloaked, $html);

            // Handle encoded URLs
            $html = str_replace(urlencode($original), urlencode($cloaked), $html);
        }

        // Remove any remaining WordPress fingerprints in URLs
        $html = $this->remove_wp_fingerprints($html);

        return $html;
    }

    /**
     * Cloak individual asset URL
     *
     * @param string $url Asset URL.
     * @return string Cloaked URL.
     */
    public function cloak_asset_url($url)
    {
        if (empty($url)) {
            return $url;
        }

        // Only process local URLs
        if (strpos($url, home_url()) === false && strpos($url, '/') !== 0) {
            return $url;
        }

        foreach ($this->url_mappings as $original => $cloaked) {
            if (strpos($url, $original) !== false) {
                $url = str_replace($original, $cloaked, $url);
                break;
            }
        }

        return $url;
    }

    /**
     * Cloak srcset URLs
     *
     * @param array $sources Image sources.
     * @return array Modified sources.
     */
    public function cloak_srcset($sources)
    {
        if (!is_array($sources)) {
            return $sources;
        }

        foreach ($sources as $key => $source) {
            if (isset($source['url'])) {
                $sources[$key]['url'] = $this->cloak_asset_url($source['url']);
            }
        }

        return $sources;
    }

    /**
     * Remove remaining WordPress fingerprints
     *
     * @param string $html HTML content.
     * @return string Cleaned HTML.
     */
    private function remove_wp_fingerprints($html)
    {
        // Remove WordPress class patterns (wp-image-123, wp-block-*, etc.)
        // Only in class attributes, preserve content
        $html = preg_replace_callback(
            '/class=["\']([^"\']*)["\']/',
            function ($matches) {
                $classes = $matches[1];
                // Remove wp- prefixed classes but keep content intact
                $classes = preg_replace('/\bwp-image-\d+\b/', '', $classes);
                // Clean up multiple spaces
                $classes = preg_replace('/\s+/', ' ', trim($classes));
                return 'class="' . $classes . '"';
            },
            $html
        );

        return $html;
    }

    /**
     * Generate .htaccess rules for URL cloaking
     *
     * These rules redirect requests from /assets/X/ to /wp-content/X/
     *
     * @return string .htaccess rules.
     */
    public static function generate_htaccess_rules()
    {
        $content_dir = basename(WP_CONTENT_DIR);

        $rules = <<<HTACCESS
# BEGIN GhostShield URL Cloaking
<IfModule mod_rewrite.c>
RewriteEngine On

# Cloak wp-content/plugins to assets/plugins
RewriteRule ^assets/plugins/(.*)$ {$content_dir}/plugins/$1 [L,QSA]

# Cloak wp-content/themes to assets/themes
RewriteRule ^assets/themes/(.*)$ {$content_dir}/themes/$1 [L,QSA]

# Cloak wp-content/uploads to assets/media
RewriteRule ^assets/media/(.*)$ {$content_dir}/uploads/$1 [L,QSA]

# Cloak wp-includes to assets/core
RewriteRule ^assets/core/(.*)$ wp-includes/$1 [L,QSA]
</IfModule>
# END GhostShield URL Cloaking
HTACCESS;

        return $rules;
    }

    /**
     * Generate Nginx rewrite rules for URL cloaking
     *
     * These rules should be added to the Nginx server block configuration.
     * Unlike Apache, Nginx requires manual configuration and server reload.
     *
     * @return string Nginx configuration rules.
     */
    public static function generate_nginx_rules()
    {
        $content_dir = basename(WP_CONTENT_DIR);

        $rules = <<<NGINX
# GhostShield URL Cloaking - Add to your Nginx server block
# After adding these rules, reload Nginx: sudo systemctl reload nginx

# Cloak wp-content/plugins to assets/plugins
location /assets/plugins/ {
    alias /path/to/wordpress/{$content_dir}/plugins/;
}

# Cloak wp-content/themes to assets/themes
location /assets/themes/ {
    alias /path/to/wordpress/{$content_dir}/themes/;
}

# Cloak wp-content/uploads to assets/media
location /assets/media/ {
    alias /path/to/wordpress/{$content_dir}/uploads/;
}

# Cloak wp-includes to assets/core
location /assets/core/ {
    alias /path/to/wordpress/wp-includes/;
}
NGINX;

        return $rules;
    }

    /**
     * Detect web server type
     *
     * @return string 'apache', 'nginx', 'litespeed', or 'unknown'.
     */
    public static function detect_server()
    {
        $server_software = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower($_SERVER['SERVER_SOFTWARE']) : '';

        if (strpos($server_software, 'nginx') !== false) {
            return 'nginx';
        } elseif (strpos($server_software, 'apache') !== false) {
            return 'apache';
        } elseif (strpos($server_software, 'litespeed') !== false) {
            return 'litespeed'; // LiteSpeed supports .htaccess
        }

        return 'unknown';
    }

    /**
     * Check if .htaccess has the cloaking rules
     *
     * @return bool True if rules are present.
     */
    public static function htaccess_has_rules()
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            return false;
        }

        $content = file_get_contents($htaccess_path);

        return strpos($content, '# BEGIN GhostShield URL Cloaking') !== false;
    }

    /**
     * Add cloaking rules to .htaccess
     *
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    public static function add_htaccess_rules()
    {
        $htaccess_path = ABSPATH . '.htaccess';

        // Check if file is writable
        if (!is_writable($htaccess_path)) {
            return new WP_Error(
                'htaccess_not_writable',
                __('The .htaccess file is not writable. Please add the rules manually.', 'ghost-shield')
            );
        }

        // Read current content
        $current_content = file_get_contents($htaccess_path);

        // Check if rules already exist
        if (self::htaccess_has_rules()) {
            // Remove old rules first
            $current_content = self::remove_htaccess_rules_from_content($current_content);
        }

        // Generate new rules
        $new_rules = self::generate_htaccess_rules();

        // Add rules at the beginning (before WordPress rules)
        if (strpos($current_content, '# BEGIN WordPress') !== false) {
            $new_content = $new_rules . "\n\n" . $current_content;
        } else {
            $new_content = $new_rules . "\n\n" . $current_content;
        }

        // Write back
        $result = file_put_contents($htaccess_path, $new_content);

        if ($result === false) {
            return new WP_Error(
                'htaccess_write_failed',
                __('Failed to write to .htaccess file.', 'ghost-shield')
            );
        }

        return true;
    }

    /**
     * Remove cloaking rules from .htaccess
     *
     * @return bool|WP_Error True on success, WP_Error on failure.
     */
    public static function remove_htaccess_rules()
    {
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            return true; // Nothing to remove
        }

        if (!is_writable($htaccess_path)) {
            return new WP_Error(
                'htaccess_not_writable',
                __('The .htaccess file is not writable.', 'ghost-shield')
            );
        }

        $content = file_get_contents($htaccess_path);
        $new_content = self::remove_htaccess_rules_from_content($content);

        $result = file_put_contents($htaccess_path, $new_content);

        if ($result === false) {
            return new WP_Error(
                'htaccess_write_failed',
                __('Failed to write to .htaccess file.', 'ghost-shield')
            );
        }

        return true;
    }

    /**
     * Remove cloaking rules from content string
     *
     * @param string $content .htaccess content.
     * @return string Content without cloaking rules.
     */
    private static function remove_htaccess_rules_from_content($content)
    {
        // Remove the block including comments
        $pattern = '/# BEGIN GhostShield URL Cloaking.*?# END GhostShield URL Cloaking\s*/s';
        return preg_replace($pattern, '', $content);
    }

    /**
     * Get reverse URL mappings (for decloaking in admin)
     *
     * @return array Cloaked => Original mappings.
     */
    public function get_reverse_mappings()
    {
        return array_flip($this->url_mappings);
    }

    /**
     * Check if URL is cloaked
     *
     * @param string $url URL to check.
     * @return bool True if URL has cloaked paths.
     */
    public function is_cloaked_url($url)
    {
        foreach ($this->url_mappings as $original => $cloaked) {
            if (strpos($url, $cloaked) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Decloak a URL back to original
     *
     * @param string $url Cloaked URL.
     * @return string Original URL.
     */
    public function decloak_url($url)
    {
        foreach ($this->url_mappings as $original => $cloaked) {
            if (strpos($url, $cloaked) !== false) {
                return str_replace($cloaked, $original, $url);
            }
        }
        return $url;
    }
}
