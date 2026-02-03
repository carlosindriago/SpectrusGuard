<?php
/**
 * SpectrusGuard Stealth Module
 *
 * Anti-fingerprinting module that removes WordPress signatures and
 * hides technical details from attackers and scanners.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Stealth
 *
 * Cleans up WordPress fingerprints and hides technical details.
 */
class SG_Stealth
{

    /**
     * Plugin settings
     *
     * @var array
     */
    private $settings;

    /**
     * Constructor
     *
     * @param array $settings Plugin settings.
     */
    public function __construct($settings = array())
    {
        $this->settings = $settings;

        // 1. Remove Generator meta tag
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');

        // 2. Clean HTTP headers
        add_filter('wp_headers', array($this, 'remove_sensitive_headers'));
        add_action('send_headers', array($this, 'remove_php_header'));

        // 3. Remove version strings from CSS/JS
        add_filter('style_loader_src', array($this, 'remove_version_params'), 9999);
        add_filter('script_loader_src', array($this, 'remove_version_params'), 9999);

        // 4. Remove unnecessary head links
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
        remove_action('wp_head', 'rest_output_link_wp_head');
        remove_action('wp_head', 'wp_oembed_add_discovery_links');
        remove_action('template_redirect', 'rest_output_link_header', 11);

        // 5. Remove emoji scripts
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');

        // 6. Block access to sensitive files
        add_action('template_redirect', array($this, 'block_sensitive_files'));

        // 7. Hide login page (Moved to class-sg-login-guard.php)
        /*
        if (!empty($this->settings['hide_login'])) {
            add_action('init', array($this, 'hide_login_page'), 1);
            add_filter('site_url', array($this, 'filter_login_url'), 10, 4);
            add_filter('wp_redirect', array($this, 'filter_login_redirect'), 10, 2);
        }
        */

        // 8. Disable XML-RPC (if enabled)
        if (!empty($this->settings['block_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('wp_headers', array($this, 'remove_xmlrpc_header'));
            add_filter('xmlrpc_methods', array($this, 'disable_xmlrpc_methods'));
        }

        // 9. Remove WordPress-specific comments
        add_action('wp_head', array($this, 'remove_wp_comments'), 1);
        add_action('wp_footer', array($this, 'remove_wp_comments'), 1);
    }

    /**
     * Remove sensitive HTTP headers
     *
     * @param array $headers HTTP headers.
     * @return array Filtered headers.
     */
    public function remove_sensitive_headers($headers)
    {
        // Remove X-Powered-By
        unset($headers['X-Powered-By']);

        // Remove Server header if possible
        unset($headers['Server']);

        // Remove Link header (API discovery)
        unset($headers['Link']);

        return $headers;
    }

    /**
     * Remove PHP version from headers
     */
    public function remove_php_header()
    {
        if (function_exists('header_remove')) {
            header_remove('X-Powered-By');
        }
    }

    /**
     * Remove version parameters from scripts and styles
     *
     * Replaces ?ver=X.X.X with a hash to maintain cache-busting
     * while hiding the actual version numbers.
     *
     * @param string $src Asset URL.
     * @return string Modified URL.
     */
    public function remove_version_params($src)
    {
        if (strpos($src, 'ver=') === false) {
            return $src;
        }

        // Check if it's a local asset or external
        $home_url = home_url();

        if (strpos($src, $home_url) !== false || strpos($src, '/') === 0) {
            // Local asset - replace version with hash
            $hash = 'sg_' . substr(md5(SG_VERSION . $src), 0, 8);
            $src = add_query_arg('ver', $hash, remove_query_arg('ver', $src));
        }

        return $src;
    }

    /**
     * Remove X-Pingback header
     *
     * @param array $headers HTTP headers.
     * @return array Filtered headers.
     */
    public function remove_xmlrpc_header($headers)
    {
        unset($headers['X-Pingback']);
        return $headers;
    }

    /**
     * Disable all XML-RPC methods
     *
     * @param array $methods XML-RPC methods.
     * @return array Empty array.
     */
    public function disable_xmlrpc_methods($methods)
    {
        return array();
    }

    /**
     * Block access to sensitive files
     */
    public function block_sensitive_files()
    {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';

        // List of files to block
        $blocked_files = array(
            '/readme.html',
            '/license.txt',
            '/wp-config-sample.php',
            '/wp-admin/install.php',
            '/wp-admin/upgrade.php',
        );

        foreach ($blocked_files as $file) {
            if (stripos($request_uri, $file) !== false) {
                // Return 404
                global $wp_query;
                $wp_query->set_404();
                status_header(404);
                nocache_headers();

                // Try to load theme's 404 template
                $template = get_404_template();
                if ($template) {
                    include $template;
                    exit;
                }

                // Fallback
                wp_die(
                    esc_html__('Page not found.', 'spectrus-guard'),
                    esc_html__('404 Not Found', 'spectrus-guard'),
                    array('response' => 404)
                );
            }
        }
    }

    /**
        // Option 1: Redirect to home
        wp_safe_redirect(home_url('/'), 302);
        exit;

        // Option 2: Show 404 (uncomment to use)
        // global $wp_query;
        // $wp_query->set_404();
        // status_header( 404 );
        // nocache_headers();
        // include get_404_template();
        // exit;
    }

    /**
     * Remove WordPress HTML comments
     *
     * Removes comments like <!-- WordPress X.X --> and <!-- Plugin Name -->
     */
    public function remove_wp_comments()
    {
        ob_start(function ($html) {
            // Remove WordPress version comments
            $html = preg_replace('/<!--[^>]*WordPress[^>]*-->/i', '', $html);

            // Remove plugin/theme name comments
            $html = preg_replace('/<!--[^>]*(plugin|theme|generator)[^>]*-->/i', '', $html);

            return $html;
        });
    }
}
