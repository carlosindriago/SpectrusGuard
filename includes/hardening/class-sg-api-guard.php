<?php
/**
 * SpectrusGuard API Guard
 *
 * Protects the WordPress REST API and blocks user enumeration.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load IP Detection Trait
require_once SG_PLUGIN_DIR . 'includes/traits/IpDetectionTrait.php';

/**
 * Class SG_API_Guard
 *
 * REST API protection and anti-enumeration module.
 */
class SG_API_Guard
{
    use IpDetectionTrait;

    /**
     * Constructor
     */
    public function __construct()
    {
        // 1. Protect user enumeration via REST API
        add_filter('rest_endpoints', array($this, 'restrict_user_endpoints'));
        add_filter('rest_pre_dispatch', array($this, 'check_api_permissions'), 10, 3);

        // 2. Block author enumeration via ?author=X
        add_action('template_redirect', array($this, 'block_author_enumeration'));

        // 3. Add honeypot to login form
        add_action('login_form', array($this, 'add_honeypot_field'));
        add_action('login_head', array($this, 'add_honeypot_styles'));
        add_filter('authenticate', array($this, 'check_honeypot'), 0, 3);

        // 4. Limit login attempts (basic)
        add_filter('authenticate', array($this, 'check_login_attempts'), 30, 3);
        add_action('wp_login_failed', array($this, 'log_failed_login'));
        add_action('wp_login', array($this, 'clear_login_attempts'));

        // 5. Remove author name from RSS feeds
        add_filter('the_author', array($this, 'hide_author_in_feed'));

        // 6. Disable REST API for non-logged-in users (optional - configurable)
        // add_filter( 'rest_authentication_errors', array( $this, 'require_auth_for_api' ) );
    }

    /**
     * Restrict access to user-related REST API endpoints
     *
     * @param array $endpoints REST API endpoints.
     * @return array Filtered endpoints.
     */
    public function restrict_user_endpoints($endpoints)
    {
        // Only restrict for non-admin users
        if (current_user_can('list_users')) {
            return $endpoints;
        }

        // Remove user endpoints
        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        if (isset($endpoints['/wp/v2/users/me'])) {
            unset($endpoints['/wp/v2/users/me']);
        }

        return $endpoints;
    }

    /**
     * Check API permissions before dispatch
     *
     * @param mixed           $result  Response to replace the requested version with.
     * @param WP_REST_Server  $server  Server instance.
     * @param WP_REST_Request $request Request used to generate the response.
     * @return mixed
     */
    public function check_api_permissions($result, $server, $request)
    {
        $route = $request->get_route();

        // Block user enumeration routes for non-authenticated users
        if (preg_match('/\/wp\/v2\/users/', $route)) {
            if (!is_user_logged_in() || !current_user_can('list_users')) {
                return new WP_Error(
                    'rest_forbidden',
                    __('You do not have permission to access this resource.', 'spectrus-guard'),
                    array('status' => 403)
                );
            }
        }

        return $result;
    }

    /**
     * Block author enumeration via URL parameter
     */
    public function block_author_enumeration()
    {
        // Block ?author=X requests
        if (isset($_GET['author']) && !is_admin()) {
            // Check if it's a numeric author query
            if (is_numeric($_GET['author'])) {
                wp_safe_redirect(home_url('/'), 301);
                exit;
            }
        }

        // Also block /author/username/ for non-logged-in users
        if (is_author() && !is_user_logged_in()) {
            // Get settings
            $settings = get_option('spectrus_shield_settings', array());
            $block_author_pages = isset($settings['block_author_pages']) ? $settings['block_author_pages'] : false;

            if ($block_author_pages) {
                wp_safe_redirect(home_url('/'), 301);
                exit;
            }
        }
    }

    /**
     * Add honeypot field to login form
     *
     * Bots will typically fill in all fields, including hidden ones.
     */
    public function add_honeypot_field()
    {
        // Create a hidden field that looks like a legitimate input
        $field_name = 'user_website'; // Looks tempting to bots
        ?>
        <p class="sg-hp-field">
            <label for="<?php echo esc_attr($field_name); ?>">
                <?php esc_html_e('Website', 'spectrus-guard'); ?><br>
                <input type="text" name="<?php echo esc_attr($field_name); ?>" id="<?php echo esc_attr($field_name); ?>"
                    class="input" value="" size="20" autocomplete="off" tabindex="-1">
            </label>
        </p>
        <?php
    }

    /**
     * Add CSS to hide the honeypot field
     */
    public function add_honeypot_styles()
    {
        ?>
        <style>
            .sg-hp-field {
                position: absolute !important;
                left: -9999px !important;
                top: -9999px !important;
                opacity: 0 !important;
                height: 0 !important;
                width: 0 !important;
                overflow: hidden !important;
            }
        </style>
        <?php
    }

    /**
     * Check if honeypot field was filled (indicates bot)
     *
     * @param WP_User|WP_Error|null $user     User object or error.
     * @param string                $username Provided username.
     * @param string                $password Provided password.
     * @return WP_User|WP_Error
     */
    public function check_honeypot($user, $username, $password)
    {
        if (empty($username)) {
            return $user;
        }

        // Check if honeypot field is filled
        if (!empty($_POST['user_website'])) {
            // Log the bot attempt
            $this->log_bot_attempt($username);

            // Add a small delay to slow down bots
            sleep(2);

            // Return error (vague to not tip off sophisticated bots)
            return new WP_Error(
                'authentication_failed',
                __('Authentication failed. Please try again.', 'spectrus-guard')
            );
        }

        return $user;
    }

    /**
     * Log bot login attempt
     *
     * @param string $username Attempted username.
     */
    private function log_bot_attempt($username)
    {
        $log_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
        $log_file = $log_dir . '/bots.log';

        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }

        $timestamp = current_time('Y-m-d H:i:s');
        $ip = $this->get_client_ip();

        $log_line = sprintf(
            "[%s] [BOT] IP: %s | Username: %s | Honeypot triggered\n",
            $timestamp,
            $ip,
            sanitize_user($username)
        );

        file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Check login attempts and block if exceeded
     *
     * @param WP_User|WP_Error|null $user     User object or error.
     * @param string                $username Provided username.
     * @param string                $password Provided password.
     * @return WP_User|WP_Error
     */
    public function check_login_attempts($user, $username, $password)
    {
        if (empty($username)) {
            return $user;
        }

        $ip = $this->get_client_ip();
        $transient_key = 'sg_login_attempts_' . md5($ip);
        $attempts = get_transient($transient_key);

        if ($attempts === false) {
            $attempts = 0;
        }

        // Settings
        $settings = get_option('spectrus_shield_settings', array());
        $max_attempts = isset($settings['max_login_attempts']) ? (int) $settings['max_login_attempts'] : 5;
        $lockout_time = isset($settings['login_lockout_time']) ? (int) $settings['login_lockout_time'] : 900; // 15 minutes

        if ($attempts >= $max_attempts) {
            return new WP_Error(
                'too_many_attempts',
                sprintf(
                    /* translators: %d: lockout time in minutes */
                    __('Too many failed login attempts. Please try again in %d minutes.', 'spectrus-guard'),
                    ceil($lockout_time / 60)
                )
            );
        }

        return $user;
    }

    /**
     * Log failed login attempt
     *
     * @param string $username Attempted username.
     */
    public function log_failed_login($username)
    {
        $ip = $this->get_client_ip();
        $transient_key = 'sg_login_attempts_' . md5($ip);

        $attempts = get_transient($transient_key);
        if ($attempts === false) {
            $attempts = 0;
        }

        $attempts++;

        // Get lockout time from settings
        $settings = get_option('spectrus_shield_settings', array());
        $lockout_time = isset($settings['login_lockout_time']) ? (int) $settings['login_lockout_time'] : 900;

        set_transient($transient_key, $attempts, $lockout_time);

        // Log to file
        $log_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
        $log_file = $log_dir . '/login-attempts.log';

        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }

        $timestamp = current_time('Y-m-d H:i:s');
        $log_line = sprintf(
            "[%s] [FAILED_LOGIN] IP: %s | Username: %s | Attempt: %d\n",
            $timestamp,
            $ip,
            sanitize_user($username),
            $attempts
        );

        file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Clear login attempts on successful login
     *
     * @param string $username The username.
     */
    public function clear_login_attempts($username)
    {
        $ip = $this->get_client_ip();
        $transient_key = 'sg_login_attempts_' . md5($ip);
        delete_transient($transient_key);
    }

    /**
     * Hide author name in RSS feeds
     *
     * @param string $author_name Author display name.
     * @return string Modified author name.
     */
    public function hide_author_in_feed($author_name)
    {
        if (is_feed()) {
            return get_bloginfo('name');
        }
        return $author_name;
    }

    /**
     * Require authentication for REST API
     *
     * @param WP_Error|null|bool $result Error from previous callback, or null/bool.
     * @return WP_Error|null|bool
     */
    public function require_auth_for_api($result)
    {
        // Don't override existing errors
        if (is_wp_error($result)) {
            return $result;
        }

        // Allow logged-in users
        if (is_user_logged_in()) {
            return $result;
        }

        // Allow some public endpoints
        $allowed_routes = array(
            '/wp/v2/posts',
            '/wp/v2/pages',
            '/wp/v2/categories',
            '/wp/v2/tags',
            '/oembed/',
        );

        $current_route = $_SERVER['REQUEST_URI'] ?? '';
        foreach ($allowed_routes as $route) {
            if (strpos($current_route, $route) !== false) {
                return $result;
            }
        }

        return new WP_Error(
            'rest_not_logged_in',
            __('You must be logged in to access the REST API.', 'spectrus-guard'),
            array('status' => 401)
        );
    }

    /**
     * Get the real client IP securely
     *
     * @return string
     */
    private function get_client_ip()
    {
        return $this->getClientIpSecure($this->getTrustedProxiesFromSettings());
    }
}
