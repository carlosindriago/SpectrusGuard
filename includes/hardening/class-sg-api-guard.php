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
     * API hardening settings
     *
     * @var array
     */
    private array $apiSettings;

    /**
     * Default whitelist for public API routes
     *
     * @var array
     */
    private const DEFAULT_WHITELIST = [
        '/wp/v2/posts',
        '/wp/v2/pages',
        '/wp/v2/categories',
        '/wp/v2/tags',
        '/wp/v2/media',
        '/wp/v2/comments',
        '/oembed/',
        '/contact-form-7/',
        '/wc/',
        '/wc-blocks/',
        '/jetpack/',
    ];

    /**
     * Constructor
     */
    public function __construct()
    {
        // Load API hardening settings
        $this->loadApiSettings();

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

        // 6. REST API Hardening (configurable)
        if ($this->apiSettings['require_auth']) {
            add_filter('rest_authentication_errors', array($this, 'require_auth_for_api'));
        }

        // 7. Hide API index/discovery
        if ($this->apiSettings['hide_index']) {
            add_filter('rest_index', array($this, 'hide_rest_index'));
        }

        // 8. Custom REST API prefix - NOTE: This filter only changes URL generation.
        // The actual route registration happens in rest_api_init which runs once.
        // For a full custom prefix to work, it must be set BEFORE WordPress initializes REST.
        // This is handled via mu-plugin or very early hook. Here we set it for URL generation.
        if (!empty($this->apiSettings['custom_prefix'])) {
            add_filter('rest_url_prefix', array($this, 'custom_rest_prefix'));

            // Also redirect old wp-json to 404 for non-admins (stealth)
            add_action('parse_request', array($this, 'block_old_rest_prefix'));
        }
    }

    /**
     * Block access to old /wp-json/ endpoint when custom prefix is enabled
     * Only blocks for non-admin users to maintain admin access
     *
     * @param WP_Query $wp WordPress query object
     */
    public function block_old_rest_prefix($wp): void
    {
        $request_path = trim($_SERVER['REQUEST_URI'] ?? '', '/');
        $customPrefix = $this->apiSettings['custom_prefix'] ?? '';

        // Check if request is to old wp-json endpoint
        if (strpos($request_path, 'wp-json') === 0 && !empty($customPrefix)) {
            // Allow admins to still access for debugging
            if (is_user_logged_in() && current_user_can('manage_options')) {
                return;
            }

            // Return 404 for everyone else
            status_header(404);
            nocache_headers();
            include(get_query_template('404'));
            exit;
        }
    }

    /**
     * Load API hardening settings
     */
    private function loadApiSettings(): void
    {
        $settings = get_option('spectrus_shield_settings', []);
        $apiDefaults = [
            'require_auth' => false,
            'hide_index' => true,
            'custom_prefix' => '',
            'whitelist' => [],
        ];

        $this->apiSettings = wp_parse_args(
            $settings['api_hardening'] ?? [],
            $apiDefaults
        );
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

        // Build whitelist from defaults + custom
        $whitelist = array_merge(
            self::DEFAULT_WHITELIST,
            $this->apiSettings['whitelist'] ?? []
        );

        // Check current route against whitelist
        $currentRoute = $_SERVER['REQUEST_URI'] ?? '';
        foreach ($whitelist as $route) {
            if (strpos($currentRoute, $route) !== false) {
                return $result;
            }
        }

        // Block with informative error
        return new WP_Error(
            'rest_forbidden',
            __('SpectrusGuard: REST API access requires authentication.', 'spectrus-guard'),
            ['status' => 401]
        );
    }

    /**
     * Hide REST API index/discovery for non-authenticated users
     *
     * @param WP_REST_Response $response Response object.
     * @return WP_REST_Response Modified response.
     */
    public function hide_rest_index($response)
    {
        // Admins can see everything
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return $response;
        }

        // For non-admins, return minimal info
        $data = $response->get_data();

        // Remove sensitive information
        unset($data['routes']);
        unset($data['namespaces']);
        unset($data['authentication']);

        // Keep only basic info
        $data['name'] = get_bloginfo('name');
        $data['description'] = get_bloginfo('description');
        $data['url'] = home_url();
        $data['_links'] = [];

        $response->set_data($data);

        return $response;
    }

    /**
     * Custom REST API URL prefix
     *
     * @param string $prefix Default prefix (wp-json).
     * @return string Custom prefix.
     */
    public function custom_rest_prefix(string $prefix): string
    {
        $customPrefix = $this->apiSettings['custom_prefix'] ?? '';

        if (!empty($customPrefix)) {
            // Sanitize prefix (alphanumeric, dashes, slashes only)
            return preg_replace('/[^a-zA-Z0-9\-\/]/', '', $customPrefix);
        }

        return $prefix;
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

    /**
     * Known plugins with their REST API namespaces
     * Used for auto-detection feature in UI
     *
     * @var array
     */
    private const KNOWN_PLUGIN_NAMESPACES = [
        'woocommerce/woocommerce.php' => [
            'name' => 'WooCommerce',
            'routes' => ['wc/v3', 'wc/v2', 'wc-blocks/', 'wc-analytics/'],
        ],
        'contact-form-7/wp-contact-form-7.php' => [
            'name' => 'Contact Form 7',
            'routes' => ['contact-form-7/v1'],
        ],
        'jetpack/jetpack.php' => [
            'name' => 'Jetpack',
            'routes' => ['jetpack/v4', 'wpcom/v2'],
        ],
        'elementor/elementor.php' => [
            'name' => 'Elementor',
            'routes' => ['elementor/v1'],
        ],
        'elementor-pro/elementor-pro.php' => [
            'name' => 'Elementor Pro',
            'routes' => ['elementor-pro/v1'],
        ],
        'wpforms-lite/wpforms.php' => [
            'name' => 'WPForms',
            'routes' => ['wpforms/v1'],
        ],
        'wpforms/wpforms.php' => [
            'name' => 'WPForms Pro',
            'routes' => ['wpforms/v1'],
        ],
        'mailchimp-for-wp/mailchimp-for-wp.php' => [
            'name' => 'Mailchimp for WP',
            'routes' => ['mailchimp/v1'],
        ],
        'yoast-seo-premium/wp-seo-premium.php' => [
            'name' => 'Yoast SEO Premium',
            'routes' => ['yoast/v1'],
        ],
        'wordpress-seo/wp-seo.php' => [
            'name' => 'Yoast SEO',
            'routes' => ['yoast/v1'],
        ],
        'woocommerce-gateway-stripe/woocommerce-gateway-stripe.php' => [
            'name' => 'Stripe for WooCommerce',
            'routes' => ['wc-stripe/v1'],
        ],
        'woocommerce-payments/woocommerce-payments.php' => [
            'name' => 'WooCommerce Payments',
            'routes' => ['wc-payments/v1'],
        ],
        'gravityforms/gravityforms.php' => [
            'name' => 'Gravity Forms',
            'routes' => ['gf/v2'],
        ],
        'learnpress/learnpress.php' => [
            'name' => 'LearnPress',
            'routes' => ['learnpress/v1'],
        ],
        'buddypress/bp-loader.php' => [
            'name' => 'BuddyPress',
            'routes' => ['buddypress/v1'],
        ],
        'bbpress/bbpress.php' => [
            'name' => 'bbPress',
            'routes' => ['bbp/v1'],
        ],
        'easy-digital-downloads/easy-digital-downloads.php' => [
            'name' => 'Easy Digital Downloads',
            'routes' => ['edd/v1'],
        ],
        'the-events-calendar/the-events-calendar.php' => [
            'name' => 'The Events Calendar',
            'routes' => ['tribe/events/v1'],
        ],
    ];

    /**
     * Get detected plugins that use REST API
     * Returns array of plugins with their API routes for auto-whitelist
     *
     * @return array Array of detected plugins with their routes
     */
    public static function get_detected_api_plugins(): array
    {
        if (!function_exists('is_plugin_active')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $detected = [];

        foreach (self::KNOWN_PLUGIN_NAMESPACES as $pluginFile => $pluginData) {
            if (is_plugin_active($pluginFile)) {
                $detected[$pluginFile] = [
                    'name' => $pluginData['name'],
                    'routes' => $pluginData['routes'],
                    'active' => true,
                ];
            }
        }

        // Also add WordPress core routes that are essential
        $detected['wordpress-core'] = [
            'name' => 'WordPress Core',
            'routes' => [
                'wp/v2/posts',
                'wp/v2/pages',
                'wp/v2/categories',
                'wp/v2/tags',
                'wp/v2/media',
                'wp/v2/comments',
                'oembed/',
                'wp-site-health/v1',
            ],
            'active' => true,
            'core' => true,
        ];

        return $detected;
    }

    /**
     * Get recommended whitelist based on active plugins
     *
     * @return array Array of route prefixes to whitelist
     */
    public static function get_recommended_whitelist(): array
    {
        $plugins = self::get_detected_api_plugins();
        $routes = [];

        foreach ($plugins as $plugin) {
            $routes = array_merge($routes, $plugin['routes']);
        }

        return array_unique($routes);
    }

    /**
     * Build full whitelist combining defaults, detected plugins, and user custom
     *
     * @param array $userWhitelist User-defined whitelist
     * @return array Complete whitelist
     */
    public function build_full_whitelist(array $userWhitelist = []): array
    {
        // Start with hardcoded defaults
        $whitelist = self::DEFAULT_WHITELIST;

        // Add detected plugin routes
        $detected = self::get_detected_api_plugins();
        foreach ($detected as $plugin) {
            $whitelist = array_merge($whitelist, $plugin['routes']);
        }

        // Add user manual whitelist
        if (!empty($userWhitelist)) {
            $whitelist = array_merge($whitelist, array_filter($userWhitelist));
        }

        // Clean and return unique entries
        return array_unique(array_filter(array_map('trim', $whitelist)));
    }

    /**
     * Check if a route is whitelisted
     *
     * @param string $route The REST route to check
     * @return bool True if whitelisted
     */
    public function is_route_whitelisted(string $route): bool
    {
        $userWhitelist = $this->apiSettings['whitelist'] ?? [];
        $fullWhitelist = $this->build_full_whitelist($userWhitelist);

        foreach ($fullWhitelist as $allowedRoute) {
            if (stripos($route, $allowedRoute) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * AJAX handler for getting detected plugins (used by UI)
     */
    public static function ajax_get_detected_plugins(): void
    {
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'spectrus-guard'));
        }

        $plugins = self::get_detected_api_plugins();
        $recommended = self::get_recommended_whitelist();

        wp_send_json_success([
            'plugins' => $plugins,
            'recommended' => $recommended,
        ]);
    }
}

// Register AJAX handler
add_action('wp_ajax_sg_get_detected_api_plugins', ['SG_API_Guard', 'ajax_get_detected_plugins']);
