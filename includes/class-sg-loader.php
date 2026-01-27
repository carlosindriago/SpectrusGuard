<?php
/**
 * SpectrusGuard Loader - Singleton Orchestrator
 *
 * Main orchestrator class that loads and initializes all modules.
 * Implements the Singleton pattern to ensure single instance.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Loader
 *
 * Singleton orchestrator for the SpectrusGuard plugin.
 */
class SG_Loader
{

    /**
     * Single instance of the class
     *
     * @var SG_Loader|null
     */
    private static $instance = null;

    /**
     * Plugin settings from database
     *
     * @var array
     */
    private $settings = array();

    /**
     * Logger instance
     *
     * @var SG_Logger|null
     */
    private $logger = null;

    /**
     * Firewall instance
     *
     * @var SG_Firewall|null
     */
    private $firewall = null;

    /**
     * Scanner instance
     *
     * @var SG_Scanner|null
     */
    private $scanner = null;

    /**
     * Get the singleton instance
     *
     * @return SG_Loader
     */
    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor to prevent direct instantiation
     */
    private function __construct()
    {
        $this->load_settings();
        $this->load_dependencies();
        $this->init_modules();
        $this->register_hooks();
    }

    /**
     * Prevent cloning of the instance
     */
    private function __clone()
    {
    }

    /**
     * Prevent unserializing of the instance
     */
    public function __wakeup()
    {
        throw new \Exception('Cannot unserialize singleton');
    }

    /**
     * Load plugin settings from database
     */
    private function load_settings()
    {
        $defaults = array(
            'waf_enabled' => true,
            'rescue_key' => '',
            'whitelist_ips' => array(),
            'log_attacks' => true,
            'block_xmlrpc' => true,
            'hide_wp_version' => true,
            'protect_api' => true,
            'hide_login' => false,
            'login_slug' => 'sg-login',
            'url_cloaking_enabled' => false,
        );

        $this->settings = wp_parse_args(
            get_option('spectrus_shield_settings', array()),
            $defaults
        );
    }

    /**
     * Load required dependency files
     */
    private function load_dependencies()
    {
        // Core classes
        require_once SG_PLUGIN_DIR . 'includes/class-sg-logger.php';

        // WAF Module
        require_once SG_PLUGIN_DIR . 'includes/waf/class-sg-firewall.php';

        // Hardening Module (Sprint 2 - load if exists)
        $hardening_file = SG_PLUGIN_DIR . 'includes/hardening/class-sg-api-guard.php';
        if (file_exists($hardening_file)) {
            require_once $hardening_file;
        }

        $stealth_file = SG_PLUGIN_DIR . 'includes/hardening/class-sg-stealth.php';
        if (file_exists($stealth_file)) {
            require_once $stealth_file;
        }

        $url_cloaker_file = SG_PLUGIN_DIR . 'includes/hardening/class-sg-url-cloaker.php';
        if (file_exists($url_cloaker_file)) {
            require_once $url_cloaker_file;
        }

        $cloak_engine_file = SG_PLUGIN_DIR . 'includes/hardening/class-sg-cloak-engine.php';
        if (file_exists($cloak_engine_file)) {
            require_once $cloak_engine_file;
            if (class_exists('Spectrus_Cloak_Engine')) {
                new Spectrus_Cloak_Engine();
            }
        }

        // Auth Module (Spectrus Sentinel 2FA)
        $totp_file = SG_PLUGIN_DIR . 'includes/auth/class-sg-totp-engine.php';
        if (file_exists($totp_file)) {
            require_once $totp_file;
        }

        $auth_handler_file = SG_PLUGIN_DIR . 'includes/auth/class-sg-2fa-handler.php';
        if (file_exists($auth_handler_file)) {
            require_once $auth_handler_file;
        }

        // Scanner Module (Sprint 3 - load if exists)
        $scanner_file = SG_PLUGIN_DIR . 'includes/scanner/class-sg-scanner.php';
        if (file_exists($scanner_file)) {
            require_once $scanner_file;
        }

        // Admin (load only in admin context)
        if (is_admin()) {
            $admin_file = SG_PLUGIN_DIR . 'includes/admin/class-sg-admin.php';
            if (file_exists($admin_file)) {
                require_once $admin_file;
            }
        }
    }

    /**
     * Initialize all modules based on settings
     */
    private function init_modules()
    {
        // Initialize Logger (always active)
        $this->logger = new SG_Logger();

        // Initialize Firewall (if enabled)
        if ($this->get_setting('waf_enabled')) {
            $this->firewall = new SG_Firewall($this->logger);
        }

        // Initialize Hardening modules (Sprint 2)
        if (class_exists('SG_API_Guard') && $this->get_setting('protect_api')) {
            new SG_API_Guard();
        }

        if (class_exists('SG_Stealth') && $this->get_setting('hide_wp_version')) {
            new SG_Stealth($this->settings);
        }

        // Initialize URL Cloaker (if enabled)
        if (class_exists('SG_URL_Cloaker') && $this->get_setting('url_cloaking_enabled')) {
            new SG_URL_Cloaker($this->settings);
        }

        // Initialize 2FA Handler (Always active if class exists, individual user check is inside)
        if (class_exists('Spectrus_2FA_Handler')) {
            new Spectrus_2FA_Handler();
        }

        // Initialize Scanner (Sprint 3)
        if (class_exists('SG_Scanner')) {
            $this->scanner = new SG_Scanner();
        }

        // Initialize Admin (if in admin context)
        if (is_admin() && class_exists('SG_Admin')) {
            new SG_Admin($this);
        }
    }

    /**
     * Register WordPress hooks
     */
    private function register_hooks()
    {
        // Register REST API endpoints
        add_action('rest_api_init', array($this, 'register_rest_routes'));

        // Admin assets
        if (is_admin()) {
            add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        }
    }

    /**
     * Register REST API routes
     */
    public function register_rest_routes()
    {
        register_rest_route(
            'spectrus-guard/v1',
            '/stats',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'get_stats_endpoint'),
                'permission_callback' => function () {
                    return current_user_can('manage_options');
                },
            )
        );
    }

    /**
     * REST endpoint: Get attack statistics
     *
     * @return WP_REST_Response
     */
    public function get_stats_endpoint()
    {
        $stats = get_option('spectrus_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'last_attack' => null,
        ));

        return rest_ensure_response($stats);
    }

    /**
     * Enqueue admin CSS and JS
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_admin_assets($hook)
    {
        // Only load on our admin pages
        if (strpos($hook, 'spectrus-guard') === false) {
            return;
        }

        wp_enqueue_style(
            'spectrus-guard-admin',
            SG_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            SG_VERSION
        );

        // Enqueue Chart.js
        wp_enqueue_script(
            'chart-js',
            'https://cdn.jsdelivr.net/npm/chart.js',
            array(),
            '3.9.1',
            true
        );

        wp_enqueue_script(
            'spectrus-guard-admin',
            SG_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery', 'chart-js'),
            SG_VERSION,
            true
        );

        wp_localize_script(
            'spectrus-guard-admin',
            'SpectrusGuard',
            array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('spectrus_shield_nonce'),
                'i18n' => array(
                    'scanning' => __('Scanning...', 'spectrus-guard'),
                    'complete' => __('Scan Complete', 'spectrus-guard'),
                    'error' => __('An error occurred', 'spectrus-guard'),
                ),
            )
        );
    }

    /**
     * Get a specific setting value
     *
     * @param string $key     Setting key.
     * @param mixed  $default Default value if setting not found.
     * @return mixed
     */
    public function get_setting($key, $default = null)
    {
        return isset($this->settings[$key]) ? $this->settings[$key] : $default;
    }

    /**
     * Get all settings
     *
     * @return array
     */
    public function get_settings()
    {
        return $this->settings;
    }

    /**
     * Update a setting
     *
     * @param string $key   Setting key.
     * @param mixed  $value Setting value.
     * @return bool
     */
    public function update_setting($key, $value)
    {
        $this->settings[$key] = $value;
        return update_option('spectrus_shield_settings', $this->settings);
    }

    /**
     * Update multiple settings at once
     *
     * @param array $new_settings Array of settings to update.
     * @return bool
     */
    public function update_settings($new_settings)
    {
        $this->settings = wp_parse_args($new_settings, $this->settings);
        return update_option('spectrus_shield_settings', $this->settings);
    }

    /**
     * Get the logger instance
     *
     * @return SG_Logger
     */
    public function get_logger()
    {
        return $this->logger;
    }

    /**
     * Get the firewall instance
     *
     * @return SG_Firewall|null
     */
    public function get_firewall()
    {
        return $this->firewall;
    }

    /**
     * Get the scanner instance
     *
     * @return SG_Scanner|null
     */
    public function get_scanner()
    {
        return $this->scanner;
    }
}
