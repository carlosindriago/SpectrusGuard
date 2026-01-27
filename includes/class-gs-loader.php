<?php
/**
 * GhostShield Loader - Singleton Orchestrator
 *
 * Main orchestrator class that loads and initializes all modules.
 * Implements the Singleton pattern to ensure single instance.
 *
 * @package GhostShield
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class GS_Loader
 *
 * Singleton orchestrator for the GhostShield plugin.
 */
class GS_Loader
{

    /**
     * Single instance of the class
     *
     * @var GS_Loader|null
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
     * @var GS_Logger|null
     */
    private $logger = null;

    /**
     * Firewall instance
     *
     * @var GS_Firewall|null
     */
    private $firewall = null;

    /**
     * Scanner instance
     *
     * @var GS_Scanner|null
     */
    private $scanner = null;

    /**
     * Get the singleton instance
     *
     * @return GS_Loader
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
            'login_slug' => 'gs-login',
            'url_cloaking_enabled' => false,
        );

        $this->settings = wp_parse_args(
            get_option('ghost_shield_settings', array()),
            $defaults
        );
    }

    /**
     * Load required dependency files
     */
    private function load_dependencies()
    {
        // Core classes
        require_once GS_PLUGIN_DIR . 'includes/class-gs-logger.php';

        // WAF Module
        require_once GS_PLUGIN_DIR . 'includes/waf/class-gs-firewall.php';

        // Hardening Module (Sprint 2 - load if exists)
        $hardening_file = GS_PLUGIN_DIR . 'includes/hardening/class-gs-api-guard.php';
        if (file_exists($hardening_file)) {
            require_once $hardening_file;
        }

        $stealth_file = GS_PLUGIN_DIR . 'includes/hardening/class-gs-stealth.php';
        if (file_exists($stealth_file)) {
            require_once $stealth_file;
        }

        $url_cloaker_file = GS_PLUGIN_DIR . 'includes/hardening/class-gs-url-cloaker.php';
        if (file_exists($url_cloaker_file)) {
            require_once $url_cloaker_file;
        }

        // Scanner Module (Sprint 3 - load if exists)
        $scanner_file = GS_PLUGIN_DIR . 'includes/scanner/class-gs-scanner.php';
        if (file_exists($scanner_file)) {
            require_once $scanner_file;
        }

        // Admin (load only in admin context)
        if (is_admin()) {
            $admin_file = GS_PLUGIN_DIR . 'includes/admin/class-gs-admin.php';
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
        $this->logger = new GS_Logger();

        // Initialize Firewall (if enabled)
        if ($this->get_setting('waf_enabled')) {
            $this->firewall = new GS_Firewall($this->logger);
        }

        // Initialize Hardening modules (Sprint 2)
        if (class_exists('GS_API_Guard') && $this->get_setting('protect_api')) {
            new GS_API_Guard();
        }

        if (class_exists('GS_Stealth') && $this->get_setting('hide_wp_version')) {
            new GS_Stealth($this->settings);
        }

        // Initialize URL Cloaker (if enabled)
        if (class_exists('GS_URL_Cloaker') && $this->get_setting('url_cloaking_enabled')) {
            new GS_URL_Cloaker($this->settings);
        }

        // Initialize Scanner (Sprint 3)
        if (class_exists('GS_Scanner')) {
            $this->scanner = new GS_Scanner();
        }

        // Initialize Admin (if in admin context)
        if (is_admin() && class_exists('GS_Admin')) {
            new GS_Admin($this);
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
            'ghost-shield/v1',
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
        $stats = get_option('ghost_shield_attack_stats', array(
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
        if (strpos($hook, 'ghost-shield') === false) {
            return;
        }

        wp_enqueue_style(
            'ghost-shield-admin',
            GS_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            GS_VERSION
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
            'ghost-shield-admin',
            GS_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery', 'chart-js'),
            GS_VERSION,
            true
        );

        wp_localize_script(
            'ghost-shield-admin',
            'GhostShield',
            array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('ghost_shield_nonce'),
                'i18n' => array(
                    'scanning' => __('Scanning...', 'ghost-shield'),
                    'complete' => __('Scan Complete', 'ghost-shield'),
                    'error' => __('An error occurred', 'ghost-shield'),
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
        return update_option('ghost_shield_settings', $this->settings);
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
        return update_option('ghost_shield_settings', $this->settings);
    }

    /**
     * Get the logger instance
     *
     * @return GS_Logger
     */
    public function get_logger()
    {
        return $this->logger;
    }

    /**
     * Get the firewall instance
     *
     * @return GS_Firewall|null
     */
    public function get_firewall()
    {
        return $this->firewall;
    }

    /**
     * Get the scanner instance
     *
     * @return GS_Scanner|null
     */
    public function get_scanner()
    {
        return $this->scanner;
    }
}
