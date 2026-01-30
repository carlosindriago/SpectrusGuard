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
            // Geo-Blocking defaults (Sprint 9)
            'geo_blocked_countries' => array(),
            'geo_block_tor' => false,
            'geo_action' => '403',
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

        // Login Guard
        $login_guard_file = SG_PLUGIN_DIR . 'includes/hardening/class-sg-login-guard.php';
        if (file_exists($login_guard_file)) {
            require_once $login_guard_file;
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

        // Whitelist Module (load if exists)
        $whitelist_file = SG_PLUGIN_DIR . 'includes/whitelist/class-sg-whitelist.php';
        if (file_exists($whitelist_file)) {
            require_once $whitelist_file;
        }

        // Geo Module (Sprint 9 - Geo-Blocking & IP Intelligence)
        $geo_engine_file = SG_PLUGIN_DIR . 'includes/geo/class-sg-geo-engine.php';
        if (file_exists($geo_engine_file)) {
            require_once $geo_engine_file;
        }

        $geo_updater_file = SG_PLUGIN_DIR . 'includes/geo/class-sg-geo-updater.php';
        if (file_exists($geo_updater_file)) {
            require_once $geo_updater_file;
            // Schedule auto-updates for geo databases
            if (class_exists('SG_Geo_Updater')) {
                $updater = new SG_Geo_Updater();
                $updater->schedule_updates();
            }
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

        // Initialize Login Guard (Always active, internal logic handles enabling/disabling via option)
        if (class_exists('Spectrus_Login_Guard')) {
            new Spectrus_Login_Guard();
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

        // Debug: Log current hook
        error_log('SpectrusGuard: Current hook = ' . $hook);

        // Base styles (always load on our pages)
        wp_enqueue_style(
            'spectrus-guard-admin',
            SG_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            SG_VERSION
        );

        // Enqueue Chart.js for dashboard
        wp_enqueue_script(
            'chart-js',
            'https://cdn.jsdelivr.net/npm/chart.js',
            array(),
            '3.9.1',
            true
        );

        // Base admin script (always load on our pages)
        wp_enqueue_script(
            'spectrus-guard-admin',
            SG_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery', 'chart-js'),
            SG_VERSION,
            true
        );

        // Localize base script with common data
        wp_localize_script(
            'spectrus-guard-admin',
            'SpectrusGuard',
            array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('spectrus_guard_nonce'),
                'i18n' => array(
                    'copied' => __('Copied!', 'spectrus-guard'),
                    'error' => __('An error occurred', 'spectrus-guard'),
                    'confirm_clear' => __('Are you sure you want to clear all logs?', 'spectrus-guard'),
                ),
            )
        );

        // Scanner-specific assets (temporarily load on all plugin pages)
        // TODO: Restrict to scanner page only once hook is verified
        // if ($hook === 'toplevel_page_spectrus-guard-scanner' ||
        //     $hook === 'spectrus-guard_page_spectrus-guard-scanner') {
        if (strpos($hook, 'spectrus-guard') !== false) {

            wp_enqueue_script(
                'spectrus-guard-scanner',
                SG_PLUGIN_URL . 'assets/js/admin/scanner.js',
                array('jquery', 'spectrus-guard-admin'),
                SG_VERSION,
                true
            );

            // Localize scanner script with scanner-specific data
            // Note: We extend SpectrusGuard object, not replace it
            wp_localize_script(
                'spectrus-guard-scanner',
                'SpectrusGuardScanner',
                array(
                    'ajax_url' => admin_url('admin-ajax.php'),
                    'nonce' => wp_create_nonce('spectrus_guard_nonce'),
                    'i18n' => array(
                        // Scan-related strings
                        'scan_complete' => __('Scan Complete!', 'spectrus-guard'),
                        'scan_failed' => __('Scan failed', 'spectrus-guard'),
                        'scan_error' => __('An error occurred during scan.', 'spectrus-guard'),
                        'scanning' => __('Scanning...', 'spectrus-guard'),

                        // Results-related strings
                        'security_issues_found' => __('Security Issues Found', 'spectrus-guard'),
                        'we_found_issues' => __('We found', 'spectrus-guard'),
                        'potential_security_issues' => __('potential security issues', 'spectrus-guard'),
                        'site_clean' => __('Your Site is Clean!', 'spectrus-guard'),
                        'clean_scan_message' => __('Great news! The scan didn\'t detect any security issues. Your WordPress installation appears to be secure.', 'spectrus-guard'),
                        'what_we_checked' => __('What We Checked', 'spectrus-guard'),
                        'check_core' => __('WordPress core file integrity', 'spectrus-guard'),
                        'check_uploads' => __('PHP files in uploads directory', 'spectrus-guard'),
                        'check_suspicious' => __('Hidden and suspicious files', 'spectrus-guard'),
                        'check_permissions' => __('File permissions', 'spectrus-guard'),
                        'check_malware' => __('Known malware signatures', 'spectrus-guard'),
                        'what_threats_mean' => __('What These Threats Mean', 'spectrus-guard'),
                        'threats_detected' => __('threats detected', 'spectrus-guard'),
                        'recommended_actions' => __('Recommended Actions:', 'spectrus-guard'),
                        'affected_files' => __('Affected Files', 'spectrus-guard'),
                        'continue' => __('Continue', 'spectrus-guard'),
                        'return_scanner' => __('Return to Scanner', 'spectrus-guard'),

                        // Action buttons
                        'quarantine' => __('Quarantine', 'spectrus-guard'),
                        'delete' => __('Delete', 'spectrus-guard'),
                        'restore_core' => __('Restore from WordPress core', 'spectrus-guard'),

                        // Confirmation dialogs
                        'confirm_delete' => __('Are you sure you want to delete this file?', 'spectrus-guard'),
                        'confirm_quarantine' => __('Are you sure you want to quarantine this file?', 'spectrus-guard'),
                        'delete_failed' => __('Failed to delete file.', 'spectrus-guard'),
                        'quarantine_failed' => __('Failed to quarantine file.', 'spectrus-guard'),

                        // Threat explanations
                        'threat_core_title' => __('WordPress Core Integrity', 'spectrus-guard'),
                        'threat_core_desc' => __('Modified or missing WordPress core files can indicate a compromised installation. Attackers may alter core files to maintain persistent access, execute malicious code, or redirect traffic.', 'spectrus-guard'),
                        'threat_core_action1' => __('Restore the modified files from a clean WordPress installation', 'spectrus-guard'),
                        'threat_core_action2' => __('Check your WordPress version and update if needed', 'spectrus-guard'),
                        'threat_core_action3' => __('Review the file modifications to understand what was changed', 'spectrus-guard'),

                        'threat_uploads_title' => __('PHP Files in Uploads', 'spectrus-guard'),
                        'threat_uploads_desc' => __('PHP files in the uploads directory are almost always malicious. The uploads folder should only contain media files (images, videos, documents). Attackers upload PHP scripts here to create backdoors and maintain access to your site.', 'spectrus-guard'),
                        'threat_uploads_action1' => __('Delete all PHP files from the uploads directory', 'spectrus-guard'),
                        'threat_uploads_action2' => __('Review the file contents to understand what the backdoor does', 'spectrus-guard'),
                        'threat_uploads_action3' => __('Check your access logs to see how the file was uploaded', 'spectrus-guard'),

                        'threat_suspicious_title' => __('Suspicious Files', 'spectrus-guard'),
                        'threat_suspicious_desc' => __('Hidden files or files with dangerous permissions may indicate malware activity. Hidden files are often used to store malicious code, while world-writable permissions can allow attackers to modify files.', 'spectrus-guard'),
                        'threat_suspicious_action1' => __('Review hidden files to determine if they are legitimate', 'spectrus-guard'),
                        'threat_suspicious_action2' => __('Fix dangerous file permissions (should be 644 for files, 755 for directories)', 'spectrus-guard'),
                        'threat_suspicious_action3' => __('Delete files you don\'t recognize', 'spectrus-guard'),

                        'threat_malware_title' => __('Malware Detected', 'spectrus-guard'),
                        'threat_malware_desc' => __('Malware signatures were detected in your files. These patterns match known malicious code used by attackers for backdoors, shell access, data theft, spam campaigns, or cryptocurrency mining.', 'spectrus-guard'),
                        'threat_malware_action1' => __('Review the infected files and the malware patterns detected', 'spectrus-guard'),
                        'threat_malware_action2' => __('Delete or clean the infected files immediately', 'spectrus-guard'),
                        'threat_malware_action3' => __('Scan from a clean computer to detect malware on your local system', 'spectrus-guard'),
                        'threat_malware_action4' => __('Change all passwords (WordPress, FTP, database, hosting)', 'spectrus-guard'),

                        'threat_default_desc' => __('Potential security issue detected.', 'spectrus-guard'),
                        'threat_default_action' => __('Review the file and determine if it is legitimate', 'spectrus-guard'),
                    ),
                )
            );
        }

        // Quarantine & Whitelist page assets (temporarily load on all plugin pages until hook is verified)
        // TODO: Restrict to specific pages once hook is verified
        // Debug: Log current hook
        error_log('SpectrusGuard: Current hook = ' . $hook . ' (looking for: spectrus-guard_page_spectrus-guard-quarantine or spectrus-guard-whitelist)');

        if (strpos($hook, 'spectrus-guard') !== false) {
            wp_enqueue_script(
                'spectrus-guard-quarantine',
                SG_PLUGIN_URL . 'assets/js/admin/quarantine.js',
                array('jquery', 'spectrus-guard-admin'),
                SG_VERSION,
                true
            );

            wp_enqueue_script(
                'spectrus-guard-whitelist',
                SG_PLUGIN_URL . 'assets/js/admin/whitelist.js',
                array('jquery', 'spectrus-guard-admin'),
                SG_VERSION,
                true
            );
        }
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
