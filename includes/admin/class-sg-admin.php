<?php
/**
 * SpectrusGuard Admin Dashboard (Refactored Router)
 *
 * Admin interface for managing SpectrusGuard settings, viewing logs,
 * and monitoring security status.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load Page Controllers
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-dashboard.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-firewall.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-scanner.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-quarantine.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-whitelist.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-hardening.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-hardening.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-settings.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-settings.php';
require_once SG_PLUGIN_DIR . 'includes/admin/pages/class-sg-page-results.php';
require_once SG_PLUGIN_DIR . 'includes/admin/class-sg-ajax.php';

/**
 * Class SG_Admin
 *
 * Admin dashboard and settings management (Router).
 */
class SG_Admin
{

    /**
     * Loader instance
     *
     * @var SG_Loader
     */
    private $loader;

    /**
     * Admin page hook suffix
     *
     * @var string
     */
    private $page_hook;

    /**
     * Page Controllers
     */
    private $page_dashboard;
    private $page_firewall;
    private $page_scanner;
    private $page_quarantine;
    private $page_whitelist;
    private $page_hardening;
    private $page_settings;
    private $page_results;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct(SG_Loader $loader)
    {
        $this->loader = $loader;

        // Initialize Page Controllers
        $this->page_dashboard = new SG_Page_Dashboard($loader);
        $this->page_firewall = new SG_Page_Firewall($loader);
        $this->page_scanner = new SG_Page_Scanner($loader);
        $this->page_quarantine = new SG_Page_Quarantine($loader);
        $this->page_whitelist = new SG_Page_Whitelist($loader);
        $this->page_hardening = new SG_Page_Hardening($loader);
        $this->page_settings = new SG_Page_Settings($loader);
        $this->page_results = new SG_Page_Results($loader);

        // Initialize AJAX Handler
        $this->ajax = new SG_Ajax();
        $this->ajax->init();

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
    }

    /**
     * Add admin menu pages
     */
    public function add_admin_menu()
    {
        // 1. Dashboard (Main Page)
        $this->page_hook = add_menu_page(
            __('SpectrusGuard Security', 'spectrus-guard'),
            __('SpectrusGuard', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard',
            array($this->page_dashboard, 'render'), // Delegate to Dashboard Controller
            'dashicons-shield',
            65
        );

        add_submenu_page(
            'spectrus-guard',
            __('Dashboard', 'spectrus-guard'),
            __('Dashboard', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard',
            array($this->page_dashboard, 'render') // Delegate to Dashboard Controller
        );

        // 2. Firewall (WAF + Geo + Logs)
        add_submenu_page(
            'spectrus-guard',
            __('Firewall', 'spectrus-guard'),
            __('Firewall', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-firewall',
            array($this->page_firewall, 'render') // Delegate to Firewall Controller
        );

        // 3. Scanner
        $scanner_hook = add_submenu_page(
            'spectrus-guard',
            __('Security Scanner', 'spectrus-guard'),
            __('Scanner', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-scanner',
            array($this->page_scanner, 'render') // Delegate to Scanner Controller
        );

        // 3.5. Quarantine (Vault)
        add_submenu_page(
            'spectrus-guard',
            __('Quarantine Vault', 'spectrus-guard'),
            __('Quarantine', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-quarantine',
            array($this->page_quarantine, 'render') // Delegate to Quarantine Controller
        );

        // 3.6. Whitelist Management
        add_submenu_page(
            'spectrus-guard',
            __('Whitelist Management', 'spectrus-guard'),
            __('Whitelist', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-whitelist',
            array($this->page_whitelist, 'render') // Delegate to Whitelist Controller
        );

        // 4. Hardening (Cloak + Login + Stealth)
        add_submenu_page(
            'spectrus-guard',
            __('Hardening', 'spectrus-guard'),
            __('Hardening', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-hardening',
            array($this->page_hardening, 'render') // Delegate to Hardening Controller
        );

        // 5. Settings (General + License)
        add_submenu_page(
            'spectrus-guard',
            __('Settings', 'spectrus-guard'),
            __('Settings', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-settings',
            array($this->page_settings, 'render') // Delegate to Settings Controller
        );

        // 6. Results Page (Hidden from menu, linked from Scanner)
        $results_hook = add_submenu_page(
            null, // NULL parent sends it to a hidden page
            __('Scan Results', 'spectrus-guard'),
            __('Scan Results', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-results',
            array($this->page_results, 'render')
        );

        // Localize Script for Scanner & Results
        add_action("admin_print_scripts-$scanner_hook", array($this, 'enqueue_admin_scripts'));
        add_action("admin_print_scripts-$results_hook", array($this, 'enqueue_admin_scripts'));
    }

    public function enqueue_admin_scripts()
    {
        wp_localize_script('spectrus-guard-admin', 'sg_ajax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('spectrus_guard_nonce')
        ));
    }

    /**
     * Register settings
     */
    public function register_settings()
    {
        register_setting(
            'spectrus_shield_settings_group',
            'spectrus_shield_settings',
            array($this, 'sanitize_settings')
        );
        register_setting('spectrus_cloak_settings', 'sg_cloak_active', 'absint');
    }

    /**
     * Sanitize settings before saving
     *
     * @param array $input Raw settings input.
     * @return array Sanitized settings.
     */
    public function sanitize_settings($input)
    {
        // 1. Get existing settings to act as base (preserve values from other tabs)
        $current_settings = get_option('spectrus_shield_settings', array());
        $sanitized = $current_settings;

        // 2. Determine Context
        $context = isset($input['form_context']) ? $input['form_context'] : 'general';

        if ($context === 'waf') {
            // --- WAF TAB ---
            $sanitized['waf_enabled'] = !empty($input['waf_enabled']);
            $sanitized['log_attacks'] = !empty($input['log_attacks']);

            if (isset($input['rescue_key'])) {
                $sanitized['rescue_key'] = sanitize_text_field($input['rescue_key']);
            }

            if (isset($input['whitelist_ips_text'])) {
                $lines = explode("\n", $input['whitelist_ips_text']);
                $ips = array();
                foreach ($lines as $line) {
                    $ip = trim($line);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        $ips[] = $ip;
                    }
                }
                $sanitized['whitelist_ips'] = $ips;
            }

        } elseif ($context === 'stealth') {
            // --- STEALTH TAB ---
            $sanitized['block_xmlrpc'] = !empty($input['block_xmlrpc']);
            $sanitized['hide_wp_version'] = !empty($input['hide_wp_version']);
            $sanitized['protect_api'] = !empty($input['protect_api']);

        } elseif ($context === 'login') {
            // --- LOGIN TAB (Legacy Check) ---
            $sanitized['hide_login'] = !empty($input['hide_login']);

            if (isset($input['login_slug'])) {
                $sanitized['login_slug'] = sanitize_title($input['login_slug']);
            }
            if (isset($input['max_login_attempts'])) {
                $sanitized['max_login_attempts'] = absint($input['max_login_attempts']);
            }
            if (isset($input['login_lockout_time'])) {
                // If it's the new form, input is minutes so * 60. If legacy... assumes logic handles it.
                // The new login-security view sends minutes and expects seconds in DB.
                $sanitized['login_lockout_time'] = max(1, absint($input['login_lockout_time'])) * 60;
            }

            // 2FA Policies
            $sanitized['enforce_2fa_global'] = !empty($input['enforce_2fa_global']);
            $sanitized['enforce_2fa_grace'] = absint($input['enforce_2fa_grace']);

            if (isset($input['enforce_2fa_roles']) && is_array($input['enforce_2fa_roles'])) {
                $sanitized['enforce_2fa_roles'] = array_map('sanitize_text_field', $input['enforce_2fa_roles']);
            } else {
                $sanitized['enforce_2fa_roles'] = [];
            }


        } elseif ($context === 'cloak') {
            // --- CLOAK TAB ---
            $sanitized['url_cloaking_enabled'] = !empty($input['url_cloaking_enabled']);

            // Rescue key logic (if present)
            if (isset($input['rescue_key'])) {
                $sanitized['rescue_key'] = sanitize_text_field($input['rescue_key']);
            }

            if (isset($input['login_slug'])) {
                $sanitized['login_slug'] = sanitize_title($input['login_slug']);
            }

            // Handle Plugin Mapping
            if (isset($_POST['sg_map_real']) && isset($_POST['sg_map_fake'])) {
                $clean_map = [];
                $reals = $_POST['sg_map_real'];
                $fakes = $_POST['sg_map_fake'];

                if (is_array($reals) && is_array($fakes)) {
                    for ($i = 0; $i < count($reals); $i++) {
                        $r = sanitize_text_field($reals[$i]);
                        $f = sanitize_title($fakes[$i]);
                        if ($r && $f) {
                            $clean_map[$r] = $f;
                        }
                    }
                }
                update_option('sg_cloak_plugin_map', $clean_map);
            }

        } elseif ($context === 'geo') {
            // --- GEO DEFENSE TAB ---
            $sanitized['geo_block_tor'] = !empty($input['geo_block_tor']);

            if (isset($input['geo_action'])) {
                $sanitized['geo_action'] = sanitize_text_field($input['geo_action']);
            }

            if (isset($input['geo_blocked_countries']) && is_array($input['geo_blocked_countries'])) {
                $clean_countries = array();
                foreach ($input['geo_blocked_countries'] as $code) {
                    $clean_countries[] = sanitize_text_field($code);
                }
                $sanitized['geo_blocked_countries'] = $clean_countries;
            } else {
                // Sent empty means cleared (only if in geo context)
                $sanitized['geo_blocked_countries'] = array();
            }

        }

        return $sanitized;
    }

}
