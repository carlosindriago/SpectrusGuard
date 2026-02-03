<?php
/**
 * SpectrusGuard Onboarding Controller
 *
 * Handles the first-run wizard experience and security status alerts.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Onboarding
 *
 * Manages the onboarding wizard and dashboard security alerts.
 */
class SG_Onboarding
{
    /**
     * Option key for wizard completion status
     */
    const OPTION_WIZARD_COMPLETE = 'spectrus_onboarding_complete';

    /**
     * Option key for showing wizard redirect
     */
    const OPTION_SHOW_WIZARD = 'spectrus_show_wizard';

    /**
     * Option key for dismissed alerts
     */
    const OPTION_DISMISSED_ALERTS = 'spectrus_dismissed_alerts';

    /**
     * Security presets configuration
     *
     * @var array
     */
    private $presets = array();

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->define_presets();
        $this->init_hooks();
    }

    /**
     * Initialize WordPress hooks
     */
    private function init_hooks()
    {
        // Check if we should redirect to wizard
        add_action('admin_init', array($this, 'maybe_redirect_to_wizard'));

        // Register wizard page
        add_action('admin_menu', array($this, 'register_wizard_page'));

        // AJAX handlers
        add_action('wp_ajax_sg_save_onboarding', array($this, 'ajax_save_onboarding'));
        add_action('wp_ajax_sg_skip_onboarding', array($this, 'ajax_skip_onboarding'));
        add_action('wp_ajax_sg_dismiss_alert', array($this, 'ajax_dismiss_alert'));

        // Enqueue assets on wizard page
        add_action('admin_enqueue_scripts', array($this, 'enqueue_wizard_assets'));
    }

    /**
     * Define security presets
     */
    private function define_presets()
    {
        $this->presets = array(
            'blog' => array(
                'name' => __('Personal Blog', 'spectrus-guard'),
                'icon' => '📝',
                'description' => __('Basic protection for blogs and personal sites', 'spectrus-guard'),
                'settings' => array(
                    'waf_enabled' => true,
                    'login_limit_enabled' => true,
                    'login_limit_attempts' => 5,
                    'hide_wp_version' => true,
                    'block_xmlrpc' => true,
                ),
            ),
            'ecommerce' => array(
                'name' => __('E-Commerce', 'spectrus-guard'),
                'icon' => '🛒',
                'description' => __('Enhanced security for online stores', 'spectrus-guard'),
                'settings' => array(
                    'waf_enabled' => true,
                    'login_limit_enabled' => true,
                    'login_limit_attempts' => 3,
                    'hide_wp_version' => true,
                    'block_xmlrpc' => true,
                    'enable_2fa_admins' => true,
                    'file_monitor_enabled' => true,
                    'security_headers_enabled' => true,
                ),
            ),
            'business' => array(
                'name' => __('Business / Agency', 'spectrus-guard'),
                'icon' => '🏢',
                'description' => __('Maximum protection for business sites', 'spectrus-guard'),
                'settings' => array(
                    'waf_enabled' => true,
                    'login_limit_enabled' => true,
                    'login_limit_attempts' => 3,
                    'hide_wp_version' => true,
                    'block_xmlrpc' => true,
                    'enable_2fa_admins' => true,
                    'file_monitor_enabled' => true,
                    'security_headers_enabled' => true,
                    'rate_limiting_enabled' => true,
                    'auto_scan_enabled' => true,
                    'custom_login_url' => 'sg-login',
                ),
            ),
        );
    }

    /**
     * Get security presets
     *
     * @return array
     */
    public function get_presets()
    {
        return $this->presets;
    }

    /**
     * Check if wizard is complete
     *
     * @return bool
     */
    public function is_wizard_complete()
    {
        return (bool) get_option(self::OPTION_WIZARD_COMPLETE, false);
    }

    /**
     * Mark wizard as complete
     */
    public function complete_wizard()
    {
        update_option(self::OPTION_WIZARD_COMPLETE, true);
        delete_option(self::OPTION_SHOW_WIZARD);
    }

    /**
     * Redirect to wizard on first run
     */
    public function maybe_redirect_to_wizard()
    {
        // Only for admins
        if (!current_user_can('manage_options')) {
            return;
        }

        // Check if we should show wizard
        if (!get_option(self::OPTION_SHOW_WIZARD)) {
            return;
        }

        // Don't redirect on wizard page itself
        if (isset($_GET['page']) && $_GET['page'] === 'spectrus-onboarding') {
            return;
        }

        // Don't redirect during AJAX
        if (wp_doing_ajax()) {
            return;
        }

        // Clear the flag and redirect
        delete_option(self::OPTION_SHOW_WIZARD);

        wp_safe_redirect(admin_url('admin.php?page=spectrus-onboarding'));
        exit;
    }

    /**
     * Register the wizard admin page (hidden from menu)
     */
    public function register_wizard_page()
    {
        add_submenu_page(
            null, // Hidden from menu
            __('SpectrusGuard Setup', 'spectrus-guard'),
            __('Setup Wizard', 'spectrus-guard'),
            'manage_options',
            'spectrus-onboarding',
            array($this, 'render_wizard_page')
        );
    }

    /**
     * Enqueue wizard assets
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_wizard_assets($hook)
    {
        if ($hook !== 'admin_page_spectrus-onboarding') {
            return;
        }

        // Wizard CSS
        wp_enqueue_style(
            'sg-onboarding',
            SG_PLUGIN_URL . 'assets/css/onboarding.css',
            array(),
            SG_VERSION
        );

        // Wizard JS
        wp_enqueue_script(
            'sg-onboarding',
            SG_PLUGIN_URL . 'assets/js/onboarding.js',
            array('jquery'),
            SG_VERSION,
            true
        );

        wp_localize_script('sg-onboarding', 'sgOnboarding', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sg_onboarding_nonce'),
            'dashboardUrl' => admin_url('admin.php?page=spectrus-guard'),
            'presets' => $this->presets,
            'strings' => array(
                'saving' => __('Applying settings...', 'spectrus-guard'),
                'success' => __('Settings saved!', 'spectrus-guard'),
                'error' => __('An error occurred', 'spectrus-guard'),
            ),
        ));
    }

    /**
     * Render the wizard page
     */
    public function render_wizard_page()
    {
        include SG_PLUGIN_DIR . 'includes/admin/views/onboarding/wizard.php';
    }

    /**
     * AJAX: Save onboarding settings
     */
    public function ajax_save_onboarding()
    {
        check_ajax_referer('sg_onboarding_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $preset = isset($_POST['preset']) ? sanitize_key($_POST['preset']) : '';
        $custom_settings = isset($_POST['settings']) ? $_POST['settings'] : array();

        // Get current settings
        $settings = get_option('spectrus_shield_settings', array());

        // Apply preset or custom settings
        if ($preset && isset($this->presets[$preset])) {
            $settings = array_merge($settings, $this->presets[$preset]['settings']);
        } elseif (!empty($custom_settings)) {
            foreach ($custom_settings as $key => $value) {
                $settings[sanitize_key($key)] = $this->sanitize_setting($value);
            }
        }

        // Save settings
        update_option('spectrus_shield_settings', $settings);

        // Mark wizard as complete
        $this->complete_wizard();

        wp_send_json_success(array(
            'message' => __('Security settings applied successfully!', 'spectrus-guard'),
            'redirect' => admin_url('admin.php?page=spectrus-guard&onboarding=complete'),
        ));
    }

    /**
     * AJAX: Skip onboarding
     */
    public function ajax_skip_onboarding()
    {
        check_ajax_referer('sg_onboarding_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $remind_later = isset($_POST['remind_later']) && $_POST['remind_later'] === 'true';

        if ($remind_later) {
            // Set reminder for later (7 days)
            update_option('spectrus_remind_onboarding', time() + (7 * DAY_IN_SECONDS));
        } else {
            // Mark as complete (skipped)
            $this->complete_wizard();
        }

        delete_option(self::OPTION_SHOW_WIZARD);

        wp_send_json_success(array(
            'redirect' => admin_url('admin.php?page=spectrus-guard'),
        ));
    }

    /**
     * AJAX: Dismiss security alert
     */
    public function ajax_dismiss_alert()
    {
        check_ajax_referer('sg_onboarding_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $alert_id = isset($_POST['alert_id']) ? sanitize_key($_POST['alert_id']) : '';
        $never_remind = isset($_POST['never_remind']) && $_POST['never_remind'] === 'true';

        if (empty($alert_id)) {
            wp_send_json_error(array('message' => 'Invalid alert'));
        }

        $dismissed = get_option(self::OPTION_DISMISSED_ALERTS, array());

        if ($never_remind) {
            // Permanently dismissed
            $dismissed[$alert_id] = 'permanent';
        } else {
            // Remind in 24 hours
            $dismissed[$alert_id] = time() + DAY_IN_SECONDS;
        }

        update_option(self::OPTION_DISMISSED_ALERTS, $dismissed);

        wp_send_json_success();
    }

    /**
     * Get active security alerts for dashboard
     *
     * @return array
     */
    public function get_security_alerts()
    {
        $alerts = array();
        $settings = get_option('spectrus_shield_settings', array());
        $dismissed = get_option(self::OPTION_DISMISSED_ALERTS, array());

        // Define critical features to check
        $critical_features = array(
            'waf_enabled' => array(
                'id' => 'waf_disabled',
                'title' => __('WAF Protection Disabled', 'spectrus-guard'),
                'message' => __('Your site is vulnerable to SQL injection, XSS, and other attacks. Enable the Web Application Firewall for protection.', 'spectrus-guard'),
                'type' => 'critical',
                'action_url' => admin_url('admin.php?page=spectrus-settings#firewall'),
                'action_text' => __('Enable Now', 'spectrus-guard'),
            ),
            'login_limit_enabled' => array(
                'id' => 'login_limit_disabled',
                'title' => __('Login Protection Disabled', 'spectrus-guard'),
                'message' => __('Brute force attacks can compromise admin accounts. Enable login attempt limiting.', 'spectrus-guard'),
                'type' => 'warning',
                'action_url' => admin_url('admin.php?page=spectrus-settings#login'),
                'action_text' => __('Enable', 'spectrus-guard'),
            ),
        );

        foreach ($critical_features as $setting_key => $alert) {
            // Check if feature is disabled
            if (empty($settings[$setting_key])) {
                // Check if alert is dismissed
                if (isset($dismissed[$alert['id']])) {
                    if ($dismissed[$alert['id']] === 'permanent') {
                        continue; // Permanently dismissed
                    }
                    if (is_numeric($dismissed[$alert['id']]) && $dismissed[$alert['id']] > time()) {
                        continue; // Temporarily dismissed
                    }
                }

                $alerts[] = $alert;
            }
        }

        return $alerts;
    }

    /**
     * Sanitize a setting value
     *
     * @param mixed $value Value to sanitize.
     * @return mixed
     */
    private function sanitize_setting($value)
    {
        if (is_array($value)) {
            return array_map(array($this, 'sanitize_setting'), $value);
        }

        if ($value === 'true' || $value === '1') {
            return true;
        }
        if ($value === 'false' || $value === '0') {
            return false;
        }
        if (is_numeric($value)) {
            return (int) $value;
        }

        return sanitize_text_field($value);
    }

    /**
     * Reset wizard (for testing or re-running)
     */
    public function reset_wizard()
    {
        delete_option(self::OPTION_WIZARD_COMPLETE);
        update_option(self::OPTION_SHOW_WIZARD, true);
    }
}
