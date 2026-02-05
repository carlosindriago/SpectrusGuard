<?php
/**
 * Plugin Name:       SpectrusGuard Enterprise: AI-Powered Security Suite
 * Plugin URI:        https://github.com/carlosindriago/SpectrusGuard/
 * Description:       Enterprise-grade security with WAF, Geo-Blocking, and AI-powered User and Entity Behavior Analytics (UEBA). Detects threats that traditional security misses.
 * Version:           3.0.6
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Carlos Indriago
 * Author URI:        https://github.com/carlosindriago/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       spectrus-guard
 * Domain Path:       /languages
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Plugin Constants
 */
define('SG_VERSION', '3.0.7');
define('SG_PLUGIN_FILE', __FILE__);
define('SG_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SG_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SG_PLUGIN_BASENAME', plugin_basename(__FILE__));
define('SG_MIN_PHP_VERSION', '8.1');
define('SG_MIN_WP_VERSION', '6.4');

/**
 * MU-Plugin paths
 */
define('SG_MU_SOURCE', SG_PLUGIN_DIR . 'mu-loader/spectrus-waf.php');
define('SG_MU_DESTINATION', WP_CONTENT_DIR . '/mu-plugins/spectrus-waf.php');

/**
 * Check minimum requirements before loading
 */
function sg_check_requirements()
{
    $errors = array();

    // Check PHP version
    if (version_compare(PHP_VERSION, SG_MIN_PHP_VERSION, '<')) {
        $errors[] = sprintf(
            /* translators: 1: Current PHP version 2: Required PHP version */
            __('SpectrusGuard requires PHP %2$s or higher. Your server is running PHP %1$s.', 'spectrus-guard'),
            PHP_VERSION,
            SG_MIN_PHP_VERSION
        );
    }

    // Check WordPress version
    global $wp_version;
    if (version_compare($wp_version, SG_MIN_WP_VERSION, '<')) {
        $errors[] = sprintf(
            /* translators: 1: Current WP version 2: Required WP version */
            __('SpectrusGuard requires WordPress %2$s or higher. You are running WordPress %1$s.', 'spectrus-guard'),
            $wp_version,
            SG_MIN_WP_VERSION
        );
    }

    return $errors;
}

/**
 * Display admin notice for requirement errors
 */
function sg_requirements_notice()
{
    $errors = sg_check_requirements();
    if (empty($errors)) {
        return;
    }

    echo '<div class="notice notice-error"><p><strong>SpectrusGuard:</strong></p><ul>';
    foreach ($errors as $error) {
        echo '<li>' . esc_html($error) . '</li>';
    }
    echo '</ul></div>';
}

/**
 * Create whitelist database table
 */
function sg_create_whitelist_table()
{
    global $wpdb;

    $table_name = $wpdb->prefix . 'spectrus_whitelist';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        file_path varchar(512) NOT NULL,
        file_hash varchar(64) NOT NULL,
        whitelisted_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
        whitelisted_by bigint(20) NOT NULL,
        notes text DEFAULT NULL,
        PRIMARY KEY  (id),
        KEY file_path (file_path),
        KEY file_hash (file_hash),
        KEY whitelisted_by (whitelisted_by)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Plugin activation hook
 */
function sg_activate()
{
    // Check requirements
    $errors = sg_check_requirements();
    if (!empty($errors)) {
        wp_die(
            esc_html(implode('<br>', $errors)),
            esc_html__('Plugin Activation Error', 'spectrus-guard'),
            array('back_link' => true)
        );
    }

    // Create mu-plugins directory if it doesn't exist
    $mu_plugins_dir = WP_CONTENT_DIR . '/mu-plugins';
    if (!file_exists($mu_plugins_dir)) {
        wp_mkdir_p($mu_plugins_dir);
    }

    // Copy the MU-Plugin file
    if (file_exists(SG_MU_SOURCE)) {
        // Remove old version if exists
        if (file_exists(SG_MU_DESTINATION)) {
            unlink(SG_MU_DESTINATION);
        }

        // Copy new version
        $copied = copy(SG_MU_SOURCE, SG_MU_DESTINATION);

        if (!$copied) {
            wp_die(
                esc_html__('SpectrusGuard could not install the MU-Plugin. Please check file permissions for wp-content/mu-plugins/', 'spectrus-guard'),
                esc_html__('Plugin Activation Error', 'spectrus-guard'),
                array('back_link' => true)
            );
        }
    }

    // Create logs directory with protection
    $logs_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
    if (!file_exists($logs_dir)) {
        wp_mkdir_p($logs_dir);

        // Protect logs directory with .htaccess
        $htaccess_content = "Order deny,allow\nDeny from all";
        file_put_contents($logs_dir . '/.htaccess', $htaccess_content);

        // Also add index.php for extra protection
        file_put_contents($logs_dir . '/index.php', '<?php // Silence is golden');
    }

    // Set default options
    $default_options = array(
        'waf_enabled' => true,
        'rescue_key' => wp_generate_password(32, false),
        'whitelist_ips' => array(),
        'log_attacks' => true,
        'block_xmlrpc' => true,
        'hide_wp_version' => true,
        'protect_api' => true,
    );

    add_option('spectrus_shield_settings', $default_options);
    add_option('spectrus_shield_version', SG_VERSION);

    // Create whitelist database table
    sg_create_whitelist_table();

    // Flush rewrite rules
    flush_rewrite_rules();

    // Trigger onboarding wizard for new installations
    if (!get_option('spectrus_onboarding_complete')) {
        update_option('spectrus_show_wizard', true);
    }
}
register_activation_hook(__FILE__, 'sg_activate');

/**
 * Check and auto-update MU-Plugin if source version is newer
 * 
 * This runs on admin_init to ensure MU-Plugin stays in sync with the plugin.
 * Uses file hash comparison to detect changes.
 */
function sg_maybe_update_mu_plugin()
{
    // Only run in admin context and not during AJAX or activation
    if (!is_admin() || wp_doing_ajax() || (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }

    // Check if source file exists
    if (!file_exists(SG_MU_SOURCE)) {
        return;
    }

    // Get current source hash
    $source_hash = md5_file(SG_MU_SOURCE);

    // Get stored hash of last deployed version
    $deployed_hash = get_option('sg_mu_plugin_hash', '');

    // If destination doesn't exist, force update
    $needs_update = !file_exists(SG_MU_DESTINATION);

    // Check if hashes differ (source was updated)
    if (!$needs_update && $source_hash !== $deployed_hash) {
        $needs_update = true;
    }

    if ($needs_update) {
        // Create mu-plugins directory if needed
        $mu_plugins_dir = WP_CONTENT_DIR . '/mu-plugins';
        if (!file_exists($mu_plugins_dir)) {
            wp_mkdir_p($mu_plugins_dir);
        }

        // Remove old version
        if (file_exists(SG_MU_DESTINATION)) {
            @unlink(SG_MU_DESTINATION);
        }

        // Copy new version
        $copied = @copy(SG_MU_SOURCE, SG_MU_DESTINATION);

        if ($copied) {
            // Store the new hash
            update_option('sg_mu_plugin_hash', $source_hash);

            // Log the update (optional admin notice)
            add_action('admin_notices', function () {
                echo '<div class="notice notice-success is-dismissible">';
                echo '<p><strong>SpectrusGuard:</strong> ' . esc_html__('MU-Plugin was automatically updated to the latest version.', 'spectrus-guard') . '</p>';
                echo '</div>';
            });
        }
    }
}
add_action('admin_init', 'sg_maybe_update_mu_plugin');

/**
 * Plugin deactivation hook
 */
function sg_deactivate()
{
    // Remove MU-Plugin
    if (file_exists(SG_MU_DESTINATION)) {
        unlink(SG_MU_DESTINATION);
    }

    // Clear scheduled events if any
    wp_clear_scheduled_hook('spectrus_shield_daily_scan');

    // Flush rewrite rules
    flush_rewrite_rules();
}
register_deactivation_hook(__FILE__, 'sg_deactivate');

/**
 * Initialize the plugin
 */
function sg_init()
{
    // Check requirements
    $errors = sg_check_requirements();
    if (!empty($errors)) {
        add_action('admin_notices', 'sg_requirements_notice');
        return;
    }

    // Load text domain for translations
    load_plugin_textdomain('spectrus-guard', false, dirname(SG_PLUGIN_BASENAME) . '/languages');

    // Initialize Ghost Rescue (Secure Mode)
    require_once SG_PLUGIN_DIR . 'includes/hardening/class-sg-ghost-rescue.php';
    $rescue = new SG_Ghost_Rescue();
    // Hook early to ensure we can intercept before other init logic, but after pluggables are loaded
    add_action('init', array($rescue, 'run'), 0);

    // Load the main loader class
    require_once SG_PLUGIN_DIR . 'includes/class-sg-loader.php';

    // Initialize the plugin
    SG_Loader::get_instance();
}
add_action('plugins_loaded', 'sg_init');

/**
 * Add settings link on plugin page
 */
function sg_plugin_action_links($links)
{
    $settings_link = sprintf(
        '<a href="%s">%s</a>',
        admin_url('admin.php?page=spectrus-guard'),
        esc_html__('Settings', 'spectrus-guard')
    );
    array_unshift($links, $settings_link);
    return $links;
}
add_filter('plugin_action_links_' . SG_PLUGIN_BASENAME, 'sg_plugin_action_links');
