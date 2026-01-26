<?php
/**
 * Plugin Name:       GhostShield: Advanced WAF & Stealth Security Suite
 * Plugin URI:        https://github.com/yourusername/ghost-shield
 * Description:       Sistema de seguridad integral que intercepta ataques antes de que toquen tu web y camufla tu sitio para que los hackers ni siquiera sepan que usas WordPress.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            Carlos Developer
 * Author URI:        https://yoursite.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       ghost-shield
 * Domain Path:       /languages
 *
 * @package GhostShield
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin Constants
 */
define( 'GS_VERSION', '1.0.0' );
define( 'GS_PLUGIN_FILE', __FILE__ );
define( 'GS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'GS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'GS_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'GS_MIN_PHP_VERSION', '7.4' );
define( 'GS_MIN_WP_VERSION', '5.8' );

/**
 * MU-Plugin paths
 */
define( 'GS_MU_SOURCE', GS_PLUGIN_DIR . 'mu-loader/ghost-waf.php' );
define( 'GS_MU_DESTINATION', WP_CONTENT_DIR . '/mu-plugins/ghost-waf.php' );

/**
 * Check minimum requirements before loading
 */
function gs_check_requirements() {
    $errors = array();

    // Check PHP version
    if ( version_compare( PHP_VERSION, GS_MIN_PHP_VERSION, '<' ) ) {
        $errors[] = sprintf(
            /* translators: 1: Current PHP version 2: Required PHP version */
            __( 'GhostShield requires PHP %2$s or higher. Your server is running PHP %1$s.', 'ghost-shield' ),
            PHP_VERSION,
            GS_MIN_PHP_VERSION
        );
    }

    // Check WordPress version
    global $wp_version;
    if ( version_compare( $wp_version, GS_MIN_WP_VERSION, '<' ) ) {
        $errors[] = sprintf(
            /* translators: 1: Current WP version 2: Required WP version */
            __( 'GhostShield requires WordPress %2$s or higher. You are running WordPress %1$s.', 'ghost-shield' ),
            $wp_version,
            GS_MIN_WP_VERSION
        );
    }

    return $errors;
}

/**
 * Display admin notice for requirement errors
 */
function gs_requirements_notice() {
    $errors = gs_check_requirements();
    if ( empty( $errors ) ) {
        return;
    }

    echo '<div class="notice notice-error"><p><strong>GhostShield:</strong></p><ul>';
    foreach ( $errors as $error ) {
        echo '<li>' . esc_html( $error ) . '</li>';
    }
    echo '</ul></div>';
}

/**
 * Plugin activation hook
 */
function gs_activate() {
    // Check requirements
    $errors = gs_check_requirements();
    if ( ! empty( $errors ) ) {
        wp_die(
            esc_html( implode( '<br>', $errors ) ),
            esc_html__( 'Plugin Activation Error', 'ghost-shield' ),
            array( 'back_link' => true )
        );
    }

    // Create mu-plugins directory if it doesn't exist
    $mu_plugins_dir = WP_CONTENT_DIR . '/mu-plugins';
    if ( ! file_exists( $mu_plugins_dir ) ) {
        wp_mkdir_p( $mu_plugins_dir );
    }

    // Copy the MU-Plugin file
    if ( file_exists( GS_MU_SOURCE ) ) {
        // Remove old version if exists
        if ( file_exists( GS_MU_DESTINATION ) ) {
            unlink( GS_MU_DESTINATION );
        }
        
        // Copy new version
        $copied = copy( GS_MU_SOURCE, GS_MU_DESTINATION );
        
        if ( ! $copied ) {
            wp_die(
                esc_html__( 'GhostShield could not install the MU-Plugin. Please check file permissions for wp-content/mu-plugins/', 'ghost-shield' ),
                esc_html__( 'Plugin Activation Error', 'ghost-shield' ),
                array( 'back_link' => true )
            );
        }
    }

    // Create logs directory with protection
    $logs_dir = WP_CONTENT_DIR . '/ghost-shield-logs';
    if ( ! file_exists( $logs_dir ) ) {
        wp_mkdir_p( $logs_dir );
        
        // Protect logs directory with .htaccess
        $htaccess_content = "Order deny,allow\nDeny from all";
        file_put_contents( $logs_dir . '/.htaccess', $htaccess_content );
        
        // Also add index.php for extra protection
        file_put_contents( $logs_dir . '/index.php', '<?php // Silence is golden' );
    }

    // Set default options
    $default_options = array(
        'waf_enabled'       => true,
        'rescue_key'        => wp_generate_password( 32, false ),
        'whitelist_ips'     => array(),
        'log_attacks'       => true,
        'block_xmlrpc'      => true,
        'hide_wp_version'   => true,
        'protect_api'       => true,
    );
    
    add_option( 'ghost_shield_settings', $default_options );
    add_option( 'ghost_shield_version', GS_VERSION );

    // Flush rewrite rules
    flush_rewrite_rules();
}
register_activation_hook( __FILE__, 'gs_activate' );

/**
 * Plugin deactivation hook
 */
function gs_deactivate() {
    // Remove MU-Plugin
    if ( file_exists( GS_MU_DESTINATION ) ) {
        unlink( GS_MU_DESTINATION );
    }

    // Clear scheduled events if any
    wp_clear_scheduled_hook( 'ghost_shield_daily_scan' );

    // Flush rewrite rules
    flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'gs_deactivate' );

/**
 * Initialize the plugin
 */
function gs_init() {
    // Check requirements
    $errors = gs_check_requirements();
    if ( ! empty( $errors ) ) {
        add_action( 'admin_notices', 'gs_requirements_notice' );
        return;
    }

    // Load text domain for translations
    load_plugin_textdomain( 'ghost-shield', false, dirname( GS_PLUGIN_BASENAME ) . '/languages' );

    // Load the main loader class
    require_once GS_PLUGIN_DIR . 'includes/class-gs-loader.php';

    // Initialize the plugin
    GS_Loader::get_instance();
}
add_action( 'plugins_loaded', 'gs_init' );

/**
 * Add settings link on plugin page
 */
function gs_plugin_action_links( $links ) {
    $settings_link = sprintf(
        '<a href="%s">%s</a>',
        admin_url( 'admin.php?page=ghost-shield' ),
        esc_html__( 'Settings', 'ghost-shield' )
    );
    array_unshift( $links, $settings_link );
    return $links;
}
add_filter( 'plugin_action_links_' . GS_PLUGIN_BASENAME, 'gs_plugin_action_links' );
