<?php
/**
 * SpectrusGuard Uninstall
 *
 * Fired when the plugin is uninstalled. Performs complete cleanup.
 *
 * @package SpectrusGuard
 */

// Exit if uninstall not called from WordPress
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Clean up all plugin data
 */
function sg_uninstall_cleanup()
{
    global $wpdb;

    // 1. Delete plugin options
    delete_option('spectrus_shield_settings');
    delete_option('spectrus_shield_version');
    delete_option('spectrus_shield_attack_stats');

    // For multisite, clean each site
    if (is_multisite()) {
        $sites = get_sites(array('fields' => 'ids'));
        foreach ($sites as $site_id) {
            switch_to_blog($site_id);
            delete_option('spectrus_shield_settings');
            delete_option('spectrus_shield_version');
            delete_option('spectrus_shield_attack_stats');
            restore_current_blog();
        }
    }

    // 2. Delete transients
    $wpdb->query(
        "DELETE FROM {$wpdb->options} 
         WHERE option_name LIKE '_transient_spectrus_shield_%' 
         OR option_name LIKE '_transient_timeout_spectrus_shield_%'"
    );

    // 3. Remove MU-Plugin file
    $mu_plugin_path = WP_CONTENT_DIR . '/mu-plugins/ghost-waf.php';
    if (file_exists($mu_plugin_path)) {
        unlink($mu_plugin_path);
    }

    // 4. Remove logs directory and all contents
    $logs_dir = WP_CONTENT_DIR . '/spectrus-guard-logs';
    if (is_dir($logs_dir)) {
        sg_delete_directory($logs_dir);
    }

    // 5. Drop custom tables if any (future-proofing)
    // $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}spectrus_shield_logs" );

    // 6. Clear any scheduled cron events
    wp_clear_scheduled_hook('spectrus_shield_daily_scan');
    wp_clear_scheduled_hook('spectrus_shield_hourly_cleanup');
}

/**
 * Recursively delete a directory and its contents
 *
 * @param string $dir Directory path to delete.
 * @return bool True on success, false on failure.
 */
function sg_delete_directory($dir)
{
    if (!is_dir($dir)) {
        return false;
    }

    $files = array_diff(scandir($dir), array('.', '..'));

    foreach ($files as $file) {
        $path = $dir . '/' . $file;
        if (is_dir($path)) {
            sg_delete_directory($path);
        } else {
            unlink($path);
        }
    }

    return rmdir($dir);
}

// Execute cleanup
sg_uninstall_cleanup();
