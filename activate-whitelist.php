<?php
/**
 * Temporary script to create whitelist table
 *
 * Run this script once to create the whitelist database table.
 * Delete after execution.
 */

// Load WordPress
require_once('/home/carlos/Local Sites/site/app/public/wp-load.php');

// Check if user is logged in
if (!is_user_logged_in()) {
    die('Access denied. Please log in to WordPress first.');
}

// Check if user has admin capabilities
if (!current_user_can('manage_options')) {
    die('Access denied. You need admin privileges.');
}

// Create the table
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

// Check if table was created
$table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'");

if ($table_exists) {
    echo "<h2>✓ Success!</h2>";
    echo "<p>Whitelist table <code>$table_name</code> created successfully.</p>";
    echo "<p><strong>IMPORTANT:</strong> Delete this file from your server for security.</p>";
    echo "<p><a href='" . admin_url('admin.php?page=spectrus-guard-whitelist') . "' class='button button-primary'>Go to Whitelist Page</a></p>";
} else {
    echo "<h2>✗ Error</h2>";
    echo "<p>Failed to create table. Please check database permissions.</p>";
}
