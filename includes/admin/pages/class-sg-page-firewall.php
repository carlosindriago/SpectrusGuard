<?php
/**
 * Page Controller: Firewall & Geo-Defense
 */
if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Firewall
{
    private $loader;

    public function __construct($loader)
    {
        $this->loader = $loader;

        // AJAX Firewall
        add_action('wp_ajax_sg_clear_logs', array($this, 'ajax_clear_logs'));
        add_action('wp_ajax_sg_whitelist_ip', array($this, 'ajax_whitelist_ip'));

        // AJAX Geo
        add_action('wp_ajax_sg_download_geoip_db', array($this, 'ajax_download_geoip_db'));
        add_action('wp_ajax_sg_update_geoip_db', array($this, 'ajax_update_geoip_db'));
        add_action('wp_ajax_sg_update_tor_nodes', array($this, 'ajax_update_tor_nodes'));
        add_action('wp_ajax_sg_upload_mmdb', array($this, 'ajax_upload_mmdb'));
        add_action('wp_ajax_sg_get_download_progress', array($this, 'ajax_get_download_progress'));
    }

    /**
     * Render the firewall page (WAF + Geo + Logs)
     */
    public function render()
    {
        $settings = $this->loader->get_settings();
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'waf';
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🔥</span>
                    <?php esc_html_e('Firewall & Geo-Defense', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <?php if ($active_tab === 'waf'): ?>
                        <button type="submit" form="sg-waf-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Rules', 'spectrus-guard'); ?>
                        </button>
                    <?php elseif ($active_tab === 'geo'): ?>
                        <button type="submit" form="sg-geo-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Geo-Defense', 'spectrus-guard'); ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Tabs Navigation -->
            <h2 class="nav-tab-wrapper" style="margin-bottom: 20px; border-bottom: 1px solid #334155;">
                <a href="?page=spectrus-guard-firewall&tab=waf"
                    class="nav-tab <?php echo $active_tab == 'waf' ? 'nav-tab-active' : ''; ?>">
                    🛡️
                    <?php esc_html_e('WAF Rules', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-firewall&tab=geo"
                    class="nav-tab <?php echo $active_tab == 'geo' ? 'nav-tab-active' : ''; ?>">
                    🌍
                    <?php esc_html_e('Geo-Defense', 'spectrus-guard'); ?>
                </a>
            </h2>

            <?php if ($active_tab === 'waf'): ?>
                <!-- WAF Rules Tab -->
                <form method="post" action="options.php" id="sg-waf-form">
                    <?php settings_fields('spectrus_shield_settings_group'); ?>
                    <input type="hidden" name="spectrus_shield_settings[form_context]" value="waf">

                    <div class="sg-main-layout">
                        <div class="sg-content-column"
                            style="grid-column: span 12; display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">

                            <!-- Firewall Core -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2>
                                        <?php esc_html_e('Firewall Core', 'spectrus-guard'); ?>
                                    </h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label class="sg-control-label">
                                                <?php esc_html_e('Web Application Firewall', 'spectrus-guard'); ?>
                                            </label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Active protection against SQLi, XSS, and RCE attacks.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[waf_enabled]" value="1" <?php checked($settings['waf_enabled'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label class="sg-control-label">
                                                <?php esc_html_e('Attack Logging', 'spectrus-guard'); ?>
                                            </label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Keep a record of all blocked malicious attempts.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[log_attacks]" value="1" <?php checked($settings['log_attacks'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="sg-control-group" style="display: block;">
                                        <label class="sg-control-label" style="margin-bottom: 8px;">
                                            <?php esc_html_e('Rescue Key', 'spectrus-guard'); ?>
                                        </label>
                                        <input type="text" name="spectrus_shield_settings[rescue_key]"
                                            value="<?php echo esc_attr($settings['rescue_key'] ?? ''); ?>" class="sg-input-text"
                                            placeholder="e.g. secret-bypass-key">
                                        <p class="sg-control-desc" style="margin-top: 8px;">
                                            <?php esc_html_e('Use ?rescue_key=YOUR_KEY to bypass the WAF if you get locked out.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <!-- Access Control (IP Whitelist) -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2>
                                        <?php esc_html_e('Access Control', 'spectrus-guard'); ?>
                                    </h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group" style="display: block;">
                                        <label class="sg-control-label" style="margin-bottom: 8px;">
                                            <?php esc_html_e('IP Whitelist', 'spectrus-guard'); ?>
                                        </label>
                                        <textarea name="spectrus_shield_settings[whitelist_ips_text]" rows="5"
                                            class="sg-textarea code"><?php echo esc_textarea(implode("\n", $settings['whitelist_ips'] ?? array())); ?></textarea>
                                        <p class="sg-control-desc" style="margin-top: 8px;">
                                            <?php esc_html_e('One IP per line. These IPs bypass WAF rules.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </form>

            <?php elseif ($active_tab === 'geo'): ?>
                <!-- Geo-Defense Tab -->
                <form method="post" action="options.php" id="sg-geo-form">
                    <?php
                    settings_fields('spectrus_shield_settings_group');
                    // Ensure the view is loaded with context
                    $geo_view = SG_PLUGIN_DIR . 'includes/hardening/views/settings-geo.php';
                    if (file_exists($geo_view)) {
                        include $geo_view;
                    } else {
                        echo '<p class="sg-alert error">Geo view not found.</p>';
                    }
                    ?>
                </form>

            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * AJAX: Clear logs
     */
    public function ajax_clear_logs()
    {
        check_ajax_referer('spectrus_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $logger = $this->loader->get_logger();
        if ($logger) {
            $logger->clear_logs();
        }

        // Reset stats
        update_option('spectrus_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => array(),
        ));

        wp_send_json_success(array('message' => __('Logs cleared successfully.', 'spectrus-guard')));
    }

    /**
     * AJAX: Whitelist current IP
     */
    public function ajax_whitelist_ip()
    {
        check_ajax_referer('spectrus_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $firewall = $this->loader->get_firewall();
        if ($firewall) {
            $ip = $firewall->get_client_ip();
            $firewall->add_to_whitelist($ip);
            wp_send_json_success(array(
                'message' => sprintf(
                    /* translators: %s: IP address */
                    __('IP %s has been whitelisted.', 'spectrus-guard'),
                    $ip
                )
            ));
        }

        wp_send_json_error(array('message' => __('Could not whitelist IP.', 'spectrus-guard')));
    }

    /**
     * AJAX: Download GeoIP database
     */
    public function ajax_download_geoip_db()
    {
        check_ajax_referer('sg_nonce', '_ajax_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'spectrus-guard'));
        }

        $license_key = isset($_POST['license_key']) ? sanitize_text_field($_POST['license_key']) : '';

        if (empty($license_key)) {
            wp_send_json_error(__('License key is required', 'spectrus-guard'));
        }

        // Save license key (obfuscated)
        update_option('spectrus_maxmind_license', base64_encode($license_key));

        if (!class_exists('SG_Geo_Updater')) {
            wp_send_json_error(__('Geo updater not available', 'spectrus-guard'));
        }

        $updater = new SG_Geo_Updater();
        $result = $updater->download_database($license_key);

        if (is_wp_error($result)) {
            wp_send_json_error($result->get_error_message());
        }

        $db_path = $updater->get_database_path();
        $file_size = file_exists($db_path) ? size_format(filesize($db_path)) : '';

        wp_send_json_success(array(
            'message' => __('GeoIP database downloaded successfully', 'spectrus-guard'),
            'size' => $file_size,
            'last_updated' => date_i18n(get_option('date_format') . ' ' . get_option('time_format'))
        ));
    }

    /**
     * AJAX: Update GeoIP database
     */
    public function ajax_update_geoip_db()
    {
        check_ajax_referer('sg_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'spectrus-guard'));
        }

        $license_key = get_option('spectrus_maxmind_license');
        if (empty($license_key)) {
            wp_send_json_error(__('MaxMind license key not configured', 'spectrus-guard'));
        }

        if (!class_exists('SG_Geo_Updater')) {
            wp_send_json_error(__('Geo updater not available', 'spectrus-guard'));
        }

        $updater = new SG_Geo_Updater();
        $result = $updater->download_database(base64_decode($license_key));

        if (is_wp_error($result)) {
            wp_send_json_error($result->get_error_message());
        }

        wp_send_json_success(array(
            'message' => __('GeoIP database updated successfully', 'spectrus-guard'),
            'file_size' => size_format(filesize($updater->get_database_path())),
            'last_updated' => date_i18n(get_option('date_format') . ' ' . get_option('time_format'))
        ));
    }

    /**
     * AJAX: Update Tor exit nodes list
     */
    public function ajax_update_tor_nodes()
    {
        check_ajax_referer('sg_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'spectrus-guard'));
        }

        if (!class_exists('SG_Geo_Engine')) {
            wp_send_json_error(__('Geo engine not available', 'spectrus-guard'));
        }

        $engine = new SG_Geo_Engine();
        $result = $engine->update_tor_nodes();

        if (is_wp_error($result)) {
            wp_send_json_error($result->get_error_message());
        }

        $tor_nodes = $engine->get_tor_nodes();
        $count = is_array($tor_nodes) ? count($tor_nodes) : 0;

        wp_send_json_success(array(
            'message' => sprintf(__('Tor exit nodes updated: %d nodes', 'spectrus-guard'), $count),
            'count' => $count,
            'last_updated' => date_i18n(get_option('date_format') . ' ' . get_option('time_format'))
        ));
    }

    /**
     * AJAX: Manual MMDB Upload
     */
    public function ajax_upload_mmdb()
    {
        check_ajax_referer('sg_nonce', '_ajax_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'spectrus-guard'));
        }

        if (empty($_FILES['mmdb_file'])) {
            wp_send_json_error(__('No file uploaded', 'spectrus-guard'));
        }

        $file = $_FILES['mmdb_file'];

        // Validate file extension
        if (pathinfo($file['name'], PATHINFO_EXTENSION) !== 'mmdb') {
            wp_send_json_error(__('Invalid file type. Must be .mmdb', 'spectrus-guard'));
        }

        // Create directory
        $upload_dir = wp_upload_dir();
        $geoip_dir = $upload_dir['basedir'] . '/spectrus-guard/geoip';

        if (!file_exists($geoip_dir)) {
            wp_mkdir_p($geoip_dir);
            file_put_contents($geoip_dir . '/.htaccess', "Order deny,allow\nDeny from all");
            file_put_contents($geoip_dir . '/index.php', '<?php // Silence is golden');
        }

        $destination = $geoip_dir . '/GeoLite2-Country.mmdb';

        // Move uploaded file
        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            wp_send_json_error(__('Failed to save file', 'spectrus-guard'));
        }

        // Verify it's a valid MMDB
        if (filesize($destination) < 1000) {
            @unlink($destination);
            wp_send_json_error(__('File appears to be invalid or corrupted', 'spectrus-guard'));
        }

        update_option('sg_geoip_last_update', time());

        wp_send_json_success(array(
            'message' => __('Database uploaded successfully!', 'spectrus-guard'),
            'size' => size_format(filesize($destination)),
            'last_updated' => date_i18n(get_option('date_format') . ' ' . get_option('time_format'))
        ));
    }

    /**
     * AJAX: Get download progress
     */
    public function ajax_get_download_progress()
    {
        check_ajax_referer('sg_nonce', '_ajax_nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Permission denied', 'spectrus-guard'));
        }

        $upload_dir = wp_upload_dir();
        $progress_file = $upload_dir['basedir'] . '/spectrus-guard/geoip/download_progress.json';

        if (!file_exists($progress_file)) {
            wp_send_json_success(array(
                'status' => 'waiting',
                'progress' => 0,
                'message' => __('Waiting to start...', 'spectrus-guard')
            ));
            return;
        }

        $progress = json_decode(file_get_contents($progress_file), true);

        if (!$progress) {
            wp_send_json_success(array(
                'status' => 'waiting',
                'progress' => 0,
                'message' => __('Initializing...', 'spectrus-guard')
            ));
            return;
        }

        wp_send_json_success($progress);
    }
}
