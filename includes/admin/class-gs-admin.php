<?php
/**
 * GhostShield Admin Dashboard
 *
 * Admin interface for managing GhostShield settings, viewing logs,
 * and monitoring security status.
 *
 * @package GhostShield
 * @since   1.0.0
 */

// Prevent direct access
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class GS_Admin
 *
 * Admin dashboard and settings management.
 */
class GS_Admin {

    /**
     * Loader instance
     *
     * @var GS_Loader
     */
    private $loader;

    /**
     * Admin page hook suffix
     *
     * @var string
     */
    private $page_hook;

    /**
     * Constructor
     *
     * @param GS_Loader $loader Loader instance.
     */
    public function __construct( GS_Loader $loader ) {
        $this->loader = $loader;

        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'wp_ajax_gs_get_stats', array( $this, 'ajax_get_stats' ) );
        add_action( 'wp_ajax_gs_clear_logs', array( $this, 'ajax_clear_logs' ) );
        add_action( 'wp_ajax_gs_whitelist_ip', array( $this, 'ajax_whitelist_ip' ) );
        add_action( 'wp_ajax_gs_run_scan', array( $this, 'ajax_run_scan' ) );
    }

    /**
     * Add admin menu pages
     */
    public function add_admin_menu() {
        $this->page_hook = add_menu_page(
            __( 'GhostShield Security', 'ghost-shield' ),
            __( 'GhostShield', 'ghost-shield' ),
            'manage_options',
            'ghost-shield',
            array( $this, 'render_dashboard' ),
            'dashicons-shield',
            65
        );

        add_submenu_page(
            'ghost-shield',
            __( 'Dashboard', 'ghost-shield' ),
            __( 'Dashboard', 'ghost-shield' ),
            'manage_options',
            'ghost-shield',
            array( $this, 'render_dashboard' )
        );

        add_submenu_page(
            'ghost-shield',
            __( 'Firewall Logs', 'ghost-shield' ),
            __( 'Firewall Logs', 'ghost-shield' ),
            'manage_options',
            'ghost-shield-logs',
            array( $this, 'render_logs_page' )
        );

        add_submenu_page(
            'ghost-shield',
            __( 'Settings', 'ghost-shield' ),
            __( 'Settings', 'ghost-shield' ),
            'manage_options',
            'ghost-shield-settings',
            array( $this, 'render_settings_page' )
        );

        add_submenu_page(
            'ghost-shield',
            __( 'Security Scanner', 'ghost-shield' ),
            __( 'Scanner', 'ghost-shield' ),
            'manage_options',
            'ghost-shield-scanner',
            array( $this, 'render_scanner_page' )
        );
    }

    /**
     * Register settings
     */
    public function register_settings() {
        register_setting(
            'ghost_shield_settings_group',
            'ghost_shield_settings',
            array( $this, 'sanitize_settings' )
        );
    }

    /**
     * Sanitize settings before saving
     *
     * @param array $input Raw settings input.
     * @return array Sanitized settings.
     */
    public function sanitize_settings( $input ) {
        $sanitized = array();

        // Boolean fields
        $boolean_fields = array(
            'waf_enabled',
            'log_attacks',
            'block_xmlrpc',
            'hide_wp_version',
            'protect_api',
            'hide_login',
            'block_author_pages',
        );

        foreach ( $boolean_fields as $field ) {
            $sanitized[ $field ] = ! empty( $input[ $field ] );
        }

        // Text fields
        if ( isset( $input['rescue_key'] ) ) {
            $sanitized['rescue_key'] = sanitize_text_field( $input['rescue_key'] );
        }

        if ( isset( $input['login_slug'] ) ) {
            $sanitized['login_slug'] = sanitize_title( $input['login_slug'] );
        }

        // IP Whitelist (text area to array)
        if ( isset( $input['whitelist_ips_text'] ) ) {
            $lines = explode( "\n", $input['whitelist_ips_text'] );
            $ips   = array();
            foreach ( $lines as $line ) {
                $ip = trim( $line );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    $ips[] = $ip;
                }
            }
            $sanitized['whitelist_ips'] = $ips;
        }

        // Numeric fields
        if ( isset( $input['max_login_attempts'] ) ) {
            $sanitized['max_login_attempts'] = absint( $input['max_login_attempts'] );
        }

        if ( isset( $input['login_lockout_time'] ) ) {
            $sanitized['login_lockout_time'] = absint( $input['login_lockout_time'] );
        }

        return $sanitized;
    }

    /**
     * Render the main dashboard page
     */
    public function render_dashboard() {
        $stats = get_option( 'ghost_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked'  => 0,
            'xss_blocked'   => 0,
            'rce_blocked'   => 0,
            'traversal_blocked' => 0,
            'last_attack'   => null,
            'daily_stats'   => array(),
        ) );

        $settings = $this->loader->get_settings();
        ?>
        <div class="wrap gs-dashboard">
            <h1>
                <span class="gs-logo">🛡️</span>
                <?php esc_html_e( 'GhostShield Security Dashboard', 'ghost-shield' ); ?>
            </h1>

            <div class="gs-dashboard-grid">
                <!-- Status Card -->
                <div class="gs-card gs-status-card">
                    <div class="gs-card-header">
                        <h2><?php esc_html_e( 'Security Status', 'ghost-shield' ); ?></h2>
                    </div>
                    <div class="gs-card-body">
                        <div class="gs-status-indicator <?php echo $settings['waf_enabled'] ? 'active' : 'inactive'; ?>">
                            <span class="gs-status-dot"></span>
                            <span class="gs-status-text">
                                <?php echo $settings['waf_enabled'] 
                                    ? esc_html__( 'Protection Active', 'ghost-shield' ) 
                                    : esc_html__( 'Protection Disabled', 'ghost-shield' ); 
                                ?>
                            </span>
                        </div>
                        <div class="gs-quick-stats">
                            <div class="gs-stat">
                                <span class="gs-stat-value"><?php echo esc_html( number_format( $stats['total_blocked'] ) ); ?></span>
                                <span class="gs-stat-label"><?php esc_html_e( 'Total Blocked', 'ghost-shield' ); ?></span>
                            </div>
                            <div class="gs-stat">
                                <span class="gs-stat-value"><?php echo $stats['last_attack'] ? esc_html( human_time_diff( strtotime( $stats['last_attack'] ) ) ) . ' ago' : 'N/A'; ?></span>
                                <span class="gs-stat-label"><?php esc_html_e( 'Last Attack', 'ghost-shield' ); ?></span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Attack Types Card -->
                <div class="gs-card">
                    <div class="gs-card-header">
                        <h2><?php esc_html_e( 'Threats Blocked', 'ghost-shield' ); ?></h2>
                    </div>
                    <div class="gs-card-body">
                        <div class="gs-threat-grid">
                            <div class="gs-threat-item critical">
                                <span class="gs-threat-icon">💉</span>
                                <span class="gs-threat-count"><?php echo esc_html( $stats['sqli_blocked'] ?? 0 ); ?></span>
                                <span class="gs-threat-name">SQL Injection</span>
                            </div>
                            <div class="gs-threat-item high">
                                <span class="gs-threat-icon">⚡</span>
                                <span class="gs-threat-count"><?php echo esc_html( $stats['xss_blocked'] ?? 0 ); ?></span>
                                <span class="gs-threat-name">XSS</span>
                            </div>
                            <div class="gs-threat-item critical">
                                <span class="gs-threat-icon">🔓</span>
                                <span class="gs-threat-count"><?php echo esc_html( $stats['rce_blocked'] ?? 0 ); ?></span>
                                <span class="gs-threat-name">RCE</span>
                            </div>
                            <div class="gs-threat-item high">
                                <span class="gs-threat-icon">📁</span>
                                <span class="gs-threat-count"><?php echo esc_html( $stats['traversal_blocked'] ?? 0 ); ?></span>
                                <span class="gs-threat-name">Path Traversal</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Quick Actions Card -->
                <div class="gs-card">
                    <div class="gs-card-header">
                        <h2><?php esc_html_e( 'Quick Actions', 'ghost-shield' ); ?></h2>
                    </div>
                    <div class="gs-card-body">
                        <div class="gs-actions">
                            <a href="<?php echo esc_url( admin_url( 'admin.php?page=ghost-shield-logs' ) ); ?>" class="gs-action-btn">
                                <span class="dashicons dashicons-list-view"></span>
                                <?php esc_html_e( 'View Logs', 'ghost-shield' ); ?>
                            </a>
                            <a href="<?php echo esc_url( admin_url( 'admin.php?page=ghost-shield-settings' ) ); ?>" class="gs-action-btn">
                                <span class="dashicons dashicons-admin-settings"></span>
                                <?php esc_html_e( 'Settings', 'ghost-shield' ); ?>
                            </a>
                            <button type="button" class="gs-action-btn" id="gs-whitelist-my-ip">
                                <span class="dashicons dashicons-admin-network"></span>
                                <?php esc_html_e( 'Whitelist My IP', 'ghost-shield' ); ?>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Rescue Mode Card -->
                <div class="gs-card gs-rescue-card">
                    <div class="gs-card-header">
                        <h2><?php esc_html_e( 'Rescue Mode', 'ghost-shield' ); ?></h2>
                    </div>
                    <div class="gs-card-body">
                        <p class="gs-info-text">
                            <?php esc_html_e( 'If you get locked out by the firewall, use this URL to temporarily bypass it:', 'ghost-shield' ); ?>
                        </p>
                        <div class="gs-rescue-url">
                            <code><?php echo esc_url( home_url( '/?ghost_rescue=' . ( $settings['rescue_key'] ?? '' ) ) ); ?></code>
                            <button type="button" class="button gs-copy-btn" data-copy="<?php echo esc_attr( home_url( '/?ghost_rescue=' . ( $settings['rescue_key'] ?? '' ) ) ); ?>">
                                <?php esc_html_e( 'Copy', 'ghost-shield' ); ?>
                            </button>
                        </div>
                        <p class="gs-warning-text">
                            <span class="dashicons dashicons-warning"></span>
                            <?php esc_html_e( 'Keep this URL secret! Anyone with it can bypass the WAF.', 'ghost-shield' ); ?>
                        </p>
                    </div>
                </div>

                <!-- Activity Chart Card -->
                <div class="gs-card gs-chart-card">
                    <div class="gs-card-header">
                        <h2><?php esc_html_e( 'Attack Activity (Last 30 Days)', 'ghost-shield' ); ?></h2>
                    </div>
                    <div class="gs-card-body">
                        <canvas id="gs-activity-chart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            // Chart data
            var dailyStats = <?php echo json_encode( $stats['daily_stats'] ?? array() ); ?>;
            var labels = [];
            var data = [];
            
            // Fill in last 30 days
            for (var i = 29; i >= 0; i--) {
                var date = new Date();
                date.setDate(date.getDate() - i);
                var dateStr = date.toISOString().split('T')[0];
                labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
                data.push(dailyStats[dateStr] || 0);
            }

            if (typeof Chart !== 'undefined') {
                var ctx = document.getElementById('gs-activity-chart').getContext('2d');
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Attacks Blocked',
                            data: data,
                            borderColor: '#667eea',
                            backgroundColor: 'rgba(102, 126, 234, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            }

            // Copy button
            $('.gs-copy-btn').on('click', function() {
                var text = $(this).data('copy');
                navigator.clipboard.writeText(text);
                $(this).text('<?php esc_html_e( 'Copied!', 'ghost-shield' ); ?>');
                setTimeout(function() {
                    $('.gs-copy-btn').text('<?php esc_html_e( 'Copy', 'ghost-shield' ); ?>');
                }, 2000);
            });

            // Whitelist IP
            $('#gs-whitelist-my-ip').on('click', function() {
                $.post(ajaxurl, {
                    action: 'gs_whitelist_ip',
                    nonce: GhostShield.nonce
                }, function(response) {
                    if (response.success) {
                        alert(response.data.message);
                    }
                });
            });
        });
        </script>
        <?php
    }

    /**
     * Render the logs page
     */
    public function render_logs_page() {
        $logger = $this->loader->get_logger();
        $logs   = $logger ? $logger->get_logs( 100 ) : array();
        ?>
        <div class="wrap gs-logs-page">
            <h1>
                <span class="gs-logo">🛡️</span>
                <?php esc_html_e( 'Firewall Logs', 'ghost-shield' ); ?>
            </h1>

            <div class="gs-logs-actions">
                <button type="button" class="button" id="gs-clear-logs">
                    <?php esc_html_e( 'Clear All Logs', 'ghost-shield' ); ?>
                </button>
                <button type="button" class="button" id="gs-refresh-logs">
                    <?php esc_html_e( 'Refresh', 'ghost-shield' ); ?>
                </button>
            </div>

            <table class="wp-list-table widefat fixed striped gs-logs-table">
                <thead>
                    <tr>
                        <th style="width: 150px;"><?php esc_html_e( 'Timestamp', 'ghost-shield' ); ?></th>
                        <th style="width: 100px;"><?php esc_html_e( 'Type', 'ghost-shield' ); ?></th>
                        <th style="width: 120px;"><?php esc_html_e( 'IP Address', 'ghost-shield' ); ?></th>
                        <th><?php esc_html_e( 'URI', 'ghost-shield' ); ?></th>
                        <th><?php esc_html_e( 'Payload', 'ghost-shield' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ( empty( $logs ) ) : ?>
                        <tr>
                            <td colspan="5" style="text-align: center;">
                                <?php esc_html_e( 'No attacks logged yet. Your site is safe!', 'ghost-shield' ); ?> 🎉
                            </td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ( $logs as $log ) : ?>
                            <tr>
                                <td><?php echo esc_html( $log['timestamp'] ); ?></td>
                                <td>
                                    <span class="gs-badge gs-badge-<?php echo esc_attr( strtolower( $log['type'] ) ); ?>">
                                        <?php echo esc_html( $log['type'] ); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html( $log['ip'] ); ?></td>
                                <td><code><?php echo esc_html( substr( $log['uri'], 0, 50 ) ); ?></code></td>
                                <td><code><?php echo esc_html( substr( $log['payload'], 0, 80 ) ); ?></code></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $('#gs-clear-logs').on('click', function() {
                if (confirm('<?php esc_html_e( 'Are you sure you want to clear all logs?', 'ghost-shield' ); ?>')) {
                    $.post(ajaxurl, {
                        action: 'gs_clear_logs',
                        nonce: GhostShield.nonce
                    }, function(response) {
                        if (response.success) {
                            location.reload();
                        }
                    });
                }
            });

            $('#gs-refresh-logs').on('click', function() {
                location.reload();
            });
        });
        </script>
        <?php
    }

    /**
     * Render the settings page
     */
    public function render_settings_page() {
        $settings = $this->loader->get_settings();
        ?>
        <div class="wrap gs-settings-page">
            <h1>
                <span class="gs-logo">🛡️</span>
                <?php esc_html_e( 'GhostShield Settings', 'ghost-shield' ); ?>
            </h1>

            <form method="post" action="options.php">
                <?php settings_fields( 'ghost_shield_settings_group' ); ?>

                <!-- WAF Settings -->
                <div class="gs-settings-section">
                    <h2><?php esc_html_e( 'Firewall Settings', 'ghost-shield' ); ?></h2>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Enable WAF', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[waf_enabled]" value="1" 
                                        <?php checked( $settings['waf_enabled'] ?? true ); ?>>
                                    <?php esc_html_e( 'Enable the Web Application Firewall', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Log Attacks', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[log_attacks]" value="1" 
                                        <?php checked( $settings['log_attacks'] ?? true ); ?>>
                                    <?php esc_html_e( 'Log blocked attacks to file', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Rescue Key', 'ghost-shield' ); ?></th>
                            <td>
                                <input type="text" name="ghost_shield_settings[rescue_key]" 
                                    value="<?php echo esc_attr( $settings['rescue_key'] ?? '' ); ?>" 
                                    class="regular-text">
                                <p class="description">
                                    <?php esc_html_e( 'Secret key to bypass the WAF if you get locked out. Keep this safe!', 'ghost-shield' ); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'IP Whitelist', 'ghost-shield' ); ?></th>
                            <td>
                                <textarea name="ghost_shield_settings[whitelist_ips_text]" rows="5" class="large-text code"><?php 
                                    echo esc_textarea( implode( "\n", $settings['whitelist_ips'] ?? array() ) ); 
                                ?></textarea>
                                <p class="description">
                                    <?php esc_html_e( 'One IP address per line. These IPs will bypass the WAF.', 'ghost-shield' ); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Stealth Settings -->
                <div class="gs-settings-section">
                    <h2><?php esc_html_e( 'Stealth & Hardening', 'ghost-shield' ); ?></h2>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Hide WordPress Version', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[hide_wp_version]" value="1" 
                                        <?php checked( $settings['hide_wp_version'] ?? true ); ?>>
                                    <?php esc_html_e( 'Remove version strings and generator tags', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Block XML-RPC', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[block_xmlrpc]" value="1" 
                                        <?php checked( $settings['block_xmlrpc'] ?? true ); ?>>
                                    <?php esc_html_e( 'Disable XML-RPC (blocks Pingback attacks)', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Protect REST API', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[protect_api]" value="1" 
                                        <?php checked( $settings['protect_api'] ?? true ); ?>>
                                    <?php esc_html_e( 'Block user enumeration via REST API', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Hide Login Page', 'ghost-shield' ); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="ghost_shield_settings[hide_login]" value="1" 
                                        <?php checked( $settings['hide_login'] ?? false ); ?>>
                                    <?php esc_html_e( 'Hide wp-admin and wp-login.php', 'ghost-shield' ); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Custom Login Slug', 'ghost-shield' ); ?></th>
                            <td>
                                <input type="text" name="ghost_shield_settings[login_slug]" 
                                    value="<?php echo esc_attr( $settings['login_slug'] ?? 'gs-login' ); ?>" 
                                    class="regular-text">
                                <p class="description">
                                    <?php 
                                    printf(
                                        /* translators: %s: example URL */
                                        esc_html__( 'Your new login URL will be: %s', 'ghost-shield' ),
                                        '<code>' . esc_html( home_url( '/' . ( $settings['login_slug'] ?? 'gs-login' ) ) ) . '</code>'
                                    ); 
                                    ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Login Protection -->
                <div class="gs-settings-section">
                    <h2><?php esc_html_e( 'Login Protection', 'ghost-shield' ); ?></h2>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Max Login Attempts', 'ghost-shield' ); ?></th>
                            <td>
                                <input type="number" name="ghost_shield_settings[max_login_attempts]" 
                                    value="<?php echo esc_attr( $settings['max_login_attempts'] ?? 5 ); ?>" 
                                    min="1" max="20" class="small-text">
                                <p class="description">
                                    <?php esc_html_e( 'Number of failed attempts before lockout.', 'ghost-shield' ); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e( 'Lockout Duration', 'ghost-shield' ); ?></th>
                            <td>
                                <input type="number" name="ghost_shield_settings[login_lockout_time]" 
                                    value="<?php echo esc_attr( ( $settings['login_lockout_time'] ?? 900 ) / 60 ); ?>" 
                                    min="1" max="1440" class="small-text">
                                <?php esc_html_e( 'minutes', 'ghost-shield' ); ?>
                            </td>
                        </tr>
                    </table>
                </div>

                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    /**
     * AJAX: Get stats for chart
     */
    public function ajax_get_stats() {
        check_ajax_referer( 'ghost_shield_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ) );
        }

        $stats = get_option( 'ghost_shield_attack_stats', array() );
        wp_send_json_success( $stats );
    }

    /**
     * AJAX: Clear logs
     */
    public function ajax_clear_logs() {
        check_ajax_referer( 'ghost_shield_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ) );
        }

        $logger = $this->loader->get_logger();
        if ( $logger ) {
            $logger->clear_logs();
        }

        // Reset stats
        update_option( 'ghost_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked'  => 0,
            'xss_blocked'   => 0,
            'rce_blocked'   => 0,
            'traversal_blocked' => 0,
            'last_attack'   => null,
            'daily_stats'   => array(),
        ) );

        wp_send_json_success( array( 'message' => __( 'Logs cleared successfully.', 'ghost-shield' ) ) );
    }

    /**
     * AJAX: Whitelist current IP
     */
    public function ajax_whitelist_ip() {
        check_ajax_referer( 'ghost_shield_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ) );
        }

        $firewall = $this->loader->get_firewall();
        if ( $firewall ) {
            $ip = $firewall->get_client_ip();
            $firewall->add_to_whitelist( $ip );
            wp_send_json_success( array( 
                'message' => sprintf( 
                    /* translators: %s: IP address */
                    __( 'IP %s has been whitelisted.', 'ghost-shield' ), 
                    $ip 
                ) 
            ) );
        }

        wp_send_json_error( array( 'message' => __( 'Could not whitelist IP.', 'ghost-shield' ) ) );
    }

    /**
     * AJAX: Run security scan
     */
    public function ajax_run_scan() {
        check_ajax_referer( 'ghost_shield_nonce', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ) );
        }

        $scanner = $this->loader->get_scanner();
        if ( ! $scanner ) {
            wp_send_json_error( array( 'message' => __( 'Scanner not available.', 'ghost-shield' ) ) );
        }

        // Run fresh scan
        $results = $scanner->run_full_scan( true );

        wp_send_json_success( array(
            'message' => __( 'Scan completed successfully.', 'ghost-shield' ),
            'results' => $scanner->get_display_results(),
        ) );
    }

    /**
     * Render the scanner page
     */
    public function render_scanner_page() {
        $scanner = $this->loader->get_scanner();
        $results = $scanner ? $scanner->get_display_results() : null;
        $last_scan = $scanner ? $scanner->get_last_scan_time() : null;
        ?>
        <div class="wrap gs-scanner-page">
            <h1>
                <span class="gs-logo">🛡️</span>
                <?php esc_html_e( 'Security Scanner', 'ghost-shield' ); ?>
            </h1>

            <div class="gs-scanner-header">
                <div class="gs-scan-info">
                    <?php if ( $last_scan ) : ?>
                        <p><?php printf( esc_html__( 'Last scan: %s', 'ghost-shield' ), esc_html( $last_scan ) ); ?></p>
                    <?php else : ?>
                        <p><?php esc_html_e( 'No scans performed yet.', 'ghost-shield' ); ?></p>
                    <?php endif; ?>
                </div>
                <button type="button" class="button button-primary button-hero" id="gs-run-scan">
                    <span class="dashicons dashicons-search"></span>
                    <?php esc_html_e( 'Run Security Scan', 'ghost-shield' ); ?>
                </button>
            </div>

            <div id="gs-scan-progress" style="display: none;">
                <div class="gs-progress-bar">
                    <div class="gs-progress-fill"></div>
                </div>
                <p class="gs-progress-text"><?php esc_html_e( 'Scanning...', 'ghost-shield' ); ?></p>
            </div>

            <?php if ( $results && $results['has_results'] ) : ?>
            <div class="gs-scanner-summary">
                <div class="gs-summary-card <?php echo $results['summary']['critical'] > 0 ? 'critical' : ( $results['summary']['high'] > 0 ? 'warning' : 'success' ); ?>">
                    <div class="gs-summary-icon">
                        <?php if ( $results['summary']['total_issues'] === 0 ) : ?>
                            ✅
                        <?php elseif ( $results['summary']['critical'] > 0 ) : ?>
                            🚨
                        <?php else : ?>
                            ⚠️
                        <?php endif; ?>
                    </div>
                    <div class="gs-summary-content">
                        <h2>
                            <?php if ( $results['summary']['total_issues'] === 0 ) : ?>
                                <?php esc_html_e( 'All Clear!', 'ghost-shield' ); ?>
                            <?php else : ?>
                                <?php printf(
                                    /* translators: %d: number of issues */
                                    esc_html( _n( '%d Issue Found', '%d Issues Found', $results['summary']['total_issues'], 'ghost-shield' ) ),
                                    $results['summary']['total_issues']
                                ); ?>
                            <?php endif; ?>
                        </h2>
                        <div class="gs-severity-counts">
                            <?php if ( $results['summary']['critical'] > 0 ) : ?>
                                <span class="gs-count critical"><?php echo esc_html( $results['summary']['critical'] ); ?> Critical</span>
                            <?php endif; ?>
                            <?php if ( $results['summary']['high'] > 0 ) : ?>
                                <span class="gs-count high"><?php echo esc_html( $results['summary']['high'] ); ?> High</span>
                            <?php endif; ?>
                            <?php if ( $results['summary']['medium'] > 0 ) : ?>
                                <span class="gs-count medium"><?php echo esc_html( $results['summary']['medium'] ); ?> Medium</span>
                            <?php endif; ?>
                            <?php if ( $results['summary']['low'] > 0 ) : ?>
                                <span class="gs-count low"><?php echo esc_html( $results['summary']['low'] ); ?> Low</span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>

            <?php if ( ! empty( $results['issues'] ) ) : ?>
            <table class="wp-list-table widefat fixed striped gs-scanner-table">
                <thead>
                    <tr>
                        <th style="width: 100px;"><?php esc_html_e( 'Severity', 'ghost-shield' ); ?></th>
                        <th style="width: 100px;"><?php esc_html_e( 'Category', 'ghost-shield' ); ?></th>
                        <th><?php esc_html_e( 'File', 'ghost-shield' ); ?></th>
                        <th><?php esc_html_e( 'Issue', 'ghost-shield' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $results['issues'] as $issue ) : ?>
                    <tr>
                        <td>
                            <span class="gs-badge gs-badge-<?php echo esc_attr( $issue['severity'] ); ?>">
                                <?php echo esc_html( ucfirst( $issue['severity'] ) ); ?>
                            </span>
                        </td>
                        <td><?php echo esc_html( ucfirst( $issue['category'] ) ); ?></td>
                        <td><code><?php echo esc_html( $issue['file'] ); ?></code></td>
                        <td><?php echo esc_html( $issue['message'] ); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
            <?php else : ?>
            <div class="gs-no-results">
                <p><?php esc_html_e( 'Click "Run Security Scan" to check your site for vulnerabilities.', 'ghost-shield' ); ?></p>
            </div>
            <?php endif; ?>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $('#gs-run-scan').on('click', function() {
                var $btn = $(this);
                $btn.prop('disabled', true).find('.dashicons').addClass('spin');
                $('#gs-scan-progress').show();

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'gs_run_scan',
                        nonce: GhostShield.nonce
                    },
                    success: function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert(response.data.message || 'Scan failed');
                            $btn.prop('disabled', false).find('.dashicons').removeClass('spin');
                            $('#gs-scan-progress').hide();
                        }
                    },
                    error: function() {
                        alert('<?php esc_html_e( 'An error occurred during the scan.', 'ghost-shield' ); ?>');
                        $btn.prop('disabled', false).find('.dashicons').removeClass('spin');
                        $('#gs-scan-progress').hide();
                    }
                });
            });
        });
        </script>

        <style>
        .gs-scanner-page { background: #1a1a2e; margin-left: -20px; padding: 20px; min-height: calc(100vh - 32px); }
        .gs-scanner-page h1 { color: #e2e8f0; display: flex; align-items: center; gap: 12px; margin-bottom: 24px; }
        .gs-scanner-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .gs-scan-info p { color: #a0aec0; margin: 0; }
        .gs-scanner-summary { margin-bottom: 24px; }
        .gs-summary-card { display: flex; align-items: center; gap: 20px; padding: 24px; border-radius: 12px; background: #16213e; border: 1px solid rgba(255,255,255,0.1); }
        .gs-summary-card.success { border-left: 4px solid #48bb78; }
        .gs-summary-card.warning { border-left: 4px solid #ed8936; }
        .gs-summary-card.critical { border-left: 4px solid #f56565; }
        .gs-summary-icon { font-size: 48px; }
        .gs-summary-content h2 { color: #e2e8f0; margin: 0 0 8px 0; }
        .gs-severity-counts { display: flex; gap: 12px; flex-wrap: wrap; }
        .gs-count { padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .gs-count.critical { background: rgba(245, 101, 101, 0.2); color: #f56565; }
        .gs-count.high { background: rgba(237, 137, 54, 0.2); color: #ed8936; }
        .gs-count.medium { background: rgba(236, 201, 75, 0.2); color: #ecc94b; }
        .gs-count.low { background: rgba(72, 187, 120, 0.2); color: #48bb78; }
        .gs-scanner-table { background: #16213e !important; border: 1px solid rgba(255,255,255,0.1) !important; }
        .gs-scanner-table thead th { background: #1f2a48 !important; color: #e2e8f0 !important; }
        .gs-scanner-table tbody td { color: #a0aec0 !important; border-color: rgba(255,255,255,0.1) !important; }
        .gs-scanner-table code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; color: #ffd700; }
        .gs-badge-critical { background: rgba(245, 101, 101, 0.2); color: #f56565; }
        .gs-badge-high { background: rgba(237, 137, 54, 0.2); color: #ed8936; }
        .gs-badge-medium { background: rgba(236, 201, 75, 0.2); color: #ecc94b; }
        .gs-no-results { text-align: center; padding: 48px; color: #a0aec0; }
        .gs-progress-bar { height: 4px; background: #16213e; border-radius: 2px; overflow: hidden; margin-bottom: 12px; }
        .gs-progress-fill { height: 100%; width: 30%; background: linear-gradient(90deg, #667eea, #764ba2); animation: progress 1.5s ease-in-out infinite; }
        @keyframes progress { 0% { width: 10%; } 50% { width: 70%; } 100% { width: 10%; } }
        .gs-progress-text { color: #a0aec0; text-align: center; }
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { 100% { transform: rotate(360deg); } }
        </style>
        <?php
    }
}
