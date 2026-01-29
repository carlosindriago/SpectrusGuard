<?php
/**
 * SpectrusGuard Admin Dashboard
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

/**
 * Class SG_Admin
 *
 * Admin dashboard and settings management.
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
     * Constructor
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct(SG_Loader $loader)
    {
        $this->loader = $loader;

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('wp_ajax_sg_get_stats', array($this, 'ajax_get_stats'));
        add_action('wp_ajax_sg_clear_logs', array($this, 'ajax_clear_logs'));
        add_action('wp_ajax_sg_whitelist_ip', array($this, 'ajax_whitelist_ip'));
        add_action('wp_ajax_sg_whitelist_ip', array($this, 'ajax_whitelist_ip'));
        add_action('wp_ajax_sg_run_scan', array($this, 'ajax_run_scan'));
        add_action('wp_ajax_sg_write_htaccess', array($this, 'ajax_write_htaccess'));

        // 2FA User Settings Save Hook
        add_action('admin_init', array($this, 'save_user_security_settings'));
    }

    /**
     * Save 2FA settings for the current user
     */
    public function save_user_security_settings()
    {
        if (isset($_POST['spectrus_2fa_method']) && isset($_POST['spectrus_security_nonce'])) {
            if (!wp_verify_nonce($_POST['spectrus_security_nonce'], 'spectrus_save_security')) {
                return;
            }

            $user_id = get_current_user_id();
            $method = sanitize_text_field($_POST['spectrus_2fa_method']);

            // Validate App Setup if selected
            if ($method === 'app') {
                $code = isset($_POST['spectrus_2fa_verify_code']) ? sanitize_text_field($_POST['spectrus_2fa_verify_code']) : '';
                $secret = isset($_POST['spectrus_2fa_secret']) ? sanitize_text_field($_POST['spectrus_2fa_secret']) : '';

                if (empty($code)) {
                    $redirect = add_query_arg(array('page' => 'spectrus-guard-settings', 'tab' => 'security', 'error' => 'missing_code'), admin_url('admin.php'));
                    wp_redirect($redirect);
                    exit;
                }

                if (class_exists('Spectrus_TOTP_Engine') && !Spectrus_TOTP_Engine::verify_code($secret, $code)) {
                    $redirect = add_query_arg(array('page' => 'spectrus-guard-settings', 'tab' => 'security', 'error' => 'invalid_code'), admin_url('admin.php'));
                    wp_redirect($redirect);
                    exit;
                }

                // If valid, save the secret
                update_user_meta($user_id, 'spectrus_2fa_secret', $secret);
            }

            update_user_meta($user_id, 'spectrus_2fa_method', $method);

            // Redirect to avoid resubmission
            $redirect = add_query_arg(array('page' => 'spectrus-guard-settings', 'tab' => 'security', 'updated' => 'true'), admin_url('admin.php'));
            wp_redirect($redirect);
            exit;
        }
    }

    /**
     * Add admin menu pages
     */
    public function add_admin_menu()
    {
        $this->page_hook = add_menu_page(
            __('SpectrusGuard Security', 'spectrus-guard'),
            __('SpectrusGuard', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard',
            array($this, 'render_dashboard'),
            'dashicons-shield',
            65
        );

        add_submenu_page(
            'spectrus-guard',
            __('Dashboard', 'spectrus-guard'),
            __('Dashboard', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard',
            array($this, 'render_dashboard')
        );

        add_submenu_page(
            'spectrus-guard',
            __('Security Scanner', 'spectrus-guard'),
            __('Scanner', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-scanner',
            array($this, 'render_scanner_page')
        );

        add_submenu_page(
            'spectrus-guard',
            __('Firewall Logs', 'spectrus-guard'),
            __('Firewall Logs', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-logs',
            array($this, 'render_logs_page')
        );

        add_submenu_page(
            'spectrus-guard',
            __('Settings', 'spectrus-guard'),
            __('Settings', 'spectrus-guard'),
            'manage_options',
            'spectrus-guard-settings',
            array($this, 'render_settings_page')
        );
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

        // 3. Define Fields per Context
        if ($context === 'cloak') {
            // --- CLOAK TAB ---
            $sanitized['url_cloaking_enabled'] = !empty($input['url_cloaking_enabled']);

            // Rescue key is generated/read-only in UI, but if we ever decide to make it editable:
            if (isset($input['rescue_key'])) {
                $sanitized['rescue_key'] = sanitize_text_field($input['rescue_key']);
            }

            // Login Slug (Also present in Cloak tab now)
            if (isset($input['login_slug'])) {
                $sanitized['login_slug'] = sanitize_title($input['login_slug']);
            }

            // Handle Plugin Mapping (Dynamic Masking)
            // Accessed via $_POST because they are outside the main settings array
            if (isset($_POST['sg_map_real']) && isset($_POST['sg_map_fake'])) {
                $clean_map = [];
                $reals = $_POST['sg_map_real'];
                $fakes = $_POST['sg_map_fake'];

                if (is_array($reals) && is_array($fakes)) {
                    for ($i = 0; $i < count($reals); $i++) {
                        $r = sanitize_text_field($reals[$i]);
                        $f = sanitize_title($fakes[$i]); // sanitize_title ensures URL safety
                        if ($r && $f) {
                            $clean_map[$r] = $f;
                        }
                    }
                }
                update_option('sg_cloak_plugin_map', $clean_map);

                // Write rules if applicable
                // We rely on the user clicking "Write Rules" manually or we can trigger it.
                // For now, allow manual trigger via UI message.
            }

        } else {
            // --- GENERAL TAB (Default) ---

            // Boolean fields (Checkboxes)
            $general_bools = array(
                'waf_enabled',
                'log_attacks',
                'block_xmlrpc',
                'hide_wp_version',
                'protect_api',
                'hide_login',
                'block_author_pages',
            );

            foreach ($general_bools as $field) {
                // If the form was submitted, presence = true, absence = false
                $sanitized[$field] = !empty($input[$field]);
            }

            // Text fields
            if (isset($input['login_slug'])) {
                $sanitized['login_slug'] = sanitize_title($input['login_slug']);
            }

            // IP Whitelist (text area to array)
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

            // Numeric fields
            if (isset($input['max_login_attempts'])) {
                $sanitized['max_login_attempts'] = absint($input['max_login_attempts']);
            }

            if (isset($input['login_lockout_time'])) {
                // User inputs minutes, we store seconds
                $sanitized['login_lockout_time'] = max(1, absint($input['login_lockout_time'])) * 60;
            }
        }

        return $sanitized;
    }

    /**
     * Render the main dashboard page
     */
    public function render_dashboard()
    {
        $stats = get_option('spectrus_shield_attack_stats', array(
            'total_blocked' => 0,
            'sqli_blocked' => 0,
            'xss_blocked' => 0,
            'rce_blocked' => 0,
            'traversal_blocked' => 0,
            'last_attack' => null,
            'daily_stats' => array(),
        ));

        $settings = $this->loader->get_settings();

        // Get scanner data for Dashboard widget
        $last_scan = get_option('spectrus_shield_last_scan', null);
        $scan_results = get_option('spectrus_shield_scan_results', array());
        $threats_found = 0;
        if (!empty($scan_results)) {
            foreach ($scan_results as $result) {
                if (isset($result['severity']) && in_array($result['severity'], array('critical', 'high', 'medium'))) {
                    $threats_found++;
                }
            }
        }

        // Determine scan status
        $scan_status = 'never'; // never, old, recent
        $days_since_scan = null;
        if ($last_scan) {
            $days_since_scan = floor((time() - strtotime($last_scan)) / DAY_IN_SECONDS);
            $scan_status = ($days_since_scan > 7) ? 'old' : 'recent';
        }

        // Get Recent Logs
        $logger = new SG_Logger();
        $recent_logs = $logger->get_logs(5);
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('SpectrusGuard Security', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-version-badge">v1.0.0</div>
            </div>

            <!-- Zone 1: Hero Section -->
            <div class="sg-hero-panel">
                <div class="sg-hero-status">
                    <div class="sg-hero-icon-wrapper">
                        <span class="sg-hero-icon">🛡️</span>
                        <div class="sg-hero-pulse"></div>
                    </div>
                    <div class="sg-hero-content">
                        <h2><?php esc_html_e('System Protected', 'spectrus-guard'); ?></h2>
                        <p><?php esc_html_e('WAF is active and monitoring traffic.', 'spectrus-guard'); ?></p>
                        <?php if ($scan_status === 'recent' && $threats_found === 0): ?>
                            <span class="sg-status-badge success">
                                <span class="dashicons dashicons-yes"></span>
                                <?php esc_html_e('Last scan clean', 'spectrus-guard'); ?>
                            </span>
                        <?php elseif ($threats_found > 0): ?>
                            <span class="sg-status-badge danger">
                                <span class="dashicons dashicons-warning"></span>
                                <?php echo intval($threats_found) . ' ' . esc_html__('threats found', 'spectrus-guard'); ?>
                            </span>
                        <?php else: ?>
                            <span class="sg-status-badge warning">
                                <span class="dashicons dashicons-calendar-alt"></span>
                                <?php esc_html_e('Scan recommended', 'spectrus-guard'); ?>
                            </span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="sg-hero-actions">
                    <div class="sg-last-scan-info">
                        <?php if ($last_scan): ?>
                            <?php echo esc_html__('Last scan:', 'spectrus-guard'); ?>
                            <strong><?php echo esc_html(human_time_diff(strtotime($last_scan))) . ' ago'; ?></strong>
                        <?php else: ?>
                            <?php esc_html_e('Never scanned', 'spectrus-guard'); ?>
                        <?php endif; ?>
                    </div>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-scanner')); ?>"
                        class="sg-btn sg-btn-primary">
                        <span class="dashicons dashicons-search"></span>
                        <?php esc_html_e('Run New Scan', 'spectrus-guard'); ?>
                    </a>
                </div>
            </div>

            <div class="sg-main-layout">

                <!-- Zone 2: Main Content (Left) -->
                <div class="sg-content-column">

                    <!-- Threat Intel Grid -->
                    <h3 class="sg-section-title"><?php esc_html_e('Threat Intelligence', 'spectrus-guard'); ?></h3>
                    <div class="sg-threat-intel-grid">
                        <!-- SQLi -->
                        <div class="sg-stat-card">
                            <div class="sg-stat-icon sqli">💉</div>
                            <div class="sg-stat-data">
                                <span class="sg-stat-number"><?php echo esc_html($stats['sqli_blocked'] ?? 0); ?></span>
                                <span class="sg-stat-label">SQL Injection</span>
                            </div>
                            <div class="sg-stat-trend">
                                <span class="trend-up">↑ 0 this week</span>
                            </div>
                        </div>
                        <!-- XSS -->
                        <div class="sg-stat-card">
                            <div class="sg-stat-icon xss">⚡</div>
                            <div class="sg-stat-data">
                                <span class="sg-stat-number"><?php echo esc_html($stats['xss_blocked'] ?? 0); ?></span>
                                <span class="sg-stat-label">XSS Attempts</span>
                            </div>
                            <div class="sg-stat-trend">
                                <span class="trend-flat">- 0 this week</span>
                            </div>
                        </div>
                        <!-- RCE -->
                        <div class="sg-stat-card">
                            <div class="sg-stat-icon rce">🔓</div>
                            <div class="sg-stat-data">
                                <span class="sg-stat-number"><?php echo esc_html($stats['rce_blocked'] ?? 0); ?></span>
                                <span class="sg-stat-label">RCE Exploits</span>
                            </div>
                            <div class="sg-stat-trend">
                                <span class="trend-flat">- 0 this week</span>
                            </div>
                        </div>
                        <!-- Traversal -->
                        <div class="sg-stat-card">
                            <div class="sg-stat-icon traversal">📁</div>
                            <div class="sg-stat-data">
                                <span class="sg-stat-number"><?php echo esc_html($stats['traversal_blocked'] ?? 0); ?></span>
                                <span class="sg-stat-label">Path Traversal</span>
                            </div>
                            <div class="sg-stat-trend">
                                <span class="trend-flat">- 0 this week</span>
                            </div>
                        </div>
                    </div>

                    <!-- Chart Section -->
                    <div class="sg-card sg-chart-card">
                        <div class="sg-card-header">
                            <h2><?php esc_html_e('Attack Activity (Last 30 Days)', 'spectrus-guard'); ?></h2>
                        </div>
                        <div class="sg-card-body">
                            <canvas id="sg-activity-chart"></canvas>
                        </div>
                    </div>

                </div>

                <!-- Zone 3: Sidebar (Right) -->
                <div class="sg-sidebar-column">

                    <!-- Quick Actions Panel -->
                    <div class="sg-card sg-actions-panel">
                        <div class="sg-card-header">
                            <h2><?php esc_html_e('Quick Actions', 'spectrus-guard'); ?></h2>
                        </div>
                        <div class="sg-action-list">
                            <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-logs')); ?>"
                                class="sg-action-item">
                                <span class="dashicons dashicons-media-text"></span>
                                <span class="sg-action-text"><?php esc_html_e('View Firewall Logs', 'spectrus-guard'); ?></span>
                                <span class="sg-action-arrow">→</span>
                            </a>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-settings')); ?>"
                                class="sg-action-item">
                                <span class="dashicons dashicons-admin-settings"></span>
                                <span class="sg-action-text"><?php esc_html_e('Global Settings', 'spectrus-guard'); ?></span>
                                <span class="sg-action-arrow">→</span>
                            </a>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-settings&tab=whitelist')); ?>"
                                class="sg-action-item">
                                <span class="dashicons dashicons-shield"></span>
                                <span
                                    class="sg-action-text"><?php esc_html_e('Manage IP Whitelist', 'spectrus-guard'); ?></span>
                                <span class="sg-action-arrow">→</span>
                            </a>
                        </div>
                    </div>

                    <!-- Rescue Mode (Compact) -->
                    <div class="sg-card sg-rescue-panel">
                        <div class="sg-card-header warning-header">
                            <h2>⚠️ <?php esc_html_e('Emergency Access', 'spectrus-guard'); ?></h2>
                        </div>
                        <div class="sg-card-body">
                            <p class="sg-rescue-desc">
                                <?php esc_html_e('Use this URL if you get locked out:', 'spectrus-guard'); ?>
                            </p>
                            <div class="sg-rescue-input-group">
                                <input type="text" readonly
                                    value="<?php echo esc_url(home_url('/?spectrus_rescue=' . $settings['rescue_key'])); ?>"
                                    class="sg-rescue-input" id="sg-rescue-url">
                                <button type="button" class="sg-copy-btn-icon"
                                    onclick="navigator.clipboard.writeText(document.getElementById('sg-rescue-url').value)">
                                    <span class="dashicons dashicons-clipboard"></span>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity -->
                    <div class="sg-card sg-recent-activity">
                        <div class="sg-card-header">
                            <h2><?php esc_html_e('Recent Activity', 'spectrus-guard'); ?></h2>
                        </div>
                        <div class="sg-activity-list">
                            <?php if (!empty($recent_logs)): ?>
                                <?php foreach ($recent_logs as $log): ?>
                                    <div class="sg-activity-item">
                                        <div class="sg-activity-icon <?php echo esc_attr(strtolower($log['type'])); ?>">
                                            <?php
                                            switch (strtolower($log['type'])) {
                                                case 'sqli':
                                                    echo '💉';
                                                    break;
                                                case 'xss':
                                                    echo '⚡';
                                                    break;
                                                case 'rce':
                                                    echo '🔓';
                                                    break;
                                                default:
                                                    echo '🛡️';
                                            }
                                            ?>
                                        </div>
                                        <div class="sg-activity-details">
                                            <span class="sg-activity-type"><?php echo esc_html($log['type']); ?></span>
                                            <span class="sg-activity-ip"><?php echo esc_html($log['ip']); ?></span>
                                        </div>
                                        <div class="sg-activity-time">
                                            <?php echo esc_html(human_time_diff(strtotime($log['timestamp']))) . ' ago'; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-logs')); ?>"
                                    class="sg-view-all-link">
                                    <?php esc_html_e('View All History', 'spectrus-guard'); ?> →
                                </a>
                            <?php else: ?>
                                <div class="sg-empty-state">
                                    <p><?php esc_html_e('No recent security events.', 'spectrus-guard'); ?></p>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                </div>
            </div>

        </div>

        <script>
            jQuery(document).ready(functio                n($) {
                // Chart data
                var dailyStats = <?php echo json_encode($stats['daily_stats'] ?? array()); ?>;
                var labels = [];
                var data = [];

                // Fill in last 30 days
                for(var i = 29; i >= 0; i--) {
                var date = new Date();
                date.setDate(date.getDate() - i);
                var dateStr = date.toISOString().split('T')[0];
                labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
                data.push(dailyStats[dateStr] || 0);
            }

            if (typeof Chart !== 'undefined') {
                var ctx = document.getElementById('sg-activity-chart').getContext('2d');

                // Create gradient
                var gradient = ctx.createLinearGradient(0, 0, 0, 300);
                gradient.addColorStop(0, 'rgba(59, 130, 246, 0.2)'); // Blue 500 low opacity
                gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');

                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Attacks Blocked',
                            data: data,
                            borderColor: '#3b82f6', // Blue 500
                            backgroundColor: gradient,
                            borderWidth: 2,
                            pointBackgroundColor: '#3b82f6',
                            pointBorderColor: '#1e293b', // Card bg
                            pointHoverBackgroundColor: '#fff',
                            pointHoverBorderColor: '#3b82f6',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: '#1e293b',
                                titleColor: '#f8fafc',
                                bodyColor: '#94a3b8',
                                borderColor: '#334155',
                                borderWidth: 1,
                                padding: 10,
                                displayColors: false,
                                callbacks: {
                                    label: function (context) {
                                        return context.parsed.y + ' Attacks';
                                    }
                                }
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(148, 163, 184, 0.1)',
                                    borderColor: 'transparent'
                                },
                                ticks: { color: '#64748b' }
                            },
                            x: {
                                grid: {
                                    display: false,
                                    borderColor: 'transparent'
                                },
                                ticks: { color: '#64748b', maxTicksLimit: 10 }
                            }
                        }
                    }
                });
            }

            // Copy button interaction
            $('.sg-copy-btn-icon').on('click', function () {
                var $btn = $(this);
                var $icon = $btn.find('.dashicons');
                var originalIcon = 'dashicons-clipboard';

                // Copy logic is handled by inline onclick, just do UI feedback here
                $icon.removeClass(originalIcon).addClass('dashicons-yes');
                $btn.addClass('success');

                setTimeout(function () {
                    $icon.removeClass('dashicons-yes').addClass(originalIcon);
                    $btn.removeClass('success');
                }, 2000);
            });

            // Whitelist IP
            $('#sg-whitelist-my-ip').on('click', function () {
                // ... (This button might not exist in new HTML, check Quick Actions)
                // ... Actually I used a link to settings tab=whitelist in Quick Actions, so this might be obsolete or valid for another button?
                // Let's keep it if I restore the button or for other pages.
            });
                                                                                                                                                                                        });
        </script>
        <?php
    }

    /**
     * Render the logs page
     */
    public function render_logs_page()
    {
        $logger = $this->loader->get_logger();
        $logs = $logger ? $logger->get_logs(100) : array();
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('Firewall Logs', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <button type="button" class="sg-btn sg-btn-danger" id="sg-clear-logs">
                        <span class="dashicons dashicons-trash"></span>
                        <?php esc_html_e('Clear Logs', 'spectrus-guard'); ?>
                    </button>
                    <button type="button" class="sg-btn sg-btn-secondary" id="sg-refresh-logs">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e('Refresh', 'spectrus-guard'); ?>
                    </button>
                </div>
            </div>

            <div class="sg-main-layout">
                <div class="sg-content-column" style="grid-column: span 12;">

                    <div class="sg-card">
                        <div class="sg-card-header">
                            <h2><?php esc_html_e('Security Events History', 'spectrus-guard'); ?></h2>
                        </div>
                        <div class="sg-card-body" style="padding: 0;">
                            <table class="sg-logs-table">
                                <thead>
                                    <tr>
                                        <th style="width: 180px;"><?php esc_html_e('Timestamp', 'spectrus-guard'); ?></th>
                                        <th style="width: 120px;"><?php esc_html_e('Type', 'spectrus-guard'); ?></th>
                                        <th style="width: 150px;"><?php esc_html_e('IP Address', 'spectrus-guard'); ?></th>
                                        <th><?php esc_html_e('Request URI', 'spectrus-guard'); ?></th>
                                        <th><?php esc_html_e('Payload', 'spectrus-guard'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($logs)): ?>
                                        <tr>
                                            <td colspan="5" style="text-align: center; padding: 40px; color: var(--sg-text-muted);">
                                                <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
                                                <p style="font-size: 16px; margin: 0;">
                                                    <?php esc_html_e('No attacks detected yet. Your site is safe.', 'spectrus-guard'); ?>
                                                </p>
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($logs as $log): ?>
                                            <tr>
                                                <td style="color: var(--sg-text-secondary); font-family: monospace;">
                                                    <?php echo esc_html($log['timestamp']); ?>
                                                </td>
                                                <td>
                                                    <span class="sg-badge <?php echo esc_attr(strtolower($log['type'])); ?>">
                                                        <?php echo esc_html($log['type']); ?>
                                                    </span>
                                                </td>
                                                <td style="font-family: monospace; color: var(--sg-primary);">
                                                    <?php echo esc_html($log['ip']); ?>
                                                </td>
                                                <td style="font-family: monospace; color: var(--sg-text-muted);">
                                                    <?php echo esc_html(substr($log['uri'], 0, 50)) . (strlen($log['uri']) > 50 ? '...' : ''); ?>
                                                </td>
                                                <td style="font-family: monospace; font-size: 11px; color: var(--sg-danger);">
                                                    <?php echo esc_html(substr($log['payload'], 0, 80)) . (strlen($log['payload']) > 80 ? '...' : ''); ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                </div>
            </div>
        </div>

        <script>
            jQuery(document).ready(function ($) {
                $('#sg-clear-logs').on('click', function () {
                    if (confirm('<?php esc_html_e('Are you sure you want to delete all security logs?', 'spectrus-guard'); ?>')) {
                        $.post(ajaxurl, {
                            action: 'sg_clear_logs',
                            nonce: SpectrusGuard.nonce
                        }, function (response) {
                            if (response.success) {
                                location.reload();
                            }
                        });
                    }
                });

                $('#sg-refresh-logs').on('click', function () {
                    location.reload();
                });
            });
        </script>
        <?php
    }



    /**
     * Render the settings page
     */
    public function render_settings_page()
    {
        $settings = $this->loader->get_settings();
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'general';
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('SpectrusGuard Configuration', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <?php if ($active_tab === 'general'): ?>
                        <button type="submit" form="sg-settings-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Changes', 'spectrus-guard'); ?>
                        </button>
                    <?php elseif ($active_tab === 'cloak'): ?>
                        <button type="submit" form="sg-cloak-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Configuration', 'spectrus-guard'); ?>
                        </button>
                    <?php else: ?>
                        <button type="submit" form="sg-security-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Security', 'spectrus-guard'); ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Tabs Navigation -->
            <?php
            if (isset($_GET['error'])) {
                $error_message = '';
                if ($_GET['error'] === 'invalid_code') {
                    $error_message = __('Invalid verification code. Please scan the QR code and try again.', 'spectrus-guard');
                } elseif ($_GET['error'] === 'missing_code') {
                    $error_message = __('Please enter the verification code from your authenticator app.', 'spectrus-guard');
                }

                if ($error_message) {
                    echo '<div class="notice notice-error is-dismissible" style="margin: 20px 0 10px;"><p>' . esc_html($error_message) . '</p></div>';
                }
            }
            if (isset($_GET['updated']) && $_GET['updated'] === 'true') {
                echo '<div class="notice notice-success is-dismissible" style="margin: 20px 0 10px;"><p>' . esc_html__('Settings saved successfully.', 'spectrus-guard') . '</p></div>';
            }
            ?>
            <h2 class="nav-tab-wrapper" style="margin-bottom: 20px; border-bottom: 1px solid #334155;">
                <a href="?page=spectrus-guard-settings&tab=general"
                    class="nav-tab <?php echo $active_tab == 'general' ? 'nav-tab-active' : ''; ?>"
                    style="background: transparent; color: #f8fafc; border-color: #334155; margin-left: 0;">
                    <?php esc_html_e('General Settings', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-settings&tab=security"
                    class="nav-tab <?php echo $active_tab == 'security' ? 'nav-tab-active' : ''; ?>"
                    style="background: transparent; color: #f8fafc; border-color: #334155;">
                    <?php esc_html_e('My Security (2FA)', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-settings&tab=cloak"
                    class="nav-tab <?php echo $active_tab == 'cloak' ? 'nav-tab-active' : ''; ?>"
                    style="background: transparent; color: #f8fafc; border-color: #334155;">
                    👻 <?php esc_html_e('Ghost Cloak', 'spectrus-guard'); ?>
                </a>
            </h2>

            <?php if ($active_tab === 'general'): ?>
                <form method="post" action="options.php" id="sg-settings-form">
                    <?php settings_fields('spectrus_shield_settings_group'); ?>
                    <input type="hidden" name="spectrus_shield_settings[form_context]" value="general">

                    <div class="sg-main-layout">
                        <!-- Column 1: Core Security -->
                        <div class="sg-content-column"
                            style="grid-column: span 12; display: grid; grid-template-columns: 1fr 1fr; gap: 24px;">

                            <!-- WAF Settings -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('Firewall Core', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">

                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Web Application Firewall', 'spectrus-guard'); ?></label>
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
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Attack Logging', 'spectrus-guard'); ?></label>
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
                                        <label class="sg-control-label"
                                            style="margin-bottom: 8px;"><?php esc_html_e('Rescue Key', 'spectrus-guard'); ?></label>
                                        <input type="text" name="spectrus_shield_settings[rescue_key]"
                                            value="<?php echo esc_attr($settings['rescue_key'] ?? ''); ?>" class="sg-input-text"
                                            placeholder="e.g. secret-bypass-key">
                                        <p class="sg-control-desc" style="margin-top: 8px;">
                                            <?php esc_html_e('Use ?rescue_key=YOUR_KEY to bypass the WAF if you get locked out.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>

                                </div>
                            </div>

                            <!-- Stealth Settings -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('Stealth Mode', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">

                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Hide WordPress Version', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Prevent scanners from detecting your WP version.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[hide_wp_version]" value="1"
                                                    <?php checked($settings['hide_wp_version'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Disable XML-RPC', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Block old API often used for brute force attacks.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[block_xmlrpc]" value="1" <?php checked($settings['block_xmlrpc'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Protect REST API', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Stop user enumeration via /wp-json/wp/v2/users.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[protect_api]" value="1" <?php checked($settings['protect_api'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>

                                </div>
                            </div>

                            <!-- Login Protection -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('Login Security', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Hide Login Page', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Disable wp-login.php and use a custom slug.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[hide_login]" value="1" <?php checked($settings['hide_login'] ?? false); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="sg-control-group" style="display: block;">
                                        <label class="sg-control-label"
                                            style="margin-bottom: 8px;"><?php esc_html_e('Custom Login Slug', 'spectrus-guard'); ?></label>
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <span
                                                style="color: var(--sg-text-secondary);"><?php echo esc_url(home_url('/')); ?></span>
                                            <input type="text" name="spectrus_shield_settings[login_slug]"
                                                value="<?php echo esc_attr($settings['login_slug'] ?? 'sg-login'); ?>"
                                                class="sg-input-text" style="width: auto; flex: 1;">
                                        </div>
                                    </div>

                                    <div class="sg-control-group">
                                        <div style="width: 100%; display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                                            <div>
                                                <label
                                                    class="sg-control-label"><?php esc_html_e('Max Attempts', 'spectrus-guard'); ?></label>
                                                <input type="number" name="spectrus_shield_settings[max_login_attempts]"
                                                    value="<?php echo esc_attr($settings['max_login_attempts'] ?? 5); ?>"
                                                    class="sg-input-text">
                                            </div>
                                            <div>
                                                <label
                                                    class="sg-control-label"><?php esc_html_e('Lockout (min)', 'spectrus-guard'); ?></label>
                                                <input type="number" name="spectrus_shield_settings[login_lockout_time]"
                                                    value="<?php echo esc_attr(intval(($settings['login_lockout_time'] ?? 900) / 60)); ?>"
                                                    class="sg-input-text">
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Access Control -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('Access Control', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group" style="display: block;">
                                        <label class="sg-control-label"
                                            style="margin-bottom: 8px;"><?php esc_html_e('IP Whitelist', 'spectrus-guard'); ?></label>
                                        <textarea name="spectrus_shield_settings[whitelist_ips_text]" rows="5"
                                            class="sg-textarea code"><?php
                                            echo esc_textarea(implode("\n", $settings['whitelist_ips'] ?? array()));
                                            ?></textarea>
                                        <p class="sg-control-desc" style="margin-top: 8px;">
                                            <?php esc_html_e('One IP per line. These IPs bypass WAF rules.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                </div>
                            </div>

                        </div>

                        <!-- Full Width: URL Cloaking REMOVED (Moved to Ghost Cloak Tab) -->

                    </div>
                </form>
                </form>
            <?php elseif ($active_tab === 'cloak'): ?>
                <!-- Ghost Cloak Tab -->
                <form method="post" action="options.php" id="sg-cloak-form">
                    <?php
                    settings_fields('spectrus_shield_settings_group');
                    $settings_view = SG_PLUGIN_DIR . 'includes/hardening/views/settings-cloak.php';
                    if (file_exists($settings_view)) {
                        include $settings_view;
                    } else {
                        echo '<p class="sg-alert error">View file not found.</p>';
                    }
                    ?>
                </form>
            <?php else: ?>
                <!-- Security Tab (2FA) -->
                <form method="post" id="sg-security-form">
                    <?php wp_nonce_field('spectrus_save_security', 'spectrus_security_nonce'); ?>
                    <div class="sg-main-layout">
                        <div class="sg-content-column" style="grid-column: span 12;">
                            <?php
                            // Load setup view
                            include SG_PLUGIN_DIR . 'includes/auth/views/setup-2fa.php';
                            ?>
                        </div>
                    </div>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * AJAX: Get stats for chart
     */
    public function ajax_get_stats()
    {
        check_ajax_referer('spectrus_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $stats = get_option('spectrus_shield_attack_stats', array());
        wp_send_json_success($stats);
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
     * AJAX: Run security scan
     */
    public function ajax_run_scan()
    {
        check_ajax_referer('spectrus_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $scanner = $this->loader->get_scanner();
        if (!$scanner) {
            wp_send_json_error(array('message' => __('Scanner not available.', 'spectrus-guard')));
        }

        $step = isset($_POST['step']) ? sanitize_text_field($_POST['step']) : 'init';
        $offset = isset($_POST['offset']) ? absint($_POST['offset']) : 0;
        $limit = 500;

        // Step 1: Initialization
        if ($step === 'init') {
            $scanner->clear_cache();
            delete_transient('spectrus_shield_scan_partial');

            wp_send_json_success(array(
                'step' => 'core_integrity',
                'offset' => 0,
                'message' => __('Starting core file verification...', 'spectrus-guard'),
                'progress' => 5,
            ));
            return;
        }

        // Retrieve partial results
        $current_results = get_transient('spectrus_shield_scan_partial');
        if (!$current_results || !is_array($current_results)) {
            $current_results = array(
                'core_integrity' => array(),
                'uploads_php' => array(),
                'suspicious' => array(),
                'malware' => array(),
            );
        }

        // Step 2: Core Integrity (Batched)
        if ($step === 'core_integrity') {
            $result = $scanner->run_core_batch($offset, $limit);

            $current_results['core_integrity'] = array_merge($current_results['core_integrity'], $result['issues']);
            set_transient('spectrus_shield_scan_partial', $current_results, DAY_IN_SECONDS);

            $processed = $result['processed'];
            $total = $result['total'];
            $new_offset = $offset + $processed;

            if ($processed < $limit || ($total > 0 && $new_offset >= $total)) {
                // Done with core files batching
                wp_send_json_success(array(
                    'step' => 'core_unknown',
                    'offset' => 0,
                    'message' => __('Checking for unknown files in core directories...', 'spectrus-guard'),
                    'progress' => 40,
                ));
            } else {
                // Continue batching
                $progress = 5 + (($total > 0) ? round(($new_offset / $total) * 35) : 0);
                wp_send_json_success(array(
                    'step' => 'core_integrity',
                    'offset' => $new_offset,
                    'message' => sprintf(__('Scanning core files... (%d/%d)', 'spectrus-guard'), $new_offset, $total),
                    'progress' => $progress,
                ));
            }
            return;
        }

        // Step 3: Unknown Files in Core
        if ($step === 'core_unknown') {
            $issues = $scanner->run_unknown_files_scan();
            $current_results['core_integrity'] = array_merge($current_results['core_integrity'], $issues);
            set_transient('spectrus_shield_scan_partial', $current_results, DAY_IN_SECONDS);

            wp_send_json_success(array(
                'step' => 'uploads_check',
                'offset' => 0,
                'message' => __('Scanning uploads directory for PHP files...', 'spectrus-guard'),
                'progress' => 50,
            ));
            return;
        }

        // Step 4: Uploads Directory
        if ($step === 'uploads_check') {
            $issues = $scanner->run_uploads_scan();
            $current_results['uploads_php'] = $issues;
            set_transient('spectrus_shield_scan_partial', $current_results, DAY_IN_SECONDS);

            wp_send_json_success(array(
                'step' => 'suspicious_check',
                'offset' => 0,
                'message' => __('Checking for suspicious files...', 'spectrus-guard'),
                'progress' => 65,
            ));
            return;
        }

        // Step 5: Suspicious Files
        if ($step === 'suspicious_check') {
            $issues = $scanner->run_suspicious_scan();
            $current_results['suspicious'] = $issues;
            set_transient('spectrus_shield_scan_partial', $current_results, DAY_IN_SECONDS);

            wp_send_json_success(array(
                'step' => 'malware_scan',
                'offset' => 0,
                'message' => __('Scanning for malware signatures...', 'spectrus-guard'),
                'progress' => 80,
            ));
            return;
        }

        // Step 6: Malware Scan and Finalize
        if ($step === 'malware_scan') {
            $issues = $scanner->run_malware_scan();
            $current_results['malware'] = $issues;

            // Finalize
            $scanner->save_scan_results($current_results);
            delete_transient('spectrus_shield_scan_partial');

            wp_send_json_success(array(
                'step' => 'finish',
                'offset' => 0,
                'message' => __('Scan completed successfully.', 'spectrus-guard'),
                'progress' => 100,
                'results' => $scanner->get_display_results(),
            ));
            return;
        }
    }

    /**
     * Render the scanner page
     */
    public function render_scanner_page()
    {
        $scanner = $this->loader->get_scanner();
        $results = $scanner ? $scanner->get_display_results() : null;
        $last_scan = $scanner ? $scanner->get_last_scan_time() : null;
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('Security Scanner', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <div class="sg-last-scan-badge">
                        <?php if ($last_scan): ?>
                            <span class="dashicons dashicons-clock"></span>
                            <?php printf(esc_html__('Last scan: %s', 'spectrus-guard'), esc_html($last_scan)); ?>
                        <?php else: ?>
                            <?php esc_html_e('No scans yet', 'spectrus-guard'); ?>
                        <?php endif; ?>
                    </div>
                    <button type="button" class="sg-btn sg-btn-primary" id="sg-run-scan">
                        <span class="dashicons dashicons-search"></span>
                        <?php esc_html_e('Run Deep Scan', 'spectrus-guard'); ?>
                    </button>
                </div>
            </div>

            <div class="sg-main-layout">
                <div class="sg-content-column" style="grid-column: span 12;">

                    <!-- Scan Progress Overlay/Area -->
                    <div id="sg-scan-progress" class="sg-card" style="display: none; text-align: center; padding: 40px;">
                        <div class="sg-spinner-ring"></div>
                        <h3 style="margin-top: 20px; color: var(--sg-text-primary);">
                            <?php esc_html_e('Scanning your site...', 'spectrus-guard'); ?>
                        </h3>
                        <p style="color: var(--sg-text-secondary);">
                            <?php esc_html_e('This may take a few moments. We are checking core files, plugins, and configurations.', 'spectrus-guard'); ?>
                        </p>
                    </div>

                    <?php if ($results && $results['has_results']): ?>

                        <!-- Summary Cards -->
                        <div class="sg-threat-intel-grid" style="margin-bottom: 24px;">
                            <div class="sg-stat-card <?php echo $results['summary']['critical'] > 0 ? 'danger-border' : ''; ?>">
                                <div class="sg-stat-icon critical">🚨</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number"><?php echo esc_html($results['summary']['critical']); ?></span>
                                    <span class="sg-stat-label">Critical Issues</span>
                                </div>
                            </div>
                            <div class="sg-stat-card <?php echo $results['summary']['high'] > 0 ? 'warning-border' : ''; ?>">
                                <div class="sg-stat-icon high">🔥</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number"><?php echo esc_html($results['summary']['high']); ?></span>
                                    <span class="sg-stat-label">High Priority</span>
                                </div>
                            </div>
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon medium">⚠️</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number"><?php echo esc_html($results['summary']['medium']); ?></span>
                                    <span class="sg-stat-label">Medium Priority</span>
                                </div>
                            </div>
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon low">ℹ️</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number"><?php echo esc_html($results['summary']['low']); ?></span>
                                    <span class="sg-stat-label">Low Priority</span>
                                </div>
                            </div>
                        </div>

                        <!-- Issues List -->
                        <div class="sg-card">
                            <div class="sg-card-header">
                                <h2><?php esc_html_e('Vulnerabilities Found', 'spectrus-guard'); ?></h2>
                            </div>
                            <div class="sg-card-body" style="padding: 0;">
                                <?php if (!empty($results['issues'])): ?>
                                    <table class="sg-logs-table">
                                        <thead>
                                            <tr>
                                                <th style="width: 100px;"><?php esc_html_e('Severity', 'spectrus-guard'); ?></th>
                                                <th style="width: 120px;"><?php esc_html_e('Category', 'spectrus-guard'); ?></th>
                                                <th><?php esc_html_e('Location', 'spectrus-guard'); ?></th>
                                                <th><?php esc_html_e('Issue Description', 'spectrus-guard'); ?></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($results['issues'] as $issue): ?>
                                                <tr>
                                                    <td>
                                                        <span
                                                            class="sg-badge sg-badge-<?php echo esc_attr(strtolower($issue['severity'])); ?>">
                                                            <?php echo esc_html(ucfirst($issue['severity'])); ?>
                                                        </span>
                                                    </td>
                                                    <td><span class="sg-tag"><?php echo esc_html(ucfirst($issue['category'])); ?></span>
                                                    </td>
                                                    <td style="font-family: monospace; color: var(--sg-text-muted);">
                                                        <?php echo esc_html($issue['file']); ?>
                                                    </td>
                                                    <td style="color: var(--sg-text-primary);">
                                                        <?php echo esc_html($issue['message']); ?>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                <?php else: ?>
                                    <div style="padding: 40px; text-align: center;">
                                        <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
                                        <h3 style="margin: 0;"><?php esc_html_e('Clean Scan!', 'spectrus-guard'); ?></h3>
                                        <p style="color: var(--sg-text-secondary);">
                                            <?php esc_html_e('No vulnerabilities detected in the last scan.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>

                    <?php else: ?>
                        <!-- Empty State -->
                        <div class="sg-card" style="text-align: center; padding: 60px 20px;">
                            <div style="font-size: 64px; margin-bottom: 24px; opacity: 0.5;">🔍</div>
                            <h2><?php esc_html_e('No Scan Results Yet', 'spectrus-guard'); ?></h2>
                            <p style="color: var(--sg-text-secondary); max-width: 500px; margin: 0 auto 24px;">
                                <?php esc_html_e('Run your first security scan to detect malware, backdoors, and configuration issues on your WordPress site.', 'spectrus-guard'); ?>
                            </p>
                            <button type="button" class="sg-btn sg-btn-primary sg-btn-lg"
                                onclick="document.getElementById('sg-run-scan').click();">
                                <?php esc_html_e('Start Initial Scan', 'spectrus-guard'); ?>
                            </button>
                        </div>
                    <?php endif; ?>

                </div>
            </div>
        </div>

        <?php
    }

    /**
     * AJAX: Write .htaccess rules for Ghost Cloak
     */
    public function ajax_write_htaccess()
    {
        check_ajax_referer('spectrus_shield_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'spectrus-guard'));
        }

        if (!class_exists('Spectrus_Cloak_Engine')) {
            $engine_path = SG_PLUGIN_DIR . 'includes/hardening/class-sg-cloak-engine.php';
            if (file_exists($engine_path)) {
                require_once $engine_path;
            } else {
                wp_send_json_error(__('Cloak Engine not found.', 'spectrus-guard'));
            }
        }

        $rules = Spectrus_Cloak_Engine::generate_apache_rules();
        $htaccess_path = ABSPATH . '.htaccess';

        if (!file_exists($htaccess_path)) {
            // Attempt to create it
            if (!file_put_contents($htaccess_path, '')) {
                wp_send_json_error(__('Could not create .htaccess file.', 'spectrus-guard'));
            }
        }

        // Use WordPress core function to write safely
        require_once ABSPATH . 'wp-admin/includes/misc.php';

        $lines = [];
        $lines[] = '<IfModule mod_rewrite.c>';
        $lines[] = 'RewriteEngine On';
        $lines[] = 'RewriteRule ^content/skins/(.*) wp-content/themes/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/modules/(.*) wp-content/plugins/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/media/(.*) wp-content/uploads/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^core/lib/(.*) wp-includes/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/modules/ui-builder/(.*) wp-content/plugins/elementor/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/modules/shop-core/(.*) wp-content/plugins/woocommerce/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/modules/forms/(.*) wp-content/plugins/contact-form-7/$1 [L,QSA]';
        $lines[] = 'RewriteRule ^content/modules/meta-engine/(.*) wp-content/plugins/yoast-seo/$1 [L,QSA]';
        $lines[] = '</IfModule>';

        $result = insert_with_markers($htaccess_path, 'SpectrusGuardCloak', $lines);

        if ($result) {
            wp_send_json_success();
        } else {
            wp_send_json_error(__('Could not write to .htaccess. Please check file permissions.', 'spectrus-guard'));
        }
    }
}
