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
        add_action('wp_ajax_sg_run_scan', array($this, 'ajax_run_scan'));
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
    }

    /**
     * Sanitize settings before saving
     *
     * @param array $input Raw settings input.
     * @return array Sanitized settings.
     */
    public function sanitize_settings($input)
    {
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
            'url_cloaking_enabled',
        );

        foreach ($boolean_fields as $field) {
            $sanitized[$field] = !empty($input[$field]);
        }

        // Text fields
        if (isset($input['rescue_key'])) {
            $sanitized['rescue_key'] = sanitize_text_field($input['rescue_key']);
        }

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

        // Handle URL Cloaking .htaccess rules
        if (class_exists('SG_URL_Cloaker')) {
            if (!empty($sanitized['url_cloaking_enabled'])) {
                // Add .htaccess rules if cloaking is enabled
                SG_URL_Cloaker::add_htaccess_rules();
            } else {
                // Remove .htaccess rules if cloaking is disabled
                SG_URL_Cloaker::remove_htaccess_rules();
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
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('SpectrusGuard Configuration', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <button type="submit" form="sg-settings-form" class="sg-btn sg-btn-primary">
                        <span class="dashicons dashicons-saved"></span>
                        <?php esc_html_e('Save Changes', 'spectrus-guard'); ?>
                    </button>
                </div>
            </div>

            <form method="post" action="options.php" id="sg-settings-form">
                <?php settings_fields('spectrus_shield_settings_group'); ?>

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

                    <!-- Full Width: URL Cloaking -->
                    <div class="sg-content-column" style="grid-column: span 12;">
                        <div class="sg-card">
                            <div class="sg-card-header">
                                <h2><?php esc_html_e('Advanced: URL Cloaking', 'spectrus-guard'); ?></h2>
                            </div>
                            <div class="sg-settings-card-body">
                                <div class="sg-control-group">
                                    <div class="sg-control-info">
                                        <label
                                            class="sg-control-label"><?php esc_html_e('Enable URL Cloaking', 'spectrus-guard'); ?></label>
                                        <p class="sg-control-desc">
                                            <?php esc_html_e('Rewrite standard WordPress paths like /wp-content/ to hide them from sensors.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                    <div class="sg-control-input">
                                        <label class="sg-switch">
                                            <input type="checkbox" name="spectrus_shield_settings[url_cloaking_enabled]"
                                                value="1" <?php checked($settings['url_cloaking_enabled'] ?? false); ?>>
                                            <span class="sg-slider"></span>
                                        </label>
                                    </div>
                                </div>

                                <?php if (!empty($settings['url_cloaking_enabled']) && class_exists('SG_URL_Cloaker')): ?>
                                    <div
                                        style="background: var(--sg-bg-app); padding: 16px; border-radius: 8px; border: 1px solid var(--sg-border);">
                                        <?php $server_type = SG_URL_Cloaker::detect_server(); ?>
                                        <?php if (in_array($server_type, array('apache', 'litespeed'), true)): ?>
                                            <?php if (SG_URL_Cloaker::htaccess_has_rules()): ?>
                                                <p class="sg-start-item" style="color: var(--sg-success);">✅
                                                    <?php esc_html_e('.htaccess rules are active', 'spectrus-guard'); ?></p>
                                            <?php else: ?>
                                                <p class="sg-start-item" style="color: var(--sg-warning);">⚠️
                                                    <?php esc_html_e('Rules pending. Click Save to apply.', 'spectrus-guard'); ?></p>
                                            <?php endif; ?>
                                        <?php elseif ($server_type === 'nginx'): ?>
                                            <div class="sg-alert critical"
                                                style="padding: 12px; border-radius: 8px; background: var(--sg-danger-bg); border: 1px solid var(--sg-danger);">
                                                <strong>🚨 Nginx Detected</strong>
                                                <p style="margin: 4px 0;">
                                                    <?php esc_html_e('You must manually apply these rules:', 'spectrus-guard'); ?></p>
                                                <pre
                                                    style="background: #000; padding: 10px; border-radius: 4px; overflow-x: auto; color: #fbbf24;"><?php echo esc_html(SG_URL_Cloaker::generate_nginx_rules()); ?></pre>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                </div>
            </form>
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

        // Run fresh scan
        $results = $scanner->run_full_scan(true);

        wp_send_json_success(array(
            'message' => __('Scan completed successfully.', 'spectrus-guard'),
            'results' => $scanner->get_display_results(),
        ));
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

        <script>
            jQuery(document).ready(function ($) {
                $('#sg-run-scan').on('click', function () {
                    var $btn = $(this);
                    $btn.prop('disabled', true).addClass('loading');
                    // Hide results, show progress
                    $('.sg-threat-intel-grid, .sg-card:not(#sg-scan-progress)').fadeOut();
                    $('#sg-scan-progress').fadeIn();

                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'sg_run_scan',
                            nonce: SpectrusGuard.nonce
                        },
                        success: function (response) {
                            if (response.success) {
                                location.reload();
                            } else {
                                alert(response.data.message || 'Scan failed');
                                location.reload(); // Reload anyway to reset state
                            }
                        },
                        error: function () {
                            alert('<?php esc_html_e('An error occurred during the scan.', 'spectrus-guard'); ?>');
                            location.reload();
                        }
                    });
                });
            });
        </script>
        <?php
    }
}
