<?php
/**
 * Page Controller: Dashboard
 *
 * @package SpectrusGuard
 */

if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Dashboard
{
    private $loader;

    public function __construct($loader)
    {
        $this->loader = $loader;
        // AJAX Hooks for Dashboard
        add_action('wp_ajax_sg_get_stats', array($this, 'ajax_get_stats'));
        add_action('wp_ajax_sg_quick_action', array($this, 'ajax_handle_quick_action'));
    }

    /**
     * Render the main dashboard page
     */
    public function render()
    {
        $settings = $this->loader->get_settings();
        $logger = $this->loader->get_logger();
        $alerts = $this->get_security_alerts($settings);

        // Read attack stats from the correct option (WAF writes to 'spectrus_shield_attack_stats')
        $stats = get_option('spectrus_shield_attack_stats', array());

        // Read scan results from the correct option (scanner saves to 'spectrus_guard_scan_report')
        $scan_results = get_option('spectrus_guard_scan_report', array());

        // Read last scan time from the correct option (scanner saves to 'spectrus_shield_last_scan')
        $last_scan = get_option('spectrus_shield_last_scan');

        $active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'overview';

        // Overview Logic - count threats from scan report summary
        $threats_found = 0;
        if (!empty($scan_results) && isset($scan_results['summary'])) {
            // The scan report structure has summary.critical, summary.high, summary.medium
            $summary = $scan_results['summary'];
            $threats_found = ($summary['critical'] ?? 0) + ($summary['high'] ?? 0) + ($summary['medium'] ?? 0);
        }
        $scan_status = 'never';
        if ($last_scan) {
            $days_since_scan = floor((time() - strtotime($last_scan)) / DAY_IN_SECONDS);
            $scan_status = ($days_since_scan > 7) ? 'old' : 'recent';
        }
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('SpectrusGuard Security', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-version-badge">v
                    <?php echo esc_html(SG_VERSION); ?>
                </div>
            </div>

            <?php if (!empty($alerts)): ?>
                <div class="sg-alerts-wrapper" style="margin: -32px -32px 32px -32px; width: calc(100% + 64px); display: flex; flex-direction: column; z-index: 100;">
                    <?php foreach ($alerts as $alert): ?>
                        <?php
                        // Define inline styles for background based on type
                        $bg_style = 'background: #1e293b;'; // Default
                        $text_style = 'color: #f8fafc;';
                        if ($alert['type'] === 'critical') {
                            $bg_style = 'background: #ef4444; color: white;';
                            $text_style = 'color: white;';
                        } elseif ($alert['type'] === 'warning') {
                            $bg_style = 'background: #f59e0b; color: rgba(0,0,0,0.8);';
                            $text_style = 'color: rgba(0,0,0,0.8);';
                        } elseif ($alert['type'] === 'info') {
                            $bg_style = 'background: #0ea5e9; color: white;';
                            $text_style = 'color: white;';
                        }
                        ?>
                        <div class="sg-alert sg-alert-<?php echo esc_attr($alert['type']); ?>" style="<?php echo $bg_style; ?> display: flex; align-items: center; gap: 20px; padding: 15px 32px; margin: 0; border-bottom: 1px solid rgba(0,0,0,0.1); border-radius: 0;">
                            <div class="sg-alert-icon" style="background: rgba(255,255,255,0.2); width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 6px; flex-shrink: 0;">
                                <?php echo $alert['icon']; ?>
                            </div>
                            <div class="sg-alert-content" style="flex: 1; display: flex; align-items: center; gap: 15px; flex-wrap: wrap;">
                                <strong style="<?php echo $text_style; ?> font-size: 15px;"><?php echo esc_html($alert['title']); ?></strong>
                                <span style="<?php echo $text_style; ?> opacity: 0.9; font-size: 14px;"><?php echo esc_html($alert['message']); ?></span>
                            </div>
                            <?php if (isset($alert['action_url'])): ?>
                                <a href="<?php echo esc_url($alert['action_url']); ?>" 
                                   class="sg-alert-action <?php echo isset($alert['quick_action']) ? 'sg-quick-action-btn' : ''; ?>"
                                   <?php if (isset($alert['quick_action'])): ?>
                                       data-action="<?php echo esc_attr($alert['quick_action']); ?>"
                                       data-nonce="<?php echo wp_create_nonce('sg_quick_action_' . $alert['quick_action']); ?>"
                                   <?php endif; ?>
                                   style="background: rgba(255,255,255,0.2); color: inherit; text-decoration: none; padding: 6px 14px; border-radius: 4px; font-weight: 600; font-size: 13px; white-space: nowrap;">
                                    <?php echo esc_html($alert['action_text']); ?> →
                                </a>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <h2 class="nav-tab-wrapper" style="margin-bottom: 20px; border-bottom: 1px solid #334155;">
                <a href="?page=spectrus-guard&tab=overview"
                    class="nav-tab <?php echo $active_tab == 'overview' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Overview', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard&tab=logs"
                    class="nav-tab <?php echo $active_tab == 'logs' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('Traffic Logs', 'spectrus-guard'); ?>
                </a>
            </h2>

            <?php if ($active_tab === 'overview'): ?>
                <?php $recent_logs = $logger ? $logger->get_logs(5) : array(); ?>

                <div class="sg-hero-panel">
                    <div class="sg-hero-status">
                        <div class="sg-hero-icon-wrapper">
                            <span class="sg-hero-icon">🛡️</span>
                            <div class="sg-hero-pulse"></div>
                        </div>
                        <div class="sg-hero-content">
                            <h2>
                                <?php esc_html_e('System Protected', 'spectrus-guard'); ?>
                            </h2>
                            <p>
                                <?php esc_html_e('WAF is active and monitoring traffic.', 'spectrus-guard'); ?>
                            </p>
                            <?php if ($scan_status === 'recent' && $threats_found === 0): ?>
                                <span class="sg-status-badge success">
                                    <span class="dashicons dashicons-yes" aria-hidden="true"></span>
                                    <?php esc_html_e('Last scan clean', 'spectrus-guard'); ?>
                                </span>
                            <?php elseif ($threats_found > 0): ?>
                                <span class="sg-status-badge danger">
                                    <span class="dashicons dashicons-warning" aria-hidden="true"></span>
                                    <?php echo intval($threats_found) . ' ' . esc_html__('threats found', 'spectrus-guard'); ?>
                                </span>
                            <?php else: ?>
                                <span class="sg-status-badge warning">
                                    <span class="dashicons dashicons-calendar-alt" aria-hidden="true"></span>
                                    <?php esc_html_e('Scan recommended', 'spectrus-guard'); ?>
                                </span>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="sg-hero-actions">
                        <div class="sg-last-scan-info">
                            <?php if ($last_scan): ?>
                                <?php echo esc_html__('Last scan:', 'spectrus-guard'); ?>
                                <strong>
                                    <?php echo esc_html(human_time_diff(strtotime($last_scan))) . ' ago'; ?>
                                </strong>
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
                    <div class="sg-content-column">
                        <h3 class="sg-section-title">
                            <?php esc_html_e('Threat Intelligence', 'spectrus-guard'); ?>
                        </h3>
                        <div class="sg-threat-intel-grid">
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon sqli">💉</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number">
                                        <?php echo esc_html($stats['sqli_blocked'] ?? 0); ?>
                                    </span>
                                    <span class="sg-stat-label">SQL Injection</span>
                                </div>
                            </div>
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon xss">⚡</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number">
                                        <?php echo esc_html($stats['xss_blocked'] ?? 0); ?>
                                    </span>
                                    <span class="sg-stat-label">XSS Attempts</span>
                                </div>
                            </div>
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon rce">🔓</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number">
                                        <?php echo esc_html($stats['rce_blocked'] ?? 0); ?>
                                    </span>
                                    <span class="sg-stat-label">RCE Exploits</span>
                                </div>
                            </div>
                            <div class="sg-stat-card">
                                <div class="sg-stat-icon traversal">📁</div>
                                <div class="sg-stat-data">
                                    <span class="sg-stat-number">
                                        <?php echo esc_html($stats['traversal_blocked'] ?? 0); ?>
                                    </span>
                                    <span class="sg-stat-label">Path Traversal</span>
                                </div>
                            </div>
                        </div>

                        <div class="sg-card sg-chart-card">
                            <div class="sg-card-header">
                                <h2>
                                    <?php esc_html_e('Attack Activity (Last 30 Days)', 'spectrus-guard'); ?>
                                </h2>
                            </div>
                            <div class="sg-card-body">
                                <canvas id="sg-activity-chart"></canvas>
                            </div>
                        </div>
                    </div>

                    <div class="sg-sidebar-column">
                        <div class="sg-card sg-actions-panel">
                            <div class="sg-card-header">
                                <h2>
                                    <?php esc_html_e('Quick Actions', 'spectrus-guard'); ?>
                                </h2>
                            </div>
                            <div class="sg-action-list">
                                <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard&tab=logs')); ?>"
                                    class="sg-action-item">
                                    <span class="dashicons dashicons-media-text"></span>
                                    <span class="sg-action-text">
                                        <?php esc_html_e('View Firewall Logs', 'spectrus-guard'); ?>
                                    </span>
                                    <span class="sg-action-arrow" aria-hidden="true">→</span>
                                </a>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-settings')); ?>"
                                    class="sg-action-item">
                                    <span class="dashicons dashicons-admin-settings"></span>
                                    <span class="sg-action-text">
                                        <?php esc_html_e('Global Settings', 'spectrus-guard'); ?>
                                    </span>
                                    <span class="sg-action-arrow" aria-hidden="true">→</span>
                                </a>
                                <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-firewall&tab=geo')); ?>"
                                    class="sg-action-item">
                                    <span class="dashicons dashicons-shield"></span>
                                    <span class="sg-action-text">
                                        <?php esc_html_e('Manage IP Whitelist', 'spectrus-guard'); ?>
                                    </span>
                                    <span class="sg-action-arrow" aria-hidden="true">→</span>
                                </a>
                            </div>
                        </div>

                        <div class="sg-card sg-rescue-panel">
                            <div class="sg-card-header warning-header">
                                <h2>⚠️
                                    <?php esc_html_e('Emergency Access', 'spectrus-guard'); ?>
                                </h2>
                            </div>
                            <div class="sg-card-body">
                                <p class="sg-rescue-desc">
                                    <?php esc_html_e('Use this URL if you get locked out:', 'spectrus-guard'); ?>
                                </p>
                                <div class="sg-rescue-input-group">
                                    <input type="text" readonly
                                        value="<?php echo esc_url(home_url('/?spectrus_rescue=' . ($settings['rescue_key'] ?? ''))); ?>"
                                        class="sg-rescue-input" id="sg-rescue-url">
                                    <button type="button" class="sg-copy-btn-icon"
                                        aria-label="<?php esc_attr_e('Copy rescue URL to clipboard', 'spectrus-guard'); ?>"
                                        title="<?php esc_attr_e('Copy rescue URL to clipboard', 'spectrus-guard'); ?>"
                                        onclick="navigator.clipboard.writeText(document.getElementById('sg-rescue-url').value)">
                                        <span class="dashicons dashicons-clipboard" aria-hidden="true"></span>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="sg-card sg-recent-activity">
                            <div class="sg-card-header">
                                <h2>
                                    <?php esc_html_e('Recent Activity', 'spectrus-guard'); ?>
                                </h2>
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
                                                <span class="sg-activity-type">
                                                    <?php echo esc_html($log['type']); ?>
                                                </span>
                                                <span class="sg-activity-ip">
                                                    <?php echo esc_html($log['ip']); ?>
                                                </span>
                                            </div>
                                            <div class="sg-activity-time">
                                                <?php echo esc_html(human_time_diff(strtotime($log['timestamp']))) . ' ago'; ?>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                    <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard&tab=logs')); ?>"
                                        class="sg-view-all-link">
                                        <?php esc_html_e('View All History', 'spectrus-guard'); ?> →
                                    </a>
                                <?php else: ?>
                                    <div class="sg-empty-state">
                                        <p>
                                            <?php esc_html_e('No recent security events.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>

                <script>
                    jQuery(document).ready(function ($) {
                        var dailyStats = <?php echo json_encode($stats['daily_stats'] ?? array()); ?>;
                        var labels = [];
                        var data = [];
                        for (var i = 29; i >= 0; i--) {
                            var date = new Date();
                            date.setDate(date.getDate() - i);
                            var dateStr = date.toISOString().split('T')[0];
                            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
                            data.push(dailyStats[dateStr] || 0);
                        }

                        if (typeof Chart !== 'undefined') {
                            var ctx = document.getElementById('sg-activity-chart').getContext('2d');
                            var gradient = ctx.createLinearGradient(0, 0, 0, 300);
                            gradient.addColorStop(0, 'rgba(59, 130, 246, 0.2)');
                            gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');

                            new Chart(ctx, {
                                type: 'line',
                                data: {
                                    labels: labels,
                                    datasets: [{
                                        label: 'Attacks Blocked',
                                        data: data,
                                        borderColor: '#3b82f6',
                                        backgroundColor: gradient,
                                        borderWidth: 2,
                                        fill: true,
                                        tension: 0.4
                                    }]
                                },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    plugins: { legend: { display: false } },
                                    scales: {
                                        y: { beginAtZero: true },
                                        x: { grid: { display: false } }
                                    }
                                }
                            });
                        }

                        $('.sg-copy-btn-icon').on('click', function () {
                            var $btn = $(this);
                            var $icon = $btn.find('.dashicons');
                            $icon.removeClass('dashicons-clipboard').addClass('dashicons-yes');
                            setTimeout(function () { $icon.removeClass('dashicons-yes').addClass('dashicons-clipboard'); }, 2000);
                        });
                    });
                </script>

            <?php elseif ($active_tab === 'logs'): ?>
                <?php $logs = $logger ? $logger->get_logs(100) : array(); ?>

                <div class="sg-main-layout">
                    <div class="sg-content-column" style="grid-column: span 12;">
                        <div class="sg-card">
                            <div class="sg-card-header">
                                <h2>
                                    <?php esc_html_e('Firewall Activity Log', 'spectrus-guard'); ?>
                                </h2>
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
                            <div class="sg-card-body" style="padding: 0;">
                                <table class="sg-logs-table">
                                    <thead>
                                        <tr>
                                            <th style="width: 180px;">
                                                <?php esc_html_e('Timestamp', 'spectrus-guard'); ?>
                                            </th>
                                            <th style="width: 120px;">
                                                <?php esc_html_e('Type', 'spectrus-guard'); ?>
                                            </th>
                                            <th style="width: 150px;">
                                                <?php esc_html_e('IP Address', 'spectrus-guard'); ?>
                                            </th>
                                            <th>
                                                <?php esc_html_e('Request URI', 'spectrus-guard'); ?>
                                            </th>
                                            <th>
                                                <?php esc_html_e('Payload', 'spectrus-guard'); ?>
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php if (empty($logs)): ?>
                                            <tr>
                                                <td colspan="5" style="text-align: center; padding: 40px; color: var(--sg-text-muted);">
                                                    <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
                                                    <p>
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

                <script>
                    jQuery(document).ready(function ($) {
                        $('#sg-clear-logs').on('click', function () {
                            if (confirm('<?php esc_html_e('Are you sure you want to delete all security logs?', 'spectrus-guard'); ?>')) {
                                $.post(ajaxurl, {
                                    action: 'sg_clear_logs',
                                    nonce: SpectrusGuard.nonce
                                }, function (response) {
                                    if (response.success) { location.reload(); }
                                });
                            }
                        });
                        $('#sg-refresh-logs').on('click', function () { location.reload(); });
                    });
                </script>
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
     * AJAX: Handle quick security actions
     */
    public function ajax_handle_quick_action()
    {
        $action = isset($_POST['security_action']) ? sanitize_text_field($_POST['security_action']) : '';
        check_ajax_referer('sg_quick_action_' . $action, 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Unauthorized'));
        }

        $settings = get_option('spectrus_guard_settings', array());
        $message = '';

        switch ($action) {
            case 'enable_waf':
                $settings['waf_enabled'] = 1;
                $message = __('WAF Enabled Successfully', 'spectrus-guard');
                break;
            case 'enable_login_protection':
                $settings['login_limit_enabled'] = 1;
                $message = __('Login Protection Enabled', 'spectrus-guard');
                break;
            case 'block_xmlrpc':
                $settings['block_xmlrpc'] = 1;
                $message = __('XML-RPC Disabled', 'spectrus-guard');
                break;
            default:
                wp_send_json_error(array('message' => 'Invalid action'));
        }

        update_option('spectrus_guard_settings', $settings);
        wp_send_json_success(array('message' => $message));
    }

    /**
     * Get security alerts based on current settings
     *
     * @param array $settings Current plugin settings
     * @return array List of alerts
     */
    private function get_security_alerts($settings)
    {
        $alerts = array();

        // Check WAF Status
        if (empty($settings['waf_enabled'])) {
            $alerts[] = array(
                'type' => 'critical',
                'icon' => '🔥',
                'title' => __('Firewall Disabled', 'spectrus-guard'),
                'message' => __('The Web Application Firewall is disabled. Your site is vulnerable to SQL injection and XSS attacks.', 'spectrus-guard'),
                'action_url' => '#',
                'action_text' => __('Enable WAF', 'spectrus-guard'),
                'quick_action' => 'enable_waf'
            );
        }

        // Check Login Guard Status
        if (empty($settings['login_limit_enabled'])) {
            $alerts[] = array(
                'type' => 'warning',
                'icon' => '🔐',
                'title' => __('Login Protection Disabled', 'spectrus-guard'),
                'message' => __('Brute force protection is off. Bots can attempt unlimited logins.', 'spectrus-guard'),
                'action_url' => '#',
                'action_text' => __('Enable Protection', 'spectrus-guard'),
                'quick_action' => 'enable_login_protection'
            );
        }

        // Check XML-RPC Status
        if (empty($settings['block_xmlrpc'])) {
            $alerts[] = array(
                'type' => 'info',
                'icon' => '⚠️',
                'title' => __('XML-RPC Enabled', 'spectrus-guard'),
                'message' => __('XML-RPC is often used for DDoS attacks. Consider disabling it if not used.', 'spectrus-guard'),
                'action_url' => '#',
                'action_text' => __('Disable XML-RPC', 'spectrus-guard'),
                'quick_action' => 'block_xmlrpc'
            );
        }

        return $alerts;
    }
}
