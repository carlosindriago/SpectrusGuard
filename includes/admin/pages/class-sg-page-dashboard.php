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
    }

    /**
     * Render the main dashboard page
     */
    public function render()
    {
        $settings = $this->loader->get_settings();
        $logger = $this->loader->get_logger();
        $stats = get_option('spectrus_shield_stats', array());
        $scan_results = get_option('spectrus_shield_scan_results', array());
        $last_scan = get_option('spectrus_shield_last_scan_time');

        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'overview';

        // Overview Logic
        $threats_found = 0;
        if (!empty($scan_results)) {
            foreach ($scan_results as $result) {
                if (isset($result['severity']) && in_array($result['severity'], array('critical', 'high', 'medium'))) {
                    $threats_found++;
                }
            }
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
                                    <button type="button" class="sg-copy-btn-icon" aria-label="<?php esc_attr_e('Copy rescue URL to clipboard', 'spectrus-guard'); ?>" title="<?php esc_attr_e('Copy rescue URL to clipboard', 'spectrus-guard'); ?>"
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
}
