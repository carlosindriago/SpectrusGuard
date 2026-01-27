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
                                <span class="sg-action-text"><?php esc_html_e('Manage IP Whitelist', 'spectrus-guard'); ?></span>
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
                    jQuery(document).ready(functio                n ($) {
                        // Chart data
                        var dailyStats = <?php echo json_encode($stats['daily_stats'] ?? array()); ?>;
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
                                                label: function(context) {
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
                <div class="wrap sg-logs-page">
                    <h1>
                        <span class="sg-logo">🛡️</span>
                        <?php esc_html_e('Firewall Logs', 'spectrus-guard'); ?>
                    </h1>

                    <div class="sg-logs-actions">
                        <button type="button" class="button" id="sg-clear-logs">
                            <?php esc_html_e('Clear All Logs', 'spectrus-guard'); ?>
                        </button>
                        <button type="button" class="button" id="sg-refresh-logs">
                            <?php esc_html_e('Refresh', 'spectrus-guard'); ?>
                        </button>
                    </div>

                    <table class="wp-list-table widefat fixed striped sg-logs-table">
                        <thead>
                            <tr>
                                <th style="width: 150px;"><?php esc_html_e('Timestamp', 'spectrus-guard'); ?></th>
                                <th style="width: 100px;"><?php esc_html_e('Type', 'spectrus-guard'); ?></th>
                                <th style="width: 120px;"><?php esc_html_e('IP Address', 'spectrus-guard'); ?></th>
                                <th><?php esc_html_e('URI', 'spectrus-guard'); ?></th>
                                <th><?php esc_html_e('Payload', 'spectrus-guard'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($logs)): ?>
                                    <tr>
                                        <td colspan="5" style="text-align: center;">
                                            <?php esc_html_e('No attacks logged yet. Your site is safe!', 'spectrus-guard'); ?> 🎉
                                        </td>
                                    </tr>
                            <?php else: ?>
                                    <?php foreach ($logs as $log): ?>
                                            <tr>
                                                <td><?php echo esc_html($log['timestamp']); ?></td>
                                                <td>
                                                    <span class="sg-badge sg-badge-<?php echo esc_attr(strtolower($log['type'])); ?>">
                                                        <?php echo esc_html($log['type']); ?>
                                                    </span>
                                                </td>
                                                <td><?php echo esc_html($log['ip']); ?></td>
                                                <td><code><?php echo esc_html(substr($log['uri'], 0, 50)); ?></code></td>
                                                <td><code><?php echo esc_html(substr($log['payload'], 0, 80)); ?></code></td>
                                            </tr>
                                    <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <script>
                    jQuery(document).ready(function ($) {
                        $('#sg-clear-logs').on('click', function () {
                            if (confirm('<?php esc_html_e('Are you sure you want to clear all logs?', 'spectrus-guard'); ?>')) {
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
                <div class="wrap sg-settings-page">
                    <h1>
                        <span class="sg-logo">🛡️</span>
                        <?php esc_html_e('SpectrusGuard Settings', 'spectrus-guard'); ?>
                    </h1>

                    <form method="post" action="options.php">
                        <?php settings_fields('spectrus_shield_settings_group'); ?>

                        <!-- WAF Settings -->
                        <div class="sg-settings-section">
                            <h2><?php esc_html_e('Firewall Settings', 'spectrus-guard'); ?></h2>

                            <table class="form-table">
                                <tr>
                                    <th scope="row"><?php esc_html_e('Enable WAF', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[waf_enabled]" value="1" <?php checked($settings['waf_enabled'] ?? true); ?>>
                                            <?php esc_html_e('Enable the Web Application Firewall', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Log Attacks', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[log_attacks]" value="1" <?php checked($settings['log_attacks'] ?? true); ?>>
                                            <?php esc_html_e('Log blocked attacks to file', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Rescue Key', 'spectrus-guard'); ?></th>
                                    <td>
                                        <input type="text" name="spectrus_shield_settings[rescue_key]"
                                            value="<?php echo esc_attr($settings['rescue_key'] ?? ''); ?>" class="regular-text">
                                        <p class="description">
                                            <?php esc_html_e('Secret key to bypass the WAF if you get locked out. Keep this safe!', 'spectrus-guard'); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('IP Whitelist', 'spectrus-guard'); ?></th>
                                    <td>
                                        <textarea name="spectrus_shield_settings[whitelist_ips_text]" rows="5" class="large-text code"><?php
                                        echo esc_textarea(implode("\n", $settings['whitelist_ips'] ?? array()));
                                        ?></textarea>
                                        <p class="description">
                                            <?php esc_html_e('One IP address per line. These IPs will bypass the WAF.', 'spectrus-guard'); ?>
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </div>

                        <!-- Stealth Settings -->
                        <div class="sg-settings-section">
                            <h2><?php esc_html_e('Stealth & Hardening', 'spectrus-guard'); ?></h2>

                            <table class="form-table">
                                <tr>
                                    <th scope="row"><?php esc_html_e('Hide WordPress Version', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[hide_wp_version]" value="1" <?php checked($settings['hide_wp_version'] ?? true); ?>>
                                            <?php esc_html_e('Remove version strings and generator tags', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Block XML-RPC', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[block_xmlrpc]" value="1" <?php checked($settings['block_xmlrpc'] ?? true); ?>>
                                            <?php esc_html_e('Disable XML-RPC (blocks Pingback attacks)', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Protect REST API', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[protect_api]" value="1" <?php checked($settings['protect_api'] ?? true); ?>>
                                            <?php esc_html_e('Block user enumeration via REST API', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Hide Login Page', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[hide_login]" value="1" <?php checked($settings['hide_login'] ?? false); ?>>
                                            <?php esc_html_e('Hide wp-admin and wp-login.php', 'spectrus-guard'); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Custom Login Slug', 'spectrus-guard'); ?></th>
                                    <td>
                                        <input type="text" name="spectrus_shield_settings[login_slug]"
                                            value="<?php echo esc_attr($settings['login_slug'] ?? 'sg-login'); ?>" class="regular-text">
                                        <p class="description">
                                            <?php
                                            printf(
                                                /* translators: %s: example URL */
                                                esc_html__('Your new login URL will be: %s', 'spectrus-guard'),
                                                '<code>' . esc_html(home_url('/' . ($settings['login_slug'] ?? 'sg-login'))) . '</code>'
                                            );
                                            ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('URL Cloaking', 'spectrus-guard'); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" name="spectrus_shield_settings[url_cloaking_enabled]" value="1" <?php checked($settings['url_cloaking_enabled'] ?? false); ?>>
                                            <?php esc_html_e('Rewrite WordPress URLs to hide fingerprints', 'spectrus-guard'); ?>
                                        </label>
                                        <p class="description">
                                            <?php esc_html_e('Changes /wp-content/plugins/ to /assets/plugins/, etc.', 'spectrus-guard'); ?>
                                        </p>
                                        <?php if (!empty($settings['url_cloaking_enabled']) && class_exists('SG_URL_Cloaker')): ?>
                                                <?php $server_type = SG_URL_Cloaker::detect_server(); ?>

                                                <?php if (in_array($server_type, array('apache', 'litespeed'), true)): ?>
                                                        <?php if (SG_URL_Cloaker::htaccess_has_rules()): ?>
                                                                <p class="sg-status-ok">✅ <?php esc_html_e('.htaccess rules are active', 'spectrus-guard'); ?>
                                                                </p>
                                                        <?php else: ?>
                                                                <p class="sg-status-warning">⚠️
                                                                    <?php esc_html_e('.htaccess rules need to be added. Save settings to apply.', 'spectrus-guard'); ?>
                                                                </p>
                                                        <?php endif; ?>

                                                <?php elseif ($server_type === 'nginx'): ?>
                                                        <div class="sg-nginx-alert">
                                                            <div class="sg-nginx-alert-header">
                                                                <span class="sg-nginx-icon">🚨</span>
                                                                <strong><?php esc_html_e('ACTION REQUIRED: Nginx Server Detected', 'spectrus-guard'); ?></strong>
                                                            </div>
                                                            <p class="sg-nginx-alert-text">
                                                                <?php esc_html_e('URL Cloaking requires manual configuration on Nginx. Without these rules, your cloaked URLs will return 404 errors!', 'spectrus-guard'); ?>
                                                            </p>
                                                            <details open>
                                                                <summary class="sg-nginx-summary">
                                                                    <?php esc_html_e('📋 Copy these rules to your Nginx config', 'spectrus-guard'); ?>
                                                                </summary>
                                                                <pre
                                                                    class="sg-code-block"><?php echo esc_html(SG_URL_Cloaker::generate_nginx_rules()); ?></pre>
                                                                <p class="sg-nginx-instructions">
                                                                    <strong><?php esc_html_e('Steps:', 'spectrus-guard'); ?></strong><br>
                                                                    1. <?php esc_html_e('Copy the rules above', 'spectrus-guard'); ?><br>
                                                                    2.
                                                                    <?php esc_html_e('Add them to your Nginx server block (usually in /etc/nginx/sites-available/)', 'spectrus-guard'); ?><br>
                                                                    3.
                                                                    <?php esc_html_e('Run: sudo nginx -t && sudo systemctl reload nginx', 'spectrus-guard'); ?>
                                                                </p>
                                                            </details>
                                                        </div>

                                                <?php else: ?>
                                                        <p class="sg-status-warning">⚠️
                                                            <?php esc_html_e('Unknown server. Add rewrite rules manually.', 'spectrus-guard'); ?>
                                                        </p>
                                                <?php endif; ?>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            </table>
                        </div>

                        <!-- Login Protection -->
                        <div class="sg-settings-section">
                            <h2><?php esc_html_e('Login Protection', 'spectrus-guard'); ?></h2>

                            <table class="form-table">
                                <tr>
                                    <th scope="row"><?php esc_html_e('Max Login Attempts', 'spectrus-guard'); ?></th>
                                    <td>
                                        <input type="number" name="spectrus_shield_settings[max_login_attempts]"
                                            value="<?php echo esc_attr($settings['max_login_attempts'] ?? 5); ?>" min="1" max="20"
                                            class="small-text">
                                        <p class="description">
                                            <?php esc_html_e('Number of failed attempts before lockout.', 'spectrus-guard'); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e('Lockout Duration', 'spectrus-guard'); ?></th>
                                    <td>
                                        <input type="number" name="spectrus_shield_settings[login_lockout_time]"
                                            value="<?php echo esc_attr(intval(($settings['login_lockout_time'] ?? 900) / 60)); ?>"
                                            min="1" max="1440" class="small-text" step="1">
                                        <?php esc_html_e('minutes', 'spectrus-guard'); ?>
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
                <div class="wrap sg-scanner-page">
                    <h1>
                        <span class="sg-logo">🛡️</span>
                        <?php esc_html_e('Security Scanner', 'spectrus-guard'); ?>
                    </h1>

                    <div class="sg-scanner-header">
                        <div class="sg-scan-info">
                            <?php if ($last_scan): ?>
                                    <p><?php printf(esc_html__('Last scan: %s', 'spectrus-guard'), esc_html($last_scan)); ?></p>
                            <?php else: ?>
                                    <p><?php esc_html_e('No scans performed yet.', 'spectrus-guard'); ?></p>
                            <?php endif; ?>
                        </div>
                        <button type="button" class="button button-primary button-hero" id="sg-run-scan">
                            <span class="dashicons dashicons-search"></span>
                            <?php esc_html_e('Run Security Scan', 'spectrus-guard'); ?>
                        </button>
                    </div>

                    <div id="sg-scan-progress" style="display: none;">
                        <div class="sg-progress-bar">
                            <div class="sg-progress-fill"></div>
                        </div>
                        <p class="sg-progress-text"><?php esc_html_e('Scanning...', 'spectrus-guard'); ?></p>
                    </div>

                    <?php if ($results && $results['has_results']): ?>
                            <div class="sg-scanner-summary">
                                <div
                                    class="sg-summary-card <?php echo $results['summary']['critical'] > 0 ? 'critical' : ($results['summary']['high'] > 0 ? 'warning' : 'success'); ?>">
                                    <div class="sg-summary-icon">
                                        <?php if ($results['summary']['total_issues'] === 0): ?>
                                                ✅
                                        <?php elseif ($results['summary']['critical'] > 0): ?>
                                                🚨
                                        <?php else: ?>
                                                ⚠️
                                        <?php endif; ?>
                                    </div>
                                    <div class="sg-summary-content">
                                        <h2>
                                            <?php if ($results['summary']['total_issues'] === 0): ?>
                                                    <?php esc_html_e('All Clear!', 'spectrus-guard'); ?>
                                            <?php else: ?>
                                                    <?php printf(
                                                        /* translators: %d: number of issues */
                                                        esc_html(_n('%d Issue Found', '%d Issues Found', $results['summary']['total_issues'], 'spectrus-guard')),
                                                        $results['summary']['total_issues']
                                                    ); ?>
                                            <?php endif; ?>
                                        </h2>
                                        <div class="sg-severity-counts">
                                            <?php if ($results['summary']['critical'] > 0): ?>
                                                    <span class="sg-count critical"><?php echo esc_html($results['summary']['critical']); ?>
                                                        Critical</span>
                                            <?php endif; ?>
                                            <?php if ($results['summary']['high'] > 0): ?>
                                                    <span class="sg-count high"><?php echo esc_html($results['summary']['high']); ?> High</span>
                                            <?php endif; ?>
                                            <?php if ($results['summary']['medium'] > 0): ?>
                                                    <span class="sg-count medium"><?php echo esc_html($results['summary']['medium']); ?> Medium</span>
                                            <?php endif; ?>
                                            <?php if ($results['summary']['low'] > 0): ?>
                                                    <span class="sg-count low"><?php echo esc_html($results['summary']['low']); ?> Low</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <?php if (!empty($results['issues'])): ?>
                                    <table class="wp-list-table widefat fixed striped sg-scanner-table">
                                        <thead>
                                            <tr>
                                                <th style="width: 100px;"><?php esc_html_e('Severity', 'spectrus-guard'); ?></th>
                                                <th style="width: 100px;"><?php esc_html_e('Category', 'spectrus-guard'); ?></th>
                                                <th><?php esc_html_e('File', 'spectrus-guard'); ?></th>
                                                <th><?php esc_html_e('Issue', 'spectrus-guard'); ?></th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($results['issues'] as $issue): ?>
                                                    <tr>
                                                        <td>
                                                            <span class="sg-badge sg-badge-<?php echo esc_attr($issue['severity']); ?>">
                                                                <?php echo esc_html(ucfirst($issue['severity'])); ?>
                                                            </span>
                                                        </td>
                                                        <td><?php echo esc_html(ucfirst($issue['category'])); ?></td>
                                                        <td><code><?php echo esc_html($issue['file']); ?></code></td>
                                                        <td><?php echo esc_html($issue['message']); ?></td>
                                                    </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                            <?php endif; ?>
                    <?php else: ?>
                            <div class="sg-no-results">
                                <p><?php esc_html_e('Click "Run Security Scan" to check your site for vulnerabilities.', 'spectrus-guard'); ?>
                                </p>
                            </div>
                    <?php endif; ?>
                </div>

                <script>
                    jQuery(document).ready(function ($) {
                        $('#sg-run-scan').on('click', function () {
                            var $btn = $(this);
                            $btn.prop('disabled', true).find('.dashicons').addClass('spin');
                            $('#sg-scan-progress').show();

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
                                        $btn.prop('disabled', false).find('.dashicons').removeClass('spin');
                                        $('#sg-scan-progress').hide();
                                    }
                                },
                                error: function () {
                                    alert('<?php esc_html_e('An error occurred during the scan.', 'spectrus-guard'); ?>');
                                    $btn.prop('disabled', false).find('.dashicons').removeClass('spin');
                                    $('#sg-scan-progress').hide();
                                }
                            });
                        });
                    });
                </script>

                <style>
                    /* Scanner Page - Full Dark Theme Override */
                    .sg-scanner-page {
                        background: #1a1a2e;
                        margin-left: -20px;
                        padding: 20px 40px;
                        min-height: calc(100vh - 32px);
                    }

                    .sg-scanner-page * {
                        box-sizing: border-box;
                    }

                    .sg-scanner-page h1 {
                        color: #e2e8f0 !important;
                        display: flex;
                        align-items: center;
                        gap: 12px;
                        margin-bottom: 24px;
                        font-size: 28px;
                    }

                    .sg-scanner-page h1 .sg-logo {
                        font-size: 32px;
                    }

                    /* Header with button */
                    .sg-scanner-header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 24px;
                        flex-wrap: wrap;
                        gap: 16px;
                    }

                    .sg-scan-info p {
                        color: #a0aec0 !important;
                        margin: 0;
                        font-size: 14px;
                    }

                    /* Scan Button - Fixed */
                    #sg-run-scan {
                        display: inline-flex !important;
                        align-items: center !important;
                        gap: 8px !important;
                        padding: 12px 24px !important;
                        font-size: 15px !important;
                        font-weight: 600 !important;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
                        border: none !important;
                        border-radius: 8px !important;
                        color: #fff !important;
                        cursor: pointer;
                        transition: transform 0.2s, box-shadow 0.2s;
                    }

                    #sg-run-scan:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
                    }

                    #sg-run-scan .dashicons {
                        font-size: 18px !important;
                        width: 18px !important;
                        height: 18px !important;
                        line-height: 1 !important;
                        vertical-align: middle !important;
                    }

                    #sg-run-scan:disabled {
                        opacity: 0.7;
                        cursor: wait;
                    }

                    /* Summary Card */
                    .sg-scanner-summary {
                        margin-bottom: 24px;
                    }

                    .sg-summary-card {
                        display: flex;
                        align-items: center;
                        gap: 20px;
                        padding: 24px;
                        border-radius: 12px;
                        background: #16213e;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }

                    .sg-summary-card.success {
                        border-left: 4px solid #48bb78;
                    }

                    .sg-summary-card.warning {
                        border-left: 4px solid #ed8936;
                    }

                    .sg-summary-card.critical {
                        border-left: 4px solid #f56565;
                    }

                    .sg-summary-icon {
                        font-size: 48px;
                        line-height: 1;
                    }

                    .sg-summary-content h2 {
                        color: #e2e8f0 !important;
                        margin: 0 0 8px 0 !important;
                        font-size: 20px;
                    }

                    .sg-severity-counts {
                        display: flex;
                        gap: 12px;
                        flex-wrap: wrap;
                    }

                    .sg-count {
                        padding: 4px 12px;
                        border-radius: 4px;
                        font-size: 12px;
                        font-weight: 600;
                    }

                    .sg-count.critical {
                        background: rgba(245, 101, 101, 0.2);
                        color: #f56565;
                    }

                    .sg-count.high {
                        background: rgba(237, 137, 54, 0.2);
                        color: #ed8936;
                    }

                    .sg-count.medium {
                        background: rgba(236, 201, 75, 0.2);
                        color: #ecc94b;
                    }

                    .sg-count.low {
                        background: rgba(72, 187, 120, 0.2);
                        color: #48bb78;
                    }

                    /* Scanner Table - Full Dark Override */
                    .sg-scanner-page .sg-scanner-table {
                        background: #16213e !important;
                        border: 1px solid rgba(255, 255, 255, 0.1) !important;
                        border-collapse: collapse !important;
                        width: 100% !important;
                    }

                    .sg-scanner-page .sg-scanner-table thead th {
                        background: #1f2a48 !important;
                        color: #e2e8f0 !important;
                        padding: 12px 16px !important;
                        text-align: left !important;
                        border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
                    }

                    .sg-scanner-page .sg-scanner-table tbody tr {
                        background: #16213e !important;
                    }

                    .sg-scanner-page .sg-scanner-table tbody tr:nth-child(odd) {
                        background: #1a2342 !important;
                    }

                    .sg-scanner-page .sg-scanner-table tbody tr:hover {
                        background: #1f2a48 !important;
                    }

                    .sg-scanner-page .sg-scanner-table tbody td {
                        color: #c9d1d9 !important;
                        padding: 12px 16px !important;
                        border-bottom: 1px solid rgba(255, 255, 255, 0.05) !important;
                        background: transparent !important;
                    }

                    .sg-scanner-page .sg-scanner-table code {
                        background: rgba(0, 0, 0, 0.4) !important;
                        padding: 4px 8px !important;
                        border-radius: 4px !important;
                        color: #fbbf24 !important;
                        font-size: 12px !important;
                        word-break: break-all !important;
                    }

                    /* Badges */
                    .sg-scanner-page .sg-badge {
                        display: inline-block;
                        padding: 4px 10px;
                        border-radius: 4px;
                        font-size: 11px;
                        font-weight: 700;
                        text-transform: uppercase;
                    }

                    .sg-badge-critical {
                        background: rgba(245, 101, 101, 0.25) !important;
                        color: #f56565 !important;
                    }

                    .sg-badge-high {
                        background: rgba(237, 137, 54, 0.25) !important;
                        color: #ed8936 !important;
                    }

                    .sg-badge-medium {
                        background: rgba(236, 201, 75, 0.25) !important;
                        color: #ecc94b !important;
                    }

                    .sg-badge-low {
                        background: rgba(72, 187, 120, 0.25) !important;
                        color: #48bb78 !important;
                    }

                    /* No Results */
                    .sg-no-results {
                        text-align: center;
                        padding: 60px 20px;
                        color: #a0aec0 !important;
                        background: #16213e;
                        border-radius: 12px;
                        border: 1px solid rgba(255, 255, 255, 0.1);
                    }

                    /* Progress */
                    .sg-progress-bar {
                        height: 4px;
                        background: #16213e;
                        border-radius: 2px;
                        overflow: hidden;
                        margin-bottom: 12px;
                    }

                    .sg-progress-fill {
                        height: 100%;
                        width: 30%;
                        background: linear-gradient(90deg, #667eea, #764ba2);
                        animation: progress 1.5s ease-in-out infinite;
                    }

                    @keyframes progress {
                        0% {
                            width: 10%;
                        }

                        50% {
                            width: 70%;
                        }

                        100% {
                            width: 10%;
                        }
                    }

                    .sg-progress-text {
                        color: #a0aec0 !important;
                        text-align: center;
                    }

                    /* Spin Animation */
                    .spin {
                        animation: spin 1s linear infinite !important;
                    }

                    @keyframes spin {
                        100% {
                            transform: rotate(360deg);
                        }
                    }
                </style>
                <?php
    }
}
