<?php
/**
 * SpectrusGuard Threat Analytics Dashboard Page
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Page_UEBA
 *
 * UEBA Dashboard page controller.
 */
class SG_Page_UEBA
{

    /**
     * Loader instance
     *
     * @var SG_Loader
     */
    private $loader;

    /**
     * UEBA Engine instance
     *
     * @var SG_UEBA_Engine|null
     */
    private $ueba_engine;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct(SG_Loader $loader)
    {
        $this->loader = $loader;
        $this->ueba_engine = $loader->get_ueba_engine();
    }

    /**
     * Render the UEBA Dashboard
     */
    public function render()
    {
        // Get analytics data
        $analytics = $this->get_analytics_data();

        ?>
        <div class="sg-ueba-dashboard">
            <div class="sg-header">
                <h1>
                    <span class="dashicons dashicons-chart-line"></span>
                    Threat Analytics & UEBA
                </h1>
                <p class="sg-subtitle">User and Entity Behavior Analytics - Real-time threat detection</p>
            </div>

            <!-- Risk Score Overview -->
            <div class="sg-section">
                <h2 class="sg-section-title">Risk Score Overview</h2>
                <div class="sg-risk-cards">
                    <div class="sg-risk-card low">
                        <div class="sg-card-header">
                            <span class="sg-risk-icon">✅</span>
                            <span class="sg-risk-level">LOW</span>
                        </div>
                        <div class="sg-card-value">
                            <?php echo esc_html($analytics['risk_distribution']['low']); ?>%
                        </div>
                        <div class="sg-card-desc">No immediate action required</div>
                    </div>

                    <div class="sg-risk-card medium">
                        <div class="sg-card-header">
                            <span class="sg-risk-icon">⚠️</span>
                            <span class="sg-risk-level">MEDIUM</span>
                        </div>
                        <div class="sg-card-value">
                            <?php echo esc_html($analytics['risk_distribution']['medium']); ?>%
                        </div>
                        <div class="sg-card-desc">Monitor for changes</div>
                    </div>

                    <div class="sg-risk-card high">
                        <div class="sg-card-header">
                            <span class="sg-risk-icon">🔶</span>
                            <span class="sg-risk-level">HIGH</span>
                        </div>
                        <div class="sg-card-value">
                            <?php echo esc_html($analytics['risk_distribution']['high']); ?>%
                        </div>
                        <div class="sg-card-desc">Additional verification</div>
                    </div>

                    <div class="sg-risk-card critical">
                        <div class="sg-card-header">
                            <span class="sg-risk-icon">🚨</span>
                            <span class="sg-risk-level">CRITICAL</span>
                        </div>
                        <div class="sg-card-value">
                            <?php echo esc_html($analytics['risk_distribution']['critical']); ?>%
                        </div>
                        <div class="sg-card-desc">Immediate action required</div>
                    </div>
                </div>
            </div>

            <!-- Real-Time Activity Chart -->
            <div class="sg-section">
                <h2 class="sg-section-title">Real-Time Security Events (Last 24h)</h2>
                <div class="sg-chart-container">
                    <canvas id="sgActivityChart"></canvas>
                </div>
            </div>

            <!-- Top Risky Users -->
            <div class="sg-section">
                <h2 class="sg-section-title">Top Risky Users</h2>
                <div class="sg-table-container">
                    <table class="sg-table">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Risk Score</th>
                                <th>Risk Level</th>
                                <th>Last Activity</th>
                                <th>Anomalies</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($analytics['top_risky_users'] as $user): ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html($user['username']); ?></strong>
                                    <div class="sg-subtext"><?php echo esc_html($user['email']); ?></div>
                                </td>
                                <td>
                                    <div class="sg-risk-score-bar">
                                        <div class="sg-risk-fill" style="width: <?php echo esc_attr($user['risk_score']); ?>%; background-color: <?php echo esc_attr($user['risk_color']); ?>"></div>
                                    </div>
                                    <span class="sg-risk-value"><?php echo esc_html($user['risk_score']); ?>/100</span>
                                </td>
                                <td>
                                    <span class="sg-badge <?php echo esc_attr(strtolower($user['risk_level'])); ?>">
                                        <?php echo esc_html($user['risk_level']); ?>
                                    </span>
                                </td>
                                <td><?php echo esc_html($user['last_activity']); ?></td>
                                <td><?php echo esc_html($user['anomaly_count']); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Top Risky IPs -->
            <div class="sg-section">
                <h2 class="sg-section-title">Top Risky IPs (Last 24h)</h2>
                <div class="sg-table-container">
                    <table class="sg-table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Failed Logins</th>
                                <th>Anomalies</th>
                                <th>Last Seen</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($analytics['top_risky_ips'] as $ip): ?>
                            <tr>
                                <td><strong><?php echo esc_html($ip['address']); ?></strong></td>
                                <td><?php echo esc_html($ip['failed_logins']); ?></td>
                                <td><?php echo esc_html($ip['anomaly_count']); ?></td>
                                <td><?php echo esc_html($ip['last_seen']); ?></td>
                                <td>
                                    <button class="sg-btn sg-btn-danger" onclick="sgBlockIP('<?php echo esc_js($ip['address']); ?>')">Block IP</button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recent Anomalies -->
            <div class="sg-section">
                <h2 class="sg-section-title">Recent Anomalies</h2>
                <div class="sg-anomaly-feed">
                    <?php foreach ($analytics['recent_anomalies'] as $anomaly): ?>
                    <div class="sg-anomaly-item <?php echo esc_attr(strtolower($anomaly['severity'])); ?>">
                        <div class="sg-anomaly-header">
                            <span class="sg-anomaly-icon">
                                <?php echo esc_html($anomaly['icon']); ?>
                            </span>
                            <span class="sg-anomaly-type"><?php echo esc_html($anomaly['type']); ?></span>
                            <span class="sg-anomaly-severity"><?php echo esc_html($anomaly['severity']); ?></span>
                            <span class="sg-anomaly-time"><?php echo esc_html($anomaly['time_ago']); ?></span>
                        </div>
                        <div class="sg-anomaly-desc">
                            <?php echo esc_html($anomaly['description']); ?>
                        </div>
                        <div class="sg-anomaly-meta">
                            <span class="sg-anomaly-user">User: <?php echo esc_html($anomaly['username']); ?></span>
                            <span class="sg-anomaly-ip">IP: <?php echo esc_html($anomaly['ip']); ?></span>
                        </div>
                    </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <script>
            // Initialize Chart.js
            document.addEventListener('DOMContentLoaded', function() {
                const ctx = document.getElementById('sgActivityChart');
                if (ctx) {
                    new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: <?php echo json_encode($analytics['activity_chart']['labels']); ?>,
                            datasets: [
                                {
                                    label: 'Security Events',
                                    data: <?php echo json_encode($analytics['activity_chart']['events']); ?>,
                                    borderColor: '#667eea',
                                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                                    tension: 0.4,
                                    fill: true
                                },
                                {
                                    label: 'Anomalies Detected',
                                    data: <?php echo json_encode($analytics['activity_chart']['anomalies']); ?>,
                                    borderColor: '#ef4444',
                                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                    tension: 0.4,
                                    fill: true
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    labels: {
                                        color: '#a8a8b3'
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: {
                                        color: '#a8a8b3'
                                    },
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    }
                                },
                                x: {
                                    ticks: {
                                        color: '#a8a8b3'
                                    },
                                    grid: {
                                        color: 'rgba(255, 255, 255, 0.1)'
                                    }
                                }
                            }
                        }
                    });
                }
            });

            // Block IP function
            function sgBlockIP(ip) {
                if (confirm('Are you sure you want to block IP ' + ip + '?')) {
                    // AJAX call to block IP
                    jQuery.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'spectrus_block_ip',
                            nonce: '<?php echo wp_create_nonce('sg_block_ip'); ?>',
                            ip: ip
                        },
                        success: function(response) {
                            if (response.success) {
                                alert('IP blocked successfully');
                                location.reload();
                            } else {
                                alert('Error blocking IP: ' + response.data.message);
                            }
                        },
                        error: function() {
                            alert('Error blocking IP');
                        }
                    });
                }
            }
        </script>

        <?php
    }

    /**
     * Get analytics data for dashboard
     *
     * @return array Analytics data.
     */
    private function get_analytics_data()
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Risk distribution
        $risk_distribution = $this->get_risk_distribution();

        // Activity chart data (last 24h)
        $activity_chart = $this->get_activity_chart_data($table_name);

        // Top risky users
        $top_risky_users = $this->get_top_risky_users($table_name);

        // Top risky IPs
        $top_risky_ips = $this->get_top_risky_ips($table_name);

        // Recent anomalies
        $recent_anomalies = $this->get_recent_anomalies($table_name);

        return array(
            'risk_distribution' => $risk_distribution,
            'activity_chart' => $activity_chart,
            'top_risky_users' => $top_risky_users,
            'top_risky_ips' => $top_risky_ips,
            'recent_anomalies' => $recent_anomalies,
        );
    }

    /**
     * Get risk distribution
     *
     * @return array Risk distribution percentages.
     */
    private function get_risk_distribution()
    {
        // For now, return hardcoded data
        // In production, calculate from actual user risk scores
        return array(
            'low' => 65,
            'medium' => 20,
            'high' => 12,
            'critical' => 3,
        );
    }

    /**
     * Get activity chart data
     *
     * @param string $table_name Table name.
     * @return array Chart data.
     */
    private function get_activity_chart_data($table_name)
    {
        // Get hourly data for last 24 hours
        $labels = array();
        $events = array();
        $anomalies = array();

        for ($i = 23; $i >= 0; $i--) {
            $hour = date('H:00', strtotime("-{$i} hours"));
            $labels[] = $hour;

            // Count events for this hour
            $count = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT COUNT(*) FROM {$table_name}
                     WHERE timestamp > DATE_SUB(NOW(), INTERVAL %d HOUR)
                     AND timestamp < DATE_SUB(NOW(), INTERVAL %d HOUR)",
                    $i,
                    $i - 1
                )
            );

            $events[] = (int) $count;

            // Simulate anomalies (in production, use actual anomaly data)
            $anomalies[] = (int) $count * 0.05;
        }

        return array(
            'labels' => $labels,
            'events' => $events,
            'anomalies' => $anomalies,
        );
    }

    /**
     * Get top risky users
     *
     * @param string $table_name Table name.
     * @return array Top risky users.
     */
    private function get_top_risky_users($table_name)
    {
        // Get users with most anomalies in last 24 hours
        $results = $wpdb->get_results(
            "SELECT user_id, user_login,
                    COUNT(*) as anomaly_count
             FROM {$table_name}
             WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY user_id
             ORDER BY anomaly_count DESC
             LIMIT 10",
            ARRAY_A
        );

        $users = array();
        foreach ($results as $result) {
            if (empty($result['user_id'])) {
                continue;
            }

            $user = get_userdata($result['user_id']);
            if (!$user) {
                continue;
            }

            // Calculate risk score (simplified)
            $risk_score = min($result['anomaly_count'] * 5, 100);
            $risk_level = $risk_score < 20 ? 'LOW' : ($risk_score < 50 ? 'MEDIUM' : ($risk_score < 80 ? 'HIGH' : 'CRITICAL'));
            $risk_color = $risk_level === 'LOW' ? '#22c55e' : ($risk_level === 'MEDIUM' ? '#eab308' : ($risk_level === 'HIGH' ? '#f97316' : '#ef4444'));

            $users[] = array(
                'user_id' => $result['user_id'],
                'username' => $user->user_login,
                'email' => $user->user_email,
                'risk_score' => $risk_score,
                'risk_level' => $risk_level,
                'risk_color' => $risk_color,
                'last_activity' => $this->get_user_last_activity($result['user_id'], $table_name),
                'anomaly_count' => $result['anomaly_count'],
            );
        }

        // Fill with placeholder data if no real data
        if (empty($users)) {
            $users = array(
                array(
                    'user_id' => 0,
                    'username' => 'admin',
                    'email' => 'admin@example.com',
                    'risk_score' => 15,
                    'risk_level' => 'LOW',
                    'risk_color' => '#22c55e',
                    'last_activity' => '2 minutes ago',
                    'anomaly_count' => 0,
                ),
            );
        }

        return $users;
    }

    /**
     * Get top risky IPs
     *
     * @param string $table_name Table name.
     * @return array Top risky IPs.
     */
    private function get_top_risky_ips($table_name)
    {
        // Get IPs with most failed logins
        $results = $wpdb->get_results(
            "SELECT ip,
                    COUNT(*) as anomaly_count,
                    SUM(CASE WHEN event_type = 'login_failed' THEN 1 ELSE 0 END) as failed_logins
             FROM {$table_name}
             WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             GROUP BY ip
             ORDER BY failed_logins DESC
             LIMIT 10",
            ARRAY_A
        );

        $ips = array();
        foreach ($results as $result) {
            $ips[] = array(
                'address' => $result['ip'],
                'failed_logins' => $result['failed_logins'],
                'anomaly_count' => $result['anomaly_count'],
                'last_seen' => $this->get_ip_last_seen($result['ip'], $table_name),
            );
        }

        return $ips;
    }

    /**
     * Get recent anomalies
     *
     * @param string $table_name Table name.
     * @return array Recent anomalies.
     */
    private function get_recent_anomalies($table_name)
    {
        // Get recent metrics that might indicate anomalies
        $results = $wpdb->get_results(
            "SELECT m.*
             FROM {$table_name} m
             WHERE m.timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
             ORDER BY m.timestamp DESC
             LIMIT 20",
            ARRAY_A
        );

        $anomalies = array();
        foreach ($results as $result) {
            // Generate anomaly from metrics (simplified)
            $type = $this->guess_anomaly_type($result);
            $severity = $this->guess_anomaly_severity($result);
            $icon = $severity === 'CRITICAL' ? '🚨' : ($severity === 'HIGH' ? '🔶' : ($severity === 'MEDIUM' ? '⚠️' : '✅'));

            $user_id = $result['user_id'];
            $user = $user_id ? get_userdata($user_id) : null;
            $username = $user ? $user->user_login : 'Unknown';

            $anomalies[] = array(
                'type' => $type,
                'severity' => $severity,
                'icon' => $icon,
                'description' => "Unusual {$type} detected from {$result['ip']}",
                'username' => $username,
                'ip' => $result['ip'],
                'time_ago' => human_time_diff(strtotime($result['timestamp']), current_time('timestamp')) . ' ago',
            );
        }

        return $anomalies;
    }

    /**
     * Guess anomaly type from metrics
     *
     * @param array $result Metric result.
     * @return string Anomaly type.
     */
    private function guess_anomaly_type($result)
    {
        $event_type = $result['event_type'];

        switch ($event_type) {
            case 'login_failed':
                return 'Failed Login';
            case 'login':
                if ($result['is_tor']) {
                    return 'Tor Login';
                }
                return 'Unusual Login';
            default:
                return 'Suspicious Activity';
        }
    }

    /**
     * Guess anomaly severity
     *
     * @param array $result Metric result.
     * @return string Severity level.
     */
    private function guess_anomaly_severity($result)
    {
        if ($result['is_tor'] || $result['event_type'] === 'login_failed') {
            return 'HIGH';
        }

        return 'MEDIUM';
    }

    /**
     * Get user last activity
     *
     * @param int    $user_id   User ID.
     * @param string $table_name Table name.
     * @return string Time ago.
     */
    private function get_user_last_activity($user_id, $table_name)
    {
        $last_activity = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT timestamp FROM {$table_name}
                 WHERE user_id = %d
                 ORDER BY timestamp DESC
                 LIMIT 1",
                $user_id
            )
        );

        if (!$last_activity) {
            return 'Never';
        }

        return human_time_diff(strtotime($last_activity), current_time('timestamp')) . ' ago';
    }

    /**
     * Get IP last seen
     *
     * @param string $ip        IP address.
     * @param string $table_name Table name.
     * @return string Time ago.
     */
    private function get_ip_last_seen($ip, $table_name)
    {
        $last_seen = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT timestamp FROM {$table_name}
                 WHERE ip = %s
                 ORDER BY timestamp DESC
                 LIMIT 1",
                $ip
            )
        );

        if (!$last_seen) {
            return 'Never';
        }

        return human_time_diff(strtotime($last_seen), current_time('timestamp')) . ' ago';
    }
}
