<?php
/**
 * SpectrusGuard Risk Scorer
 *
 * Calculates risk scores based on anomalies and metrics.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Risk_Scorer
 *
 * Risk scoring engine with configurable weights.
 */
class SG_Risk_Scorer
{

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Risk category weights
     *
     * @var array
     */
    private $weights = array(
        'login_frequency' => 20,
        'time_anomaly' => 15,
        'geo_anomaly' => 25,
        'device_anomaly' => 10,
        'request_rate_anomaly' => 15,
        'ip_reputation' => 15,
    );

    /**
     * Severity multipliers
     *
     * @var array
     */
    private $severity_multipliers = array(
        'LOW' => 0.3,
        'MEDIUM' => 0.6,
        'HIGH' => 0.9,
        'CRITICAL' => 1.0,
    );

    /**
     * Constructor
     *
     * @param SG_Logger $logger Logger instance.
     */
    public function __construct(SG_Logger $logger)
    {
        $this->logger = $logger;
    }

    /**
     * Calculate comprehensive risk score
     *
     * @param int   $user_id   User ID.
     * @param array $metrics   Current metrics.
     * @param array $baseline  Behavioral baseline.
     * @param array $anomalies Detected anomalies.
     * @return int Risk score (0-100).
     */
    public function calculate_risk_score($user_id, $metrics, $baseline, $anomalies)
    {
        $risk_score = 0;
        $risk_factors = array();

        // 1. Analyze anomalies
        foreach ($anomalies as $anomaly) {
            $anomaly_risk = $this->calculate_anomaly_risk($anomaly);
            $risk_score += $anomaly_risk['points'];
            $risk_factors[] = $anomaly_risk;
        }

        // 2. IP reputation check
        $ip_risk = $this->calculate_ip_risk($metrics);
        if ($ip_risk > 0) {
            $risk_score += $ip_risk;
            $risk_factors[] = array(
                'type' => 'ip_reputation',
                'description' => 'Suspicious IP reputation',
                'points' => $ip_risk,
            );
        }

        // 3. Login failure rate check
        if (isset($metrics['event_type']) && $metrics['event_type'] === 'login') {
            $failure_risk = $this->calculate_failure_risk($user_id, $metrics);
            if ($failure_risk > 0) {
                $risk_score += $failure_risk;
                $risk_factors[] = array(
                    'type' => 'login_failure_rate',
                    'description' => 'High login failure rate',
                    'points' => $failure_risk,
                );
            }
        }

        // Cap at 100
        $risk_score = min($risk_score, 100);

        // Log risk calculation
        $this->logger->log_debug(
            sprintf(
                'UEBA: Risk score calculated for user %d: %d/100',
                $user_id,
                $risk_score
            ),
            'info'
        );

        return $risk_score;
    }

    /**
     * Calculate risk contribution from a single anomaly
     *
     * @param array $anomaly Anomaly details.
     * @return array Risk details with points.
     */
    private function calculate_anomaly_risk($anomaly)
    {
        $type = $anomaly['type'] ?? 'unknown';
        $severity = $anomaly['severity'] ?? 'MEDIUM';

        // Get base weight for this anomaly type
        $base_weight = isset($this->weights[$type]) ? $this->weights[$type] : 10;

        // Apply severity multiplier
        $multiplier = $this->severity_multipliers[$severity] ?? 0.6;

        // Calculate points
        $points = $base_weight * $multiplier;

        return array(
            'type' => $type,
            'severity' => $severity,
            'description' => $anomaly['description'] ?? '',
            'points' => $points,
            'weight' => $base_weight,
            'multiplier' => $multiplier,
        );
    }

    /**
     * Calculate IP reputation risk
     *
     * @param array $metrics Current metrics.
     * @return int Risk points (0-15).
     */
    private function calculate_ip_risk($metrics)
    {
        $risk = 0;

        // Tor exit node
        if (isset($metrics['is_tor']) && $metrics['is_tor']) {
            $risk += 15;
        }

        // VPN or datacenter
        if (isset($metrics['is_vpn']) && $metrics['is_vpn']) {
            $risk += 8;
        }

        return $risk;
    }

    /**
     * Calculate login failure risk
     *
     * @param int   $user_id User ID.
     * @param array $metrics Current metrics.
     * @return int Risk points (0-20).
     */
    private function calculate_failure_risk($user_id, $metrics)
    {
        $ip = isset($metrics['ip']) ? $metrics['ip'] : '0.0.0.0';

        global $wpdb;
        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Get failed logins in last hour for this IP/user combo
        $failed_count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE (user_id = %d OR ip = %s)
                 AND event_type = 'login_failed'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
                $user_id,
                $ip
            )
        );

        $failed_count = (int) $failed_count;

        if ($failed_count == 0) {
            return 0;
        }

        if ($failed_count <= 3) {
            return 5; // Low risk
        }

        if ($failed_count <= 10) {
            return 10; // Medium risk
        }

        return 20; // High risk
    }

    /**
     * Get risk level from score
     *
     * @param int $score Risk score (0-100).
     * @return string Risk level.
     */
    public function get_risk_level($score)
    {
        if ($score < 20) {
            return 'LOW';
        }

        if ($score < 50) {
            return 'MEDIUM';
        }

        if ($score < 80) {
            return 'HIGH';
        }

        return 'CRITICAL';
    }

    /**
     * Get risk level details
     *
     * @param string $level Risk level.
     * @return array Level details.
     */
    public function get_risk_level_details($level)
    {
        $details = array(
            'LOW' => array(
                'color' => '#22c55e', // Green
                'icon' => '✅',
                'action' => 'monitor',
                'description' => 'No immediate action required. Monitor for changes.',
            ),
            'MEDIUM' => array(
                'color' => '#eab308', // Yellow
                'icon' => '⚠️',
                'action' => 'warn',
                'description' => 'Unusual activity detected. Consider additional verification.',
            ),
            'HIGH' => array(
                'color' => '#f97316', // Orange
                'icon' => '🔶',
                'action' => 'challenge',
                'description' => 'Suspicious activity. Additional authentication required.',
            ),
            'CRITICAL' => array(
                'color' => '#ef4444', // Red
                'icon' => '🚨',
                'action' => 'block',
                'description' => 'Critical security event. Immediate action required.',
            ),
        );

        return $details[$level] ?? $details['LOW'];
    }

    /**
     * Get recommended action for risk level
     *
     * @param string $level Risk level.
     * @return string Recommended action.
     */
    public function get_recommended_action($level)
    {
        $details = $this->get_risk_level_details($level);
        return $details['action'];
    }

    /**
     * Update risk weights (configurable)
     *
     * @param array $new_weights New weights.
     */
    public function update_weights($new_weights)
    {
        $this->weights = wp_parse_args($new_weights, $this->weights);
    }

    /**
     * Get current weights
     *
     * @return array Current weights.
     */
    public function get_weights()
    {
        return $this->weights;
    }

    /**
     * Calculate trend (improving vs worsening)
     *
     * @param int   $user_id     User ID.
     * @param array $current_score Current risk score.
     * @param int   $hours       Hours to look back.
     * @return string Trend (improving, stable, worsening).
     */
    public function calculate_trend($user_id, $current_score, $hours = 24)
    {
        global $wpdb;
        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Get recent risk scores (we'll calculate from anomalies)
        $recent_anomalies = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT timestamp FROM {$table_name}
                 WHERE user_id = %d
                 AND timestamp > DATE_SUB(NOW(), INTERVAL %d HOUR)
                 ORDER BY timestamp DESC
                 LIMIT 50",
                $user_id,
                $hours
            )
        );

        if (count($recent_anomalies) < 3) {
            return 'stable';
        }

        // Calculate trend based on anomaly count
        // More anomalies recently = worsening trend
        $recent_count = count($recent_anomalies);

        if ($recent_count > 20) {
            return 'worsening';
        }

        if ($recent_count < 5) {
            return 'improving';
        }

        return 'stable';
    }
}
