<?php
/**
 * SpectrusGuard Anomaly Detector
 *
 * Detects anomalies in user behavior using statistical methods.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Anomaly_Detector
 *
 * Statistical anomaly detection using multiple algorithms.
 */
class SG_Anomaly_Detector
{

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Z-Score threshold for anomaly detection
     *
     * @var float
     */
    private $z_score_threshold = 3.0;

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
     * Detect anomalies in current metrics compared to baseline
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array Detected anomalies.
     */
    public function detect_anomalies($metrics, $baseline)
    {
        $anomalies = array();

        // Skip if no baseline yet
        if (!isset($baseline['status']) || $baseline['status'] !== 'ready') {
            return $anomalies;
        }

        // 1. Login frequency anomaly
        $login_anomaly = $this->detect_login_frequency_anomaly($metrics, $baseline);
        if ($login_anomaly) {
            $anomalies[] = $login_anomaly;
        }

        // 2. Time-based anomaly (login at unusual hour)
        $time_anomaly = $this->detect_time_anomaly($metrics, $baseline);
        if ($time_anomaly) {
            $anomalies[] = $time_anomaly;
        }

        // 3. Geographic anomaly
        $geo_anomaly = $this->detect_geo_anomaly($metrics, $baseline);
        if ($geo_anomaly) {
            $anomalies[] = $geo_anomaly;
        }

        // 4. Device fingerprint anomaly
        $device_anomaly = $this->detect_device_anomaly($metrics, $baseline);
        if ($device_anomaly) {
            $anomalies[] = $device_anomaly;
        }

        // 5. Request rate anomaly (for request events)
        if (isset($metrics['event_type']) && $metrics['event_type'] === 'request') {
            $request_anomaly = $this->detect_request_rate_anomaly($metrics, $baseline);
            if ($request_anomaly) {
                $anomalies[] = $request_anomaly;
            }
        }

        // 6. IP reputation anomaly
        $ip_anomaly = $this->detect_ip_reputation_anomaly($metrics);
        if ($ip_anomaly) {
            $anomalies[] = $ip_anomaly;
        }

        return $anomalies;
    }

    /**
     * Detect login frequency anomaly using Z-Score
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array|null Anomaly details or null.
     */
    private function detect_login_frequency_anomaly($metrics, $baseline)
    {
        if (!isset($baseline['login_frequency']['mean']) || !isset($baseline['login_frequency']['std_dev'])) {
            return null;
        }

        $mean = $baseline['login_frequency']['mean'];
        $std_dev = $baseline['login_frequency']['std_dev'];

        if ($std_dev == 0) {
            return null;
        }

        // Count logins today for this user
        $today_logins = $this->get_today_logins($metrics['user_id']);

        if ($today_logins == 0) {
            return null;
        }

        // Calculate Z-Score
        $z_score = ($today_logins - $mean) / $std_dev;

        if (abs($z_score) > $this->z_score_threshold) {
            $severity = abs($z_score) > 4 ? 'CRITICAL' : 'HIGH';

            return array(
                'type' => 'login_frequency',
                'severity' => $severity,
                'description' => sprintf(
                    'Unusual login frequency: %d logins today (expected: %.2f ± %.2f)',
                    $today_logins,
                    $mean,
                    $std_dev
                ),
                'z_score' => $z_score,
                'expected_range' => array(
                    'min' => max(0, $mean - ($std_dev * $this->z_score_threshold)),
                    'max' => $mean + ($std_dev * $this->z_score_threshold),
                ),
                'actual' => $today_logins,
            );
        }

        return null;
    }

    /**
     * Detect time-based anomaly
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array|null Anomaly details or null.
     */
    private function detect_time_anomaly($metrics, $baseline)
    {
        if (!isset($baseline['login_hours']) || empty($baseline['login_hours'])) {
            return null;
        }

        $current_hour = isset($metrics['hour']) ? (int) $metrics['hour'] : (int) date('H');

        // Check if current hour is in typical login hours
        if (!in_array($current_hour, $baseline['login_hours'], true)) {
            return array(
                'type' => 'time_anomaly',
                'severity' => 'MEDIUM',
                'description' => sprintf(
                    'Login at unusual time: %02d:00 (typical hours: %s)',
                    $current_hour,
                    implode(', ', array_map(function ($h) {
                        return sprintf('%02d:00', $h);
                    }, $baseline['login_hours']))
                ),
                'current_hour' => $current_hour,
                'typical_hours' => $baseline['login_hours'],
            );
        }

        return null;
    }

    /**
     * Detect geographic anomaly
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array|null Anomaly details or null.
     */
    private function detect_geo_anomaly($metrics, $baseline)
    {
        if (!isset($metrics['country']) || empty($metrics['country'])) {
            return null;
        }

        $baseline_countries = isset($baseline['login_countries']) ? $baseline['login_countries'] : array();

        if (empty($baseline_countries)) {
            return null;
        }

        $current_country = strtoupper($metrics['country']);

        if (!in_array($current_country, $baseline_countries, true)) {
            return array(
                'type' => 'geo_anomaly',
                'severity' => 'HIGH',
                'description' => sprintf(
                    'Login from unusual country: %s (typical countries: %s)',
                    $current_country,
                    implode(', ', $baseline_countries)
                ),
                'current_country' => $current_country,
                'typical_countries' => $baseline_countries,
            );
        }

        return null;
    }

    /**
     * Detect device fingerprint anomaly
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array|null Anomaly details or null.
     */
    private function detect_device_anomaly($metrics, $baseline)
    {
        if (!isset($metrics['device_fingerprint']) || empty($metrics['device_fingerprint'])) {
            return null;
        }

        $baseline_fingerprints = isset($baseline['device_fingerprints']) ? $baseline['device_fingerprints'] : array();

        if (empty($baseline_fingerprints)) {
            return null;
        }

        $current_fingerprint = $metrics['device_fingerprint'];

        if (!in_array($current_fingerprint, $baseline_fingerprints, true)) {
            return array(
                'type' => 'device_anomaly',
                'severity' => 'MEDIUM',
                'description' => 'Login from new/unknown device or browser',
                'current_fingerprint' => $current_fingerprint,
                'number_of_known_devices' => count($baseline_fingerprints),
            );
        }

        return null;
    }

    /**
     * Detect request rate anomaly
     *
     * @param array $metrics  Current metrics.
     * @param array $baseline Behavioral baseline.
     * @return array|null Anomaly details or null.
     */
    private function detect_request_rate_anomaly($metrics, $baseline)
    {
        if (!isset($baseline['request_rate']['mean']) || !isset($baseline['request_rate']['std_dev'])) {
            return null;
        }

        $mean = $baseline['request_rate']['mean'];
        $std_dev = $baseline['request_rate']['std_dev'];

        if ($std_dev == 0) {
            return null;
        }

        // Get recent request rate
        $recent_rate = $this->get_recent_request_rate($metrics['user_id'], 5); // Last 5 minutes

        if ($recent_rate == 0) {
            return null;
        }

        // Calculate Z-Score
        $z_score = ($recent_rate - $mean) / $std_dev;

        // Threshold is higher for request rate (more forgiving)
        $threshold = 4.0;

        if (abs($z_score) > $threshold) {
            $severity = abs($z_score) > 5 ? 'HIGH' : 'MEDIUM';

            return array(
                'type' => 'request_rate_anomaly',
                'severity' => $severity,
                'description' => sprintf(
                    'Unusual request rate: %.2f req/min (expected: %.2f ± %.2f)',
                    $recent_rate,
                    $mean,
                    $std_dev
                ),
                'z_score' => $z_score,
                'expected_range' => array(
                    'min' => max(0, $mean - ($std_dev * $threshold)),
                    'max' => $mean + ($std_dev * $threshold),
                ),
                'actual' => $recent_rate,
            );
        }

        return null;
    }

    /**
     * Detect IP reputation anomaly
     *
     * @param array $metrics Current metrics.
     * @return array|null Anomaly details or null.
     */
    private function detect_ip_reputation_anomaly($metrics)
    {
        $anomalies = array();

        // Check Tor exit node
        if (isset($metrics['is_tor']) && $metrics['is_tor']) {
            $anomalies[] = array(
                'type' => 'tor_exit_node',
                'severity' => 'HIGH',
                'description' => 'Login from Tor exit node',
            );
        }

        // Check VPN
        if (isset($metrics['is_vpn']) && $metrics['is_vpn']) {
            $anomalies[] = array(
                'type' => 'vpn_detected',
                'severity' => 'MEDIUM',
                'description' => 'Login from VPN or datacenter IP',
            );
        }

        return $anomalies;
    }

    /**
     * Get number of logins today for user
     *
     * @param int $user_id User ID.
     * @return int Number of logins today.
     */
    private function get_today_logins($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 AND DATE(timestamp) = CURDATE()",
                $user_id
            )
        );

        return (int) $count;
    }

    /**
     * Get recent request rate
     *
     * @param int $user_id User ID.
     * @param int $minutes Minutes to look back.
     * @return float Requests per minute.
     */
    private function get_recent_request_rate($user_id, $minutes)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'request'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
                $user_id,
                $minutes
            )
        );

        return (int) $count / $minutes;
    }

    /**
     * Detect outliers using IQR method
     *
     * @param array $data Data points.
     * @return array Outlier indices.
     */
    public function detect_outliers_iqr($data)
    {
        if (count($data) < 4) {
            return array();
        }

        sort($data);

        $q1 = $this->percentile($data, 25);
        $q3 = $this->percentile($data, 75);
        $iqr = $q3 - $q1;

        $lower_bound = $q1 - (1.5 * $iqr);
        $upper_bound = $q3 + (1.5 * $iqr);

        $outliers = array();
        foreach ($data as $index => $value) {
            if ($value < $lower_bound || $value > $upper_bound) {
                $outliers[] = $index;
            }
        }

        return $outliers;
    }

    /**
     * Calculate percentile
     *
     * @param array $data       Data points.
     * @param int   $percentile Percentile (0-100).
     * @return float Percentile value.
     */
    private function percentile($data, $percentile)
    {
        sort($data);
        $index = ceil(($percentile / 100) * count($data)) - 1;
        return $data[$index];
    }

    /**
     * Calculate Z-Score for a value
     *
     * @param float $value   Value to score.
     * @param float $mean     Mean of distribution.
     * @param float $std_dev Standard deviation.
     * @return float Z-Score.
     */
    public function calculate_z_score($value, $mean, $std_dev)
    {
        if ($std_dev == 0) {
            return 0;
        }

        return ($value - $mean) / $std_dev;
    }
}
