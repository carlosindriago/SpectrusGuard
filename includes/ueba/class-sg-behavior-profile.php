<?php
/**
 * SpectrusGuard Behavior Profile
 *
 * Maintains behavioral baselines for users and IPs.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Behavior_Profile
 *
 * Manages behavior baselines for anomaly detection.
 */
class SG_Behavior_Profile
{

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Minimum days required for baseline
     *
     * @var int
     */
    private $min_baseline_days = 7;

    /**
     * Constructor
     *
     * @param SG_Logger $logger Logger instance.
     */
    public function __construct(SG_Logger $logger)
    {
        $this->logger = $logger;
        $this->create_tables();
    }

    /**
     * Create database tables for metrics
     */
    private function create_tables()
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();
        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            user_id bigint(20) unsigned DEFAULT NULL,
            user_login varchar(100) DEFAULT NULL,
            user_role varchar(50) DEFAULT NULL,
            ip varchar(45) NOT NULL,
            user_agent text,
            device_fingerprint varchar(32) DEFAULT NULL,
            country varchar(2) DEFAULT NULL,
            is_tor tinyint(1) DEFAULT 0,
            is_vpn tinyint(1) DEFAULT 0,
            success tinyint(1) DEFAULT 1,
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            hour tinyint(2) DEFAULT NULL,
            day_of_week tinyint(1) DEFAULT NULL,
            action varchar(100) DEFAULT NULL,
            request_uri text,
            request_method varchar(10) DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY user_id (user_id),
            KEY ip (ip),
            KEY timestamp (timestamp),
            KEY event_user (event_type, user_id, timestamp)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    /**
     * Get baseline for user
     *
     * @param int $user_id User ID.
     * @return array Baseline data.
     */
    public function get_baseline($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Check if we have enough data
        $days_of_data = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(DISTINCT DATE(timestamp))
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'",
                $user_id
            )
        );

        if ($days_of_data < $this->min_baseline_days) {
            // Not enough data for reliable baseline
            return array(
                'status' => 'insufficient_data',
                'days_of_data' => (int) $days_of_data,
                'min_required' => $this->min_baseline_days,
            );
        }

        // Calculate statistical baselines
        $baseline = array(
            'status' => 'ready',
            'days_of_data' => (int) $days_of_data,
            'login_frequency' => $this->calculate_login_frequency_baseline($user_id),
            'login_hours' => $this->calculate_login_hours_baseline($user_id),
            'login_countries' => $this->calculate_login_countries($user_id),
            'login_cities' => $this->calculate_login_cities($user_id),
            'request_rate' => $this->calculate_request_rate_baseline($user_id),
            'error_rate' => $this->calculate_error_rate_baseline($user_id),
            'device_fingerprints' => $this->calculate_device_fingerprints($user_id),
            'last_login' => $this->get_last_login($user_id),
        );

        return $baseline;
    }

    /**
     * Get IP baseline
     *
     * @param string $ip IP address.
     * @return array IP baseline.
     */
    public function get_ip_baseline($ip)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Failed logins in last hour
        $failed_logins = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE event_type = 'login_failed'
                 AND ip = %s
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
                $ip
            )
        );

        // Successful logins in last 24 hours
        $successful_logins = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE event_type = 'login'
                 AND ip = %s
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
                $ip
            )
        );

        // Unique users from this IP
        $unique_users = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(DISTINCT user_id) FROM {$table_name}
                 WHERE event_type = 'login'
                 AND ip = %s
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
                $ip
            )
        );

        return array(
            'failed_logins_last_hour' => (int) $failed_logins,
            'successful_logins_last_24h' => (int) $successful_logins,
            'unique_users_last_24h' => (int) $unique_users,
        );
    }

    /**
     * Update baseline with new metrics
     *
     * @param int   $user_id  User ID.
     * @param array $metrics  Metrics data.
     */
    public function update_baseline($user_id, $metrics)
    {
        // Store metrics in database
        $this->store_metrics($metrics);
    }

    /**
     * Update IP baseline
     *
     * @param string $ip      IP address.
     * @param array  $metrics Metrics data.
     */
    public function update_ip_baseline($ip, $metrics)
    {
        $this->store_metrics($metrics);
    }

    /**
     * Update request baseline
     *
     * @param int   $user_id  User ID.
     * @param array $metrics  Request metrics.
     */
    public function update_request_baseline($user_id, $metrics)
    {
        $this->store_metrics($metrics);
    }

    /**
     * Update action baseline
     *
     * @param int   $user_id  User ID.
     * @param array $metrics  Action metrics.
     */
    public function update_action_baseline($user_id, $metrics)
    {
        $this->store_metrics($metrics);
    }

    /**
     * Store metrics in database
     *
     * @param array $metrics Metrics data.
     */
    private function store_metrics($metrics)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $data = array(
            'event_type' => $metrics['event_type'] ?? 'unknown',
            'user_id' => $metrics['user_id'] ?? null,
            'user_login' => $metrics['user_login'] ?? null,
            'user_role' => $metrics['user_role'] ?? null,
            'ip' => $metrics['ip'] ?? '0.0.0.0',
            'user_agent' => $metrics['user_agent'] ?? '',
            'device_fingerprint' => $metrics['device_fingerprint'] ?? null,
            'country' => $metrics['country'] ?? null,
            'is_tor' => isset($metrics['is_tor']) ? (int) $metrics['is_tor'] : 0,
            'is_vpn' => isset($metrics['is_vpn']) ? (int) $metrics['is_vpn'] : 0,
            'success' => isset($metrics['success']) ? (int) $metrics['success'] : 1,
            'timestamp' => isset($metrics['timestamp'])
                ? date('Y-m-d H:i:s', $metrics['timestamp'])
                : current_time('mysql'),
            'hour' => $metrics['hour'] ?? null,
            'day_of_week' => $metrics['day_of_week'] ?? null,
            'action' => $metrics['action'] ?? null,
            'request_uri' => $metrics['request_uri'] ?? null,
            'request_method' => $metrics['request_method'] ?? null,
        );

        $wpdb->insert($table_name, $data);
    }

    /**
     * Calculate login frequency baseline
     *
     * @param int $user_id User ID.
     * @return array Login frequency stats.
     */
    private function calculate_login_frequency_baseline($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Calculate mean and standard deviation
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT COUNT(*) as login_count, DATE(timestamp) as login_date
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
                 GROUP BY DATE(timestamp)",
                $user_id
            )
        );

        if (empty($results)) {
            return array('mean' => 0, 'std_dev' => 0, 'median' => 0);
        }

        $login_counts = array_map(function ($row) {
            return (int) $row->login_count;
        }, $results);

        sort($login_counts);
        $mean = array_sum($login_counts) / count($login_counts);
        $std_dev = $this->calculate_std_dev($login_counts, $mean);
        $median = $this->calculate_median($login_counts);

        return array(
            'mean' => round($mean, 2),
            'std_dev' => round($std_dev, 2),
            'median' => $median,
        );
    }

    /**
     * Calculate login hours baseline
     *
     * @param int $user_id User ID.
     * @return array Login hours distribution.
     */
    private function calculate_login_hours_baseline($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Get typical login hours (top 80% of logins)
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT hour, COUNT(*) as count
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
                 GROUP BY hour
                 ORDER BY count DESC",
                $user_id
            )
        );

        if (empty($results)) {
            return array();
        }

        // Get top 80% of login hours
        $total = array_sum(array_map(function ($row) {
            return (int) $row->count;
        }, $results));

        $cumulative = 0;
        $typical_hours = array();

        foreach ($results as $row) {
            $cumulative += (int) $row->count;
            $typical_hours[] = (int) $row->hour;

            if ($cumulative >= ($total * 0.8)) {
                break;
            }
        }

        return $typical_hours;
    }

    /**
     * Calculate login countries
     *
     * @param int $user_id User ID.
     * @return array List of countries.
     */
    private function calculate_login_countries($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $countries = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT DISTINCT country
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 AND country IS NOT NULL
                 AND country != ''
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 90 DAY)",
                $user_id
            )
        );

        return array_filter($countries);
    }

    /**
     * Calculate login cities
     *
     * @param int $user_id User ID.
     * @return array List of cities.
     */
    private function calculate_login_cities($user_id)
    {
        // For now, return empty array - cities require geo-city database
        return array();
    }

    /**
     * Calculate request rate baseline
     *
     * @param int $user_id User ID.
     * @return array Request rate stats.
     */
    private function calculate_request_rate_baseline($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Calculate requests per hour for the last 30 days
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT DATE(timestamp) as request_date, COUNT(*) as request_count
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'request'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)
                 GROUP BY DATE(timestamp)",
                $user_id
            )
        );

        if (empty($results)) {
            return array('mean' => 0, 'std_dev' => 0, 'median' => 0);
        }

        // Calculate per hour average
        $hourly_rates = array_map(function ($row) {
            return (int) $row->request_count / 24; // Average per hour
        }, $results);

        $mean = array_sum($hourly_rates) / count($hourly_rates);
        $std_dev = $this->calculate_std_dev($hourly_rates, $mean);
        $median = $this->calculate_median($hourly_rates);

        return array(
            'mean' => round($mean, 2),
            'std_dev' => round($std_dev, 2),
            'median' => round($median, 2),
        );
    }

    /**
     * Calculate error rate baseline
     *
     * @param int $user_id User ID.
     * @return array Error rate stats.
     */
    private function calculate_error_rate_baseline($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        // Calculate error rate (failed / total)
        $total_logins = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE user_id = %d
                 AND (event_type = 'login' OR event_type = 'login_failed')
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)",
                $user_id
            )
        );

        if ($total_logins == 0) {
            return array('mean' => 0, 'std_dev' => 0);
        }

        $failed_logins = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login_failed'
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 30 DAY)",
                $user_id
            )
        );

        $error_rate = (int) $failed_logins / (int) $total_logins;

        return array(
            'mean' => round($error_rate, 4),
            'std_dev' => 0.05, // Default std dev for error rate
        );
    }

    /**
     * Calculate device fingerprints
     *
     * @param int $user_id User ID.
     * @return array Device fingerprints.
     */
    private function calculate_device_fingerprints($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $fingerprints = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT DISTINCT device_fingerprint
                 FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 AND device_fingerprint IS NOT NULL
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 90 DAY)",
                $user_id
            )
        );

        return array_filter($fingerprints);
    }

    /**
     * Get last login
     *
     * @param int $user_id User ID.
     * @return string Last login datetime.
     */
    private function get_last_login($user_id)
    {
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';

        $last_login = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT timestamp FROM {$table_name}
                 WHERE user_id = %d
                 AND event_type = 'login'
                 ORDER BY timestamp DESC
                 LIMIT 1",
                $user_id
            )
        );

        return $last_login ?: null;
    }

    /**
     * Calculate standard deviation
     *
     * @param array $data Data points.
     * @param float $mean Mean value.
     * @return float Standard deviation.
     */
    private function calculate_std_dev($data, $mean)
    {
        if (count($data) < 2) {
            return 0;
        }

        $sum_squares = array_sum(array_map(function ($val) use ($mean) {
            return pow($val - $mean, 2);
        }, $data));

        return sqrt($sum_squares / count($data));
    }

    /**
     * Calculate median
     *
     * @param array $data Data points.
     * @return float Median.
     */
    private function calculate_median($data)
    {
        $count = count($data);
        $middle = floor($count / 2);

        if ($count % 2) {
            return $data[$middle];
        }

        return ($data[$middle - 1] + $data[$middle]) / 2;
    }
}
