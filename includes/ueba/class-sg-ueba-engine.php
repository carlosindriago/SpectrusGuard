<?php
/**
 * SpectrusGuard UEBA Engine
 *
 * User and Entity Behavior Analytics - Core Engine
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_UEBA_Engine
 *
 * Main orchestrator for User and Entity Behavior Analytics.
 * Detects anomalies in user behavior using statistical analysis.
 */
class SG_UEBA_Engine
{

    /**
     * Logger instance
     *
     * @var SG_Logger|null
     */
    private $logger;

    /**
     * Metrics Collector instance
     *
     * @var SG_Metrics_Collector|null
     */
    private $metrics_collector;

    /**
     * Anomaly Detector instance
     *
     * @var SG_Anomaly_Detector|null
     */
    private $anomaly_detector;

    /**
     * Risk Scorer instance
     *
     * @var SG_Risk_Scorer|null
     */
    private $risk_scorer;

    /**
     * Response Engine instance
     *
     * @var SG_Response_Engine|null
     */
    private $response_engine;

    /**
     * Behavior Profile instance
     *
     * @var SG_Behavior_Profile|null
     */
    private $behavior_profile;

    /**
     * Constructor
     *
     * @param SG_Logger $logger Logger instance.
     */
    public function __construct(SG_Logger $logger)
    {
        $this->logger = $logger;

        // Initialize components
        $this->initialize_components();

        // Register hooks
        $this->register_hooks();
    }

    /**
     * Initialize UEBA components
     */
    private function initialize_components()
    {
        require_once SG_PLUGIN_DIR . 'includes/ueba/class-sg-metrics-collector.php';
        require_once SG_PLUGIN_DIR . 'includes/ueba/class-sg-behavior-profile.php';
        require_once SG_PLUGIN_DIR . 'includes/ueba/class-sg-anomaly-detector.php';
        require_once SG_PLUGIN_DIR . 'includes/ueba/class-sg-risk-scorer.php';
        require_once SG_PLUGIN_DIR . 'includes/ueba/class-sg-response-engine.php';

        $this->metrics_collector = new SG_Metrics_Collector($this->logger);
        $this->behavior_profile = new SG_Behavior_Profile($this->logger);
        $this->anomaly_detector = new SG_Anomaly_Detector($this->logger);
        $this->risk_scorer = new SG_Risk_Scorer($this->logger);
        $this->response_engine = new SG_Response_Engine($this->logger);
    }

    /**
     * Register WordPress hooks for UEBA
     */
    private function register_hooks()
    {
        // Monitor user login
        add_action('wp_login', array($this, 'on_user_login'), 10, 2);

        // Monitor failed login
        add_action('wp_login_failed', array($this, 'on_failed_login'));

        // Monitor admin requests
        add_action('admin_init', array($this, 'on_admin_request'));

        // Monitor user actions
        add_action('admin_action_', array($this, 'on_user_action'));

        // Register REST API endpoints
        add_action('rest_api_init', array($this, 'register_rest_routes'));

        // Cleanup old metrics (daily)
        add_action('spectrus_ueba_daily_cleanup', array($this, 'cleanup_old_metrics'));
        if (!wp_next_scheduled('spectrus_ueba_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'spectrus_ueba_daily_cleanup');
        }
    }

    /**
     * Handle successful user login
     *
     * @param string  $user_login Username.
     * @param WP_User $user       User object.
     */
    public function on_user_login($user_login, $user)
    {
        $this->logger->log_debug('UEBA: User login detected - ' . $user_login, 'info');

        // Collect login metrics
        $metrics = $this->metrics_collector->collect_login_metrics($user);

        // Get baseline
        $baseline = $this->behavior_profile->get_baseline($user->ID);

        // Detect anomalies
        $anomalies = $this->anomaly_detector->detect_anomalies($metrics, $baseline);

        // Calculate risk score
        $risk_score = $this->risk_scorer->calculate_risk_score(
            $user->ID,
            $metrics,
            $baseline,
            $anomalies
        );

        // Get risk level
        $risk_level = $this->risk_scorer->get_risk_level($risk_score);

        // Execute response
        $context = array(
            'user_id' => $user->ID,
            'user_login' => $user_login,
            'metrics' => $metrics,
            'anomalies' => $anomalies,
            'risk_score' => $risk_score,
            'risk_level' => $risk_level,
            'ip' => $metrics['ip'],
            'timestamp' => time(),
        );

        $this->response_engine->execute_response($risk_score, $risk_level, $context);

        // Update baseline
        $this->behavior_profile->update_baseline($user->ID, $metrics);
    }

    /**
     * Handle failed login attempt
     *
     * @param string $username Username.
     */
    public function on_failed_login($username)
    {
        $this->logger->log_debug('UEBA: Failed login detected - ' . $username, 'warning');

        // Collect failed login metrics
        $ip = $this->metrics_collector->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $metrics = array(
            'event_type' => 'login_failed',
            'username' => $username,
            'ip' => $ip,
            'user_agent' => $user_agent,
            'timestamp' => time(),
        );

        // Check if this is a brute force attack
        $baseline = $this->behavior_profile->get_ip_baseline($ip);

        $anomalies = array();
        if (isset($baseline['failed_logins_last_hour']) && $baseline['failed_logins_last_hour'] > 10) {
            $anomalies[] = array(
                'type' => 'brute_force',
                'severity' => 'HIGH',
                'description' => 'More than 10 failed logins in last hour from this IP',
            );
        }

        // Execute response
        if (!empty($anomalies)) {
            $context = array(
                'username' => $username,
                'metrics' => $metrics,
                'anomalies' => $anomalies,
                'ip' => $ip,
                'timestamp' => time(),
            );

            $this->response_engine->execute_response(75, 'HIGH', $context);
        }

        // Update IP baseline
        $this->behavior_profile->update_ip_baseline($ip, $metrics);
    }

    /**
     * Handle admin request
     */
    public function on_admin_request()
    {
        if (!is_user_logged_in()) {
            return;
        }

        $user_id = get_current_user_id();
        $metrics = $this->metrics_collector->collect_request_metrics($user_id);

        // Only collect for admin users to reduce overhead
        if (user_can($user_id, 'manage_options')) {
            $this->behavior_profile->update_request_baseline($user_id, $metrics);
        }
    }

    /**
     * Handle user action
     */
    public function on_user_action()
    {
        if (!is_user_logged_in()) {
            return;
        }

        $user_id = get_current_user_id();
        $action = isset($_GET['action']) ? sanitize_text_field($_GET['action']) : '';

        $this->logger->log_debug('UEBA: User action detected - ' . $action, 'info');

        // Track suspicious actions
        $suspicious_actions = array('delete', 'trash', 'spam', 'unapprove', 'remove');

        if (in_array($action, $suspicious_actions, true)) {
            $metrics = array(
                'event_type' => 'admin_action',
                'action' => $action,
                'user_id' => $user_id,
                'ip' => $this->metrics_collector->get_client_ip(),
                'timestamp' => time(),
            );

            $this->behavior_profile->update_action_baseline($user_id, $metrics);
        }
    }

    /**
     * Register REST API routes
     */
    public function register_rest_routes()
    {
        // Get user risk score
        register_rest_route(
            'spectrus-guard/v1',
            '/ueba/risk-score/(?P<user_id>\d+)',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'rest_get_risk_score'),
                'permission_callback' => function ($request) {
                    return current_user_can('manage_options');
                },
                'args' => array(
                    'user_id' => array(
                        'validate_callback' => function ($param) {
                            return is_numeric($param);
                        },
                    ),
                ),
            )
        );

        // Get user baseline
        register_rest_route(
            'spectrus-guard/v1',
            '/ueba/baseline/(?P<user_id>\d+)',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'rest_get_baseline'),
                'permission_callback' => function ($request) {
                    return current_user_can('manage_options');
                },
                'args' => array(
                    'user_id' => array(
                        'validate_callback' => function ($param) {
                            return is_numeric($param);
                        },
                    ),
                ),
            )
        );

        // Get anomalies
        register_rest_route(
            'spectrus-guard/v1',
            '/ueba/anomalies/(?P<user_id>\d+)',
            array(
                'methods' => 'GET',
                'callback' => array($this, 'rest_get_anomalies'),
                'permission_callback' => function ($request) {
                    return current_user_can('manage_options');
                },
                'args' => array(
                    'user_id' => array(
                        'validate_callback' => function ($param) {
                            return is_numeric($param);
                        },
                    ),
                ),
            )
        );
    }

    /**
     * REST endpoint: Get user risk score
     *
     * @param WP_REST_Request $request Request object.
     * @return WP_REST_Response
     */
    public function rest_get_risk_score($request)
    {
        $user_id = intval($request['user_id']);
        $metrics = $this->metrics_collector->collect_login_metrics(get_user_by('id', $user_id));
        $baseline = $this->behavior_profile->get_baseline($user_id);

        $risk_score = $this->risk_scorer->calculate_risk_score(
            $user_id,
            $metrics,
            $baseline,
            array()
        );

        return rest_ensure_response(array(
            'user_id' => $user_id,
            'risk_score' => $risk_score,
            'risk_level' => $this->risk_scorer->get_risk_level($risk_score),
        ));
    }

    /**
     * REST endpoint: Get user baseline
     *
     * @param WP_REST_Request $request Request object.
     * @return WP_REST_Response
     */
    public function rest_get_baseline($request)
    {
        $user_id = intval($request['user_id']);
        $baseline = $this->behavior_profile->get_baseline($user_id);

        return rest_ensure_response($baseline);
    }

    /**
     * REST endpoint: Get user anomalies
     *
     * @param WP_REST_Request $request Request object.
     * @return WP_REST_Response
     */
    public function rest_get_anomalies($request)
    {
        $user_id = intval($request['user_id']);
        $metrics = $this->metrics_collector->collect_login_metrics(get_user_by('id', $user_id));
        $baseline = $this->behavior_profile->get_baseline($user_id);

        $anomalies = $this->anomaly_detector->detect_anomalies($metrics, $baseline);

        return rest_ensure_response(array(
            'user_id' => $user_id,
            'anomalies' => $anomalies,
        ));
    }

    /**
     * Cleanup old metrics (daily cron)
     */
    public function cleanup_old_metrics()
    {
        $this->logger->log_debug('UEBA: Running daily cleanup', 'info');

        // Remove metrics older than 90 days
        global $wpdb;

        $table_name = $wpdb->prefix . 'spectrus_ueba_metrics';
        $cutoff_date = date('Y-m-d H:i:s', strtotime('-90 days'));

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$table_name} WHERE timestamp < %s",
                $cutoff_date
            )
        );
    }

    /**
     * Get metrics collector
     *
     * @return SG_Metrics_Collector
     */
    public function get_metrics_collector()
    {
        return $this->metrics_collector;
    }

    /**
     * Get behavior profile
     *
     * @return SG_Behavior_Profile
     */
    public function get_behavior_profile()
    {
        return $this->behavior_profile;
    }

    /**
     * Get anomaly detector
     *
     * @return SG_Anomaly_Detector
     */
    public function get_anomaly_detector()
    {
        return $this->anomaly_detector;
    }

    /**
     * Get risk scorer
     *
     * @return SG_Risk_Scorer
     */
    public function get_risk_scorer()
    {
        return $this->risk_scorer;
    }

    /**
     * Get response engine
     *
     * @return SG_Response_Engine
     */
    public function get_response_engine()
    {
        return $this->response_engine;
    }
}
