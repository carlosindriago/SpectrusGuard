<?php
/**
 * SpectrusGuard Response Engine
 *
 * Executes automated responses based on risk levels.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Response_Engine
 *
 * Automated response system for detected threats.
 */
class SG_Response_Engine
{

    /**
     * Logger instance
     *
     * @var SG_Logger
     */
    private $logger;

    /**
     * Risk level actions
     *
     * @var array
     */
    private $risk_actions = array(
        'LOW' => array(
            'action' => 'log',
            'notify_admin' => false,
            'block_user' => false,
            'challenge_user' => false,
        ),
        'MEDIUM' => array(
            'action' => 'warn',
            'notify_admin' => false,
            'block_user' => false,
            'challenge_user' => false,
        ),
        'HIGH' => array(
            'action' => 'challenge',
            'notify_admin' => true,
            'block_user' => false,
            'challenge_user' => true,
        ),
        'CRITICAL' => array(
            'action' => 'block',
            'notify_admin' => true,
            'block_user' => true,
            'challenge_user' => true,
        ),
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
     * Execute response based on risk level
     *
     * @param int    $risk_score  Risk score (0-100).
     * @param string $risk_level  Risk level (LOW/MEDIUM/HIGH/CRITICAL).
     * @param array  $context     Context data.
     */
    public function execute_response($risk_score, $risk_level, $context)
    {
        $actions = $this->risk_actions[$risk_level] ?? $this->risk_actions['LOW'];

        // Log the event
        $this->log_security_event($risk_score, $risk_level, $context);

        // Execute actions based on risk level
        switch ($risk_level) {
            case 'LOW':
                $this->handle_low_risk($context);
                break;

            case 'MEDIUM':
                $this->handle_medium_risk($context);
                break;

            case 'HIGH':
                $this->handle_high_risk($context);
                break;

            case 'CRITICAL':
                $this->handle_critical_risk($context);
                break;

            default:
                $this->handle_low_risk($context);
        }
    }

    /**
     * Handle LOW risk
     *
     * @param array $context Context data.
     */
    private function handle_low_risk($context)
    {
        // Just log, no action needed
        $this->logger->log_debug('UEBA: LOW risk detected - no action taken', 'info');
    }

    /**
     * Handle MEDIUM risk
     *
     * @param array $context Context data.
     */
    private function handle_medium_risk($context)
    {
        // Show warning in admin
        add_action('admin_notices', function () use ($context) {
            $user_id = isset($context['user_id']) ? $context['user_id'] : 0;
            $ip = isset($context['ip']) ? $context['ip'] : 'unknown';
            $anomalies = isset($context['anomalies']) ? $context['anomalies'] : array();

            echo '<div class="notice notice-warning is-dismissible">';
            echo '<p><strong>⚠️ SpectrusGuard: Unusual Activity Detected</strong></p>';
            echo '<p>We detected unusual activity on your account:</p>';
            echo '<ul>';

            foreach ($anomalies as $anomaly) {
                echo '<li>' . esc_html($anomaly['description'] ?? 'Unknown anomaly') . '</li>';
            }

            echo '</ul>';
            echo '<p><strong>IP:</strong> ' . esc_html($ip) . '</p>';
            echo '<p>If this was you, you can ignore this message. If not, please change your password immediately.</p>';
            echo '</div>';
        });

        $this->logger->log_debug('UEBA: MEDIUM risk - warning displayed', 'warning');
    }

    /**
     * Handle HIGH risk
     *
     * @param array $context Context data.
     */
    private function handle_high_risk($context)
    {
        // Require additional 2FA
        $this->force_additional_verification($context);

        // Notify admin
        $this->notify_admin($context, 'HIGH');

        // Set transient to track this user as "high risk"
        $user_id = isset($context['user_id']) ? $context['user_id'] : 0;
        if ($user_id > 0) {
            set_transient('sg_user_high_risk_' . $user_id, true, 3600); // 1 hour
        }

        $this->logger->log_debug('UEBA: HIGH risk - additional verification required', 'alert');
    }

    /**
     * Handle CRITICAL risk
     *
     * @param array $context Context data.
     */
    private function handle_critical_risk($context)
    {
        // Block the IP
        $this->block_ip($context);

        // Logout the user
        $this->logout_user($context);

        // Notify admin urgently
        $this->notify_admin($context, 'CRITICAL');

        // Log critical event
        $this->logger->log_debug('UEBA: CRITICAL risk - user blocked and notified', 'critical');

        // Display block page
        $this->display_critical_block_page($context);
    }

    /**
     * Force additional verification (2FA)
     *
     * @param array $context Context data.
     */
    private function force_additional_verification($context)
    {
        // Set session flag to require additional 2FA
        if (session_status() === PHP_SESSION_NONE) {
            @session_start();
        }

        $_SESSION['sg_require_additional_2fa'] = true;
        $_SESSION['sg_2fa_reason'] = 'unusual_activity';
    }

    /**
     * Block IP address
     *
     * @param array $context Context data.
     */
    private function block_ip($context)
    {
        $ip = isset($context['ip']) ? $context['ip'] : '0.0.0.0';

        // Add to blocked IPs list
        $settings = get_option('spectrus_shield_settings', array());
        $blocked_ips = isset($settings['blocked_ips']) ? (array) $settings['blocked_ips'] : array();

        if (!in_array($ip, $blocked_ips, true)) {
            $blocked_ips[] = $ip;
            $settings['blocked_ips'] = $blocked_ips;
            update_option('spectrus_shield_settings', $settings);
        }

        // Set transient for immediate block
        set_transient('sg_blocked_' . md5($ip), true, 3600); // 1 hour
    }

    /**
     * Logout user
     *
     * @param array $context Context data.
     */
    private function logout_user($context)
    {
        $user_id = isset($context['user_id']) ? $context['user_id'] : 0;

        if ($user_id > 0 && is_user_logged_in()) {
            // Destroy session
            wp_destroy_current_session();
            wp_clear_auth_cookie();

            // Force logout
            wp_logout();
        }
    }

    /**
     * Notify admin about security event
     *
     * @param array  $context   Context data.
     * @param string $risk_level Risk level.
     */
    private function notify_admin($context, $risk_level)
    {
        $admin_email = get_option('admin_email');
        $user_id = isset($context['user_id']) ? $context['user_id'] : 0;
        $ip = isset($context['ip']) ? $context['ip'] : 'unknown';
        $risk_score = isset($context['risk_score']) ? $context['risk_score'] : 0;
        $anomalies = isset($context['anomalies']) ? $context['anomalies'] : array();

        // Get user info
        $user = get_userdata($user_id);
        $user_login = $user ? $user->user_login : 'Unknown';
        $user_email = $user ? $user->user_email : 'Unknown';

        // Prepare email
        $subject = sprintf(
            '🚨 SpectrusGuard: %s Security Alert - Risk Score: %d/100',
            $risk_level,
            $risk_score
        );

        $message = sprintf(
            "SECURITY ALERT DETECTED\n\n" .
            "Risk Level: %s\n" .
            "Risk Score: %d/100\n\n" .
            "User Details:\n" .
            "- ID: %d\n" .
            "- Username: %s\n" .
            "- Email: %s\n\n" .
            "Session Details:\n" .
            "- IP Address: %s\n" .
            "- Time: %s\n\n" .
            "Detected Anomalies:\n",
            $risk_level,
            $risk_score,
            $user_id,
            $user_login,
            $user_email,
            $ip,
            date('Y-m-d H:i:s')
        );

        // List anomalies
        foreach ($anomalies as $index => $anomaly) {
            $message .= sprintf(
                "%d. [%s] %s\n",
                $index + 1,
                $anomaly['severity'] ?? 'MEDIUM',
                $anomaly['description'] ?? 'Unknown anomaly'
            );
        }

        $message .= sprintf(
            "\nRecommended Action: %s\n\n" .
            "Please review this activity and take appropriate action.\n\n" .
            "---\n" .
            "SpectrusGuard Security Suite",
            $this->risk_actions[$risk_level]['action'] ?? 'review'
        );

        // Send email
        wp_mail($admin_email, $subject, $message);
    }

    /**
     * Log security event
     *
     * @param int    $risk_score  Risk score.
     * @param string $risk_level  Risk level.
     * @param array  $context     Context data.
     */
    private function log_security_event($risk_score, $risk_level, $context)
    {
        $user_id = isset($context['user_id']) ? $context['user_id'] : 0;
        $ip = isset($context['ip']) ? $context['ip'] : 'unknown';

        $log_data = array(
            'event_type' => 'ueba_security_event',
            'risk_score' => $risk_score,
            'risk_level' => $risk_level,
            'user_id' => $user_id,
            'ip' => $ip,
            'anomalies_count' => isset($context['anomalies']) ? count($context['anomalies']) : 0,
            'timestamp' => time(),
        );

        $this->logger->log_attack(
            $risk_level,
            json_encode($log_data),
            $ip,
            isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '',
            $log_data
        );
    }

    /**
     * Display critical block page
     *
     * @param array $context Context data.
     */
    private function display_critical_block_page($context)
    {
        // Don't display if headers already sent
        if (headers_sent()) {
            return;
        }

        // Set headers
        status_header(403);
        header('Content-Type: text/html; charset=utf-8');
        header('X-SpectrusGuard-Block: UEBA-CRITICAL');

        // Get details
        $risk_score = isset($context['risk_score']) ? $context['risk_score'] : 0;
        $ip = isset($context['ip']) ? $context['ip'] : 'unknown';
        $incident_id = substr(md5(uniqid('', true)), 0, 12);

        // Output HTML
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="robots" content="noindex, nofollow">
            <title>Access Blocked - Security Alert</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #fff;
                }
                .container {
                    text-align: center;
                    padding: 2rem;
                    max-width: 600px;
                }
                .alert-icon {
                    font-size: 5rem;
                    margin-bottom: 1.5rem;
                    animation: pulse 2s ease-in-out infinite;
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); opacity: 1; }
                    50% { transform: scale(1.05); opacity: 0.8; }
                }
                h1 {
                    font-size: 2.5rem;
                    margin-bottom: 1rem;
                    color: #ef4444;
                }
                p {
                    color: #a8a8b3;
                    line-height: 1.6;
                    margin-bottom: 1rem;
                }
                .incident-box {
                    background: rgba(239, 68, 68, 0.1);
                    border: 2px solid rgba(239, 68, 68, 0.3);
                    border-radius: 12px;
                    padding: 1.5rem;
                    font-family: 'Monaco', 'Consolas', monospace;
                    font-size: 0.9rem;
                    color: #ef4444;
                    margin: 2rem 0;
                    text-align: left;
                }
                .incident-box .label {
                    color: #fff;
                    font-weight: bold;
                    display: inline-block;
                    width: 140px;
                }
                .info-box {
                    background: rgba(255, 255, 255, 0.05);
                    border-radius: 8px;
                    padding: 1rem;
                    margin: 1.5rem 0;
                    border-left: 4px solid #ef4444;
                    text-align: left;
                }
                .btn {
                    display: inline-block;
                    margin-top: 1rem;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #fff;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: 600;
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 10px 40px rgba(102, 126, 234, 0.4);
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="alert-icon">🚨</div>
                <h1>ACCESS BLOCKED</h1>
                <p>Your account has been temporarily blocked due to unusual activity detected.</p>
                <p>Our security system identified suspicious behavior that requires administrator review.</p>
                
                <div class="info-box">
                    <strong>What happened?</strong><br>
                    We detected anomalies in your login behavior that significantly differ from your usual patterns. This is a security measure to protect your account.
                </div>
                
                <div class="incident-box">
                    <div><span class="label">Incident ID:</span> <?php echo esc_html($incident_id); ?></div>
                    <div><span class="label">Risk Score:</span> <?php echo esc_html($risk_score); ?>/100 (CRITICAL)</div>
                    <div><span class="label">IP Address:</span> <?php echo esc_html($ip); ?></div>
                    <div><span class="label">Time:</span> <?php echo esc_html(date('Y-m-d H:i:s')); ?></div>
                </div>
                
                <p><strong>What should I do?</strong></p>
                <p>Contact your site administrator with the Incident ID above. They can review the security event and unblock your account if appropriate.</p>
                
                <a href="<?php echo esc_url(home_url('/')); ?>" class="btn">Return to Homepage</a>
            </div>
        </body>
        </html>
        <?php

        // Exit to prevent WordPress from continuing
        exit;
    }

    /**
     * Update risk actions (configurable)
     *
     * @param array $new_actions New actions.
     */
    public function update_actions($new_actions)
    {
        $this->risk_actions = wp_parse_args($new_actions, $this->risk_actions);
    }

    /**
     * Get current actions
     *
     * @return array Current actions.
     */
    public function get_actions()
    {
        return $this->risk_actions;
    }
}
