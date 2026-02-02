<?php
/**
 * SpectrusGuard Two-Factor Authentication Handler
 *
 * Manages 2FA verification flow for user authentication.
 * Supports TOTP (authenticator app) and email-based verification.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

declare(strict_types=1);

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_2FA_Handler
 *
 * Handles two-factor authentication verification and sudo mode.
 */
class SG_2FA_Handler
{
    /**
     * Nonce action for 2FA verification form
     */
    private const NONCE_ACTION = 'spectrus_2fa_verify_action';

    /**
     * Nonce field name
     */
    private const NONCE_FIELD = 'spectrus_2fa_nonce';

    /**
     * Pre-auth token expiration in seconds (10 minutes)
     */
    private const PRE_AUTH_EXPIRATION = 600;

    /**
     * Email code expiration in seconds (5 minutes)
     */
    private const EMAIL_CODE_EXPIRATION = 300;

    /**
     * Sudo mode timeout in seconds (15 minutes)
     */
    private const SUDO_TIMEOUT = 900;

    /**
     * Constructor - Register WordPress hooks
     */
    public function __construct()
    {
        // Intercept login after credentials validated
        add_filter('wp_authenticate_user', [$this, 'intercept_login'], 10, 2);

        // Process 2FA verification form
        add_action('login_form_spectrus_2fa_verify', [$this, 'process_2fa_verification']);

        // Protect sensitive actions with sudo mode
        add_action('admin_init', [$this, 'check_sudo_mode_for_sensitive_actions']);
    }

    /**
     * Intercept login after username/password validation
     *
     * If user has 2FA enabled, redirect to verification screen.
     *
     * @param WP_User|WP_Error $user     User object or error.
     * @param string           $password User password.
     * @return WP_User|WP_Error User object to continue or error to stop.
     */
    public function intercept_login($user, string $password)
    {
        // Pass through errors
        if (is_wp_error($user)) {
            return $user;
        }

        // Check if user has 2FA enabled
        $method = get_user_meta($user->ID, 'spectrus_2fa_method', true);

        if (empty($method)) {
            return $user; // No 2FA configured, proceed normally
        }

        // Send email code if using email method
        if ($method === 'email') {
            $this->send_email_code($user);
        }

        // Generate cryptographically secure pre-auth token
        $temp_token = $this->generate_secure_token();
        set_transient(
            'spectrus_pre_auth_' . $temp_token,
            $user->ID,
            self::PRE_AUTH_EXPIRATION
        );

        // Redirect to verification screen
        $verify_url = add_query_arg([
            'action' => 'spectrus_2fa_verify',
            'token' => $temp_token,
        ], wp_login_url());

        wp_redirect($verify_url);
        exit;
    }

    /**
     * Process 2FA verification form submission
     *
     * Validates the 2FA code and completes login if successful.
     */
    public function process_2fa_verification(): void
    {
        // Sanitize and validate token from URL
        $token = isset($_GET['token']) ? sanitize_text_field(wp_unslash($_GET['token'])) : '';

        if (empty($token) || !preg_match('/^[a-f0-9]{32}$/', $token)) {
            wp_die(
                esc_html__('Invalid verification token.', 'spectrus-guard'),
                esc_html__('2FA Error', 'spectrus-guard'),
                ['response' => 400]
            );
        }

        $user_id = get_transient('spectrus_pre_auth_' . $token);

        if (!$user_id) {
            wp_die(
                esc_html__('Session expired. Please login again.', 'spectrus-guard'),
                esc_html__('2FA Error', 'spectrus-guard'),
                ['response' => 403]
            );
        }

        $error = '';

        // Process form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // Verify CSRF nonce
            if (
                !isset($_POST[self::NONCE_FIELD]) ||
                !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST[self::NONCE_FIELD])), self::NONCE_ACTION)
            ) {
                wp_die(
                    esc_html__('Security verification failed. Please try again.', 'spectrus-guard'),
                    esc_html__('Security Error', 'spectrus-guard'),
                    ['response' => 403]
                );
            }

            if (isset($_POST['spectrus_2fa_code'])) {
                $code = sanitize_text_field(wp_unslash($_POST['spectrus_2fa_code']));
                $user = get_user_by('id', $user_id);

                if ($user && $this->validate_2fa($user, $code)) {
                    // Success: Complete login
                    delete_transient('spectrus_pre_auth_' . $token);

                    // Set authentication cookie and mark sudo mode
                    wp_set_auth_cookie($user_id, true);
                    update_user_meta($user_id, 'spectrus_last_sudo', time());

                    wp_safe_redirect(admin_url());
                    exit;
                }

                $error = __('Invalid verification code.', 'spectrus-guard');
            }
        }

        // Render verification form
        $nonce_field = self::NONCE_FIELD;
        $nonce_action = self::NONCE_ACTION;
        include plugin_dir_path(__FILE__) . 'views/verify-2fa.php';
        exit;
    }

    /**
     * Validate 2FA code based on user's configured method
     *
     * @param WP_User $user User object.
     * @param string  $code Verification code to validate.
     * @return bool True if code is valid.
     */
    private function validate_2fa(WP_User $user, string $code): bool
    {
        $method = get_user_meta($user->ID, 'spectrus_2fa_method', true);

        if ($method === 'app') {
            require_once __DIR__ . '/class-sg-totp-engine.php';
            $secret = get_user_meta($user->ID, 'spectrus_2fa_secret', true);
            return Spectrus_TOTP_Engine::verify_code($secret, $code);
        }

        if ($method === 'email') {
            $saved_code = get_transient('spectrus_email_code_' . $user->ID);
            if ($saved_code && hash_equals((string) $saved_code, $code)) {
                // Delete code after successful verification (one-time use)
                delete_transient('spectrus_email_code_' . $user->ID);
                return true;
            }
        }

        return false;
    }

    /**
     * Send email verification code to user
     *
     * @param WP_User $user User object.
     */
    private function send_email_code(WP_User $user): void
    {
        // Generate cryptographically secure 6-digit code
        $code = (string) random_int(100000, 999999);

        set_transient(
            'spectrus_email_code_' . $user->ID,
            $code,
            self::EMAIL_CODE_EXPIRATION
        );

        $subject = sprintf(
            /* translators: %s: Site name */
            __('Your verification code - %s', 'spectrus-guard'),
            get_bloginfo('name')
        );

        $message = sprintf(
            /* translators: 1: Verification code, 2: Expiration in minutes */
            __("Your security verification code is: %1\$s\n\nThis code expires in %2\$d minutes.", 'spectrus-guard'),
            $code,
            self::EMAIL_CODE_EXPIRATION / 60
        );

        wp_mail($user->user_email, $subject, $message);
    }

    /**
     * Generate cryptographically secure token
     *
     * @return string 32-character hex token.
     */
    private function generate_secure_token(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Enforce sudo mode for sensitive configuration changes
     *
     * Requires re-authentication if sudo timeout has expired.
     */
    public function check_sudo_mode_for_sensitive_actions(): void
    {
        global $pagenow;

        // Only protect SpectrusGuard settings page
        $page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';

        if ($pagenow !== 'admin.php' || $page !== 'spectrus-guard') {
            return;
        }

        // Check on POST requests (saving settings)
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        $last_sudo = (int) get_user_meta(get_current_user_id(), 'spectrus_last_sudo', true);

        if (!$last_sudo || (time() - $last_sudo > self::SUDO_TIMEOUT)) {
            wp_die(
                '<strong>' . esc_html__('Sudo Mode Required', 'spectrus-guard') . '</strong><br>' .
                esc_html__('For security, please re-authenticate to modify critical settings.', 'spectrus-guard'),
                esc_html__('Authentication Required', 'spectrus-guard'),
                ['response' => 403, 'back_link' => true]
            );
        }
    }
}

// Backward compatibility alias
class_alias('SG_2FA_Handler', 'Spectrus_2FA_Handler');
