<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Ghost_Rescue
 * Handles the emergency rescue mechanism securely.
 */
class SG_Ghost_Rescue
{
    private $settings;

    public function __construct()
    {
        $this->settings = get_option('spectrus_shield_settings', []);
    }

    /**
     * Run the rescue check
     */
    public function run()
    {
        if (!isset($_GET['ghost_rescue'])) {
            return;
        }

        $input_key = sanitize_text_field($_GET['ghost_rescue']);
        $actual_key = $this->settings['rescue_key'] ?? '';

        // If no key configured or mismatch, ignore
        if (empty($actual_key) || !hash_equals($actual_key, $input_key)) {
            return;
        }

        // --- AUTHENTICATED RESCUE SEQUENCE ---

        // 1. Security Headers (No Robots)
        if (!headers_sent()) {
            header('X-Robots-Tag: noindex, nofollow');
        }

        // 2. Process Flow
        $step = $_POST['sg_step'] ?? 'email';
        $error = '';

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $error = $this->handle_post();
        } else {
            // Initial View
            $this->render_ui('email');
        }

        exit;
    }

    private function handle_post()
    {
        $step = $_POST['sg_step'] ?? '';

        if ($step === 'verify_email') {
            return $this->process_email_step();
        } elseif ($step === 'verify_code') {
            return $this->process_code_step();
        }

        return 'Invalid Request';
    }

    private function process_email_step()
    {
        $email = sanitize_email($_POST['email'] ?? '');
        $user = get_user_by('email', $email);

        if (!$user || !user_can($user, 'manage_options')) {
            // Delay to prevent enumeration
            sleep(1);
            // Generic error for security
            return __('Invalid email or insufficient permissions.', 'spectrus-guard');
        }

        // Check 2FA Status
        $has_2fa = get_user_meta($user->ID, 'sg_2fa_enabled', true);

        if ($has_2fa) {
            // User has 2FA, ask for it
            $this->render_ui('2fa', ['user_id' => $user->ID]);
        } else {
            // No 2FA, send email code using cryptographically secure RNG
            $code = random_int(100000, 999999);
            set_transient('sg_rescue_' . $user->ID, $code, 10 * 60); // 10 mins

            $subject = __('[SpectrusGuard] Emergency Rescue Code', 'spectrus-guard');
            $message = sprintf(__('Your rescue code is: %s', 'spectrus-guard'), $code);
            wp_mail($email, $subject, $message);

            $this->render_ui('email_code', ['user_id' => $user->ID]);
        }
    }

    private function process_code_step()
    {
        $user_id = intval($_POST['user_id']);
        $code = sanitize_text_field($_POST['code']);
        $mode = $_POST['mode']; // '2fa' or 'email'

        if ($mode === '2fa') {
            if (!class_exists('SG_Sentinel_2FA')) {
                require_once SG_PLUGIN_DIR . 'includes/sentinel/class-sg-sentinel-2fa.php';
            }
            $sentinel = new SG_Sentinel_2FA(); // Revisit if this needs args
            $valid = $sentinel->verify_code($user_id, $code);
        } else {
            $saved_code = get_transient('sg_rescue_' . $user_id);
            $valid = ($saved_code && hash_equals((string) $saved_code, (string) $code));
        }

        if ($valid) {
            // SUCCESS! Disable Cloaking
            $this->disable_cloaking();

            // Redirect to Login
            wp_redirect(wp_login_url());
            exit;
        } else {
            return __('Invalid Code. Please try again.', 'spectrus-guard');
        }
    }

    private function disable_cloaking()
    {
        $settings = get_option('spectrus_shield_settings', []);
        $settings['url_cloaking_enabled'] = 0; // Disable
        update_option('spectrus_shield_settings', $settings);

        // Also update legacy just in case
        update_option('sg_cloak_active', 0);
    }

    private function render_ui($state, $data = [])
    {
        $error = $data['error'] ?? '';

        ?>
        <!DOCTYPE html>
        <html>

        <head>
            <title>SpectrusGuard Rescue</title>
            <meta name="robots" content="noindex, nofollow">
            <style>
                body {
                    font-family: -apple-system, system-ui, sans-serif;
                    background: #0f172a;
                    color: #e2e8f0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                }

                .card {
                    background: #1e293b;
                    padding: 2rem;
                    border-radius: 12px;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                    width: 100%;
                    max-width: 400px;
                    border: 1px solid #334155;
                }

                h1 {
                    margin-top: 0;
                    font-size: 1.5rem;
                    color: #fff;
                    text-align: center;
                    margin-bottom: 1.5rem;
                }

                input {
                    width: 100%;
                    padding: 0.75rem;
                    margin-bottom: 1rem;
                    border-radius: 6px;
                    border: 1px solid #475569;
                    background: #0f172a;
                    color: #fff;
                    box-sizing: border-box;
                }

                button {
                    width: 100%;
                    padding: 0.75rem;
                    background: #ef4444;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                    cursor: pointer;
                    transition: background 0.2s;
                }

                button:hover {
                    background: #dc2626;
                }

                .error {
                    background: rgba(239, 68, 68, 0.1);
                    color: #ef4444;
                    padding: 0.75rem;
                    border-radius: 6px;
                    margin-bottom: 1rem;
                    text-align: center;
                }

                .note {
                    font-size: 0.875rem;
                    color: #94a3b8;
                    text-align: center;
                    margin-top: 1rem;
                }
            </style>
        </head>

        <body>
            <div class="card">
                <h1>⛑️ SpectrusGuard Rescue</h1>

                <?php if ($error): ?>
                    <div class="error">
                        <?php echo esc_html($error); ?>
                    </div>
                <?php endif; ?>

                <form method="post">
                    <?php if ($state === 'email'): ?>
                        <p class="note">Enter your Administrator Email to verify identity.</p>
                        <input type="email" name="email" placeholder="admin@example.com" required>
                        <input type="hidden" name="sg_step" value="verify_email">
                        <button type="submit">Verify Identity</button>

                    <?php elseif ($state === '2fa'): ?>
                        <p class="note">Your account is protected with 2FA. Enter code from your app.</p>
                        <input type="text" name="code" placeholder="123456" required pattern="[0-9]*" autocomplete="one-time-code">
                        <input type="hidden" name="user_id" value="<?php echo intval($data['user_id']); ?>">
                        <input type="hidden" name="mode" value="2fa">
                        <input type="hidden" name="sg_step" value="verify_code">
                        <button type="submit">Unlock Site</button>

                    <?php elseif ($state === 'email_code'): ?>
                        <p class="note">A verification code has been sent to your email.</p>
                        <input type="text" name="code" placeholder="123456" required>
                        <input type="hidden" name="user_id" value="<?php echo intval($data['user_id']); ?>">
                        <input type="hidden" name="mode" value="email">
                        <input type="hidden" name="sg_step" value="verify_code">
                        <button type="submit">Unlock Site</button>
                    <?php endif; ?>
                </form>
            </div>
        </body>

        </html>
        <?php
        exit;
    }
}
