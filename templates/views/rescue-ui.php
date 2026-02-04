<?php
/**
 * Rescue UI Template
 *
 * Variables available:
 * @var string $state   Current state: 'email', '2fa', 'email_code'
 * @var array  $data    Data array with 'error', 'user_id' etc.
 */
if (!defined('ABSPATH')) {
    exit;
}

$error = $data['error'] ?? '';
?>
<!DOCTYPE html>
<html>

<head>
    <title>
        <?php esc_html_e('SpectrusGuard Rescue', 'spectrus-guard'); ?>
    </title>
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
        <h1>⛑️
            <?php esc_html_e('SpectrusGuard Rescue', 'spectrus-guard'); ?>
        </h1>

        <?php if ($error): ?>
            <div class="error">
                <?php echo esc_html($error); ?>
            </div>
        <?php endif; ?>

        <form method="post">
            <?php if ($state === 'email'): ?>
                <p class="note">
                    <?php esc_html_e('Enter your Administrator Email to verify identity.', 'spectrus-guard'); ?>
                </p>
                <input type="email" name="email" placeholder="admin@example.com" required>
                <input type="hidden" name="sg_step" value="verify_email">
                <button type="submit">
                    <?php esc_html_e('Verify Identity', 'spectrus-guard'); ?>
                </button>

            <?php elseif ($state === '2fa'): ?>
                <p class="note">
                    <?php esc_html_e('Your account is protected with 2FA. Enter code from your app.', 'spectrus-guard'); ?>
                </p>
                <input type="text" name="code" placeholder="123456" required pattern="[0-9]*" autocomplete="one-time-code">
                <input type="hidden" name="user_id" value="<?php echo intval($data['user_id']); ?>">
                <input type="hidden" name="mode" value="2fa">
                <input type="hidden" name="sg_step" value="verify_code">
                <button type="submit">
                    <?php esc_html_e('Unlock Site', 'spectrus-guard'); ?>
                </button>

            <?php elseif ($state === 'email_code'): ?>
                <p class="note">
                    <?php esc_html_e('A verification code has been sent to your email.', 'spectrus-guard'); ?>
                </p>
                <input type="text" name="code" placeholder="123456" required>
                <input type="hidden" name="user_id" value="<?php echo intval($data['user_id']); ?>">
                <input type="hidden" name="mode" value="email">
                <input type="hidden" name="sg_step" value="verify_code">
                <button type="submit">
                    <?php esc_html_e('Unlock Site', 'spectrus-guard'); ?>
                </button>
            <?php endif; ?>
        </form>
    </div>
</body>

</html>