<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectrusGuard 2FA Verification</title>
    <style>
        body {
            background-color: #0f172a;
            /* Slate 900 */
            color: #f8fafc;
            /* Slate 50 */
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }

        .sg-2fa-container {
            background-color: #1e293b;
            /* Slate 800 */
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            width: 100%;
            max-width: 400px;
            text-align: center;
            border: 1px solid #334155;
        }

        .sg-logo {
            font-size: 3rem;
            margin-bottom: 1rem;
            display: block;
        }

        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: #f8fafc;
        }

        p {
            color: #94a3b8;
            margin-bottom: 2rem;
            font-size: 0.95rem;
        }

        .sg-input {
            width: 100%;
            padding: 0.75rem;
            background-color: #0f172a;
            border: 1px solid #334155;
            color: #fff;
            border-radius: 4px;
            font-size: 1.25rem;
            text-align: center;
            letter-spacing: 0.5rem;
            margin-bottom: 1.5rem;
            box-sizing: border-box;
        }

        .sg-input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.5);
        }

        .sg-btn {
            background-color: #3b82f6;
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            font-weight: 600;
            border: none;
            cursor: pointer;
            width: 100%;
            font-size: 1rem;
            transition: background-color 0.2s;
        }

        .sg-btn:hover {
            background-color: #2563eb;
        }

        .error-msg {
            color: #ef4444;
            background-color: rgba(239, 68, 68, 0.1);
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>

<body>
    <div class="sg-2fa-container">
        <span class="sg-logo">🛡️</span>
        <h1>Two-Factor Authentication</h1>
        <p>Please enter the 6-digit code from your authenticator app or email to verify your identity.</p>

        <?php if (isset($error)): ?>
            <div class="error-msg">
                <?php echo esc_html($error); ?>
            </div>
        <?php endif; ?>

        <form method="post">
            <?php wp_nonce_field($nonce_action, $nonce_field); ?>
            <input type="text" name="spectrus_2fa_code" class="sg-input" placeholder="000000" maxlength="6" autofocus
                required autocomplete="one-time-code" inputmode="numeric">
            <button type="submit" class="sg-btn"><?php esc_html_e('Verify Login', 'spectrus-guard'); ?></button>
        </form>
    </div>
</body>

</html>