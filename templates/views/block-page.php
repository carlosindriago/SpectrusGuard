<?php
/**
 * Block Page Template
 *
 * Variables available:
 * @var string $incident_id
 * @var array $attack
 */
if (!defined('ABSPATH')) {
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php esc_html_e('Access Denied | Security Alert', 'spectrus-guard'); ?></title>
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

        .shield {
            font-size: 5rem;
            margin-bottom: 1rem;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% {
                transform: scale(1);
                opacity: 1;
            }
            50% {
                transform: scale(1.05);
                opacity: 0.8;
            }
        }

        h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: #e94560;
        }

        p {
            color: #a8a8b3;
            line-height: 1.6;
            margin-bottom: 1rem;
        }

        .incident {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1rem;
            font-family: monospace;
            font-size: 0.9rem;
            color: #ffd700;
            margin-top: 2rem;
        }

        .back-btn {
            display: inline-block;
            margin-top: 2rem;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            text-decoration: none;
            border-radius: 25px;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .back-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(102, 126, 234, 0.4);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1><?php esc_html_e('Access Blocked', 'spectrus-guard'); ?></h1>
        <p>
            <?php esc_html_e('Your request has been blocked by our security system.', 'spectrus-guard'); ?>
            <?php esc_html_e('This may be due to suspicious activity detected in your request.', 'spectrus-guard'); ?>
        </p>
        <p>
            <?php esc_html_e('If you believe this is a mistake, please contact the site administrator with the incident ID below.', 'spectrus-guard'); ?>
        </p>
        <div class="incident">
            <?php esc_html_e('Incident ID:', 'spectrus-guard'); ?>
            <?php echo esc_html($incident_id); ?>
        </div>
        <a href="javascript:history.back()" class="back-btn"><?php esc_html_e('← Go Back', 'spectrus-guard'); ?></a>
    </div>
</body>
</html>
