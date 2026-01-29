<?php
// Ensure dependencies
if (!class_exists('Spectrus_TOTP_Engine')) {
    require_once plugin_dir_path(__FILE__) . '../class-sg-totp-engine.php';
}

$user_id = get_current_user_id();
$current_method = get_user_meta($user_id, 'spectrus_2fa_method', true);
$secret = get_user_meta($user_id, 'spectrus_2fa_secret', true);

// Generate new secret if none exists
if (!$secret) {
    $secret = Spectrus_TOTP_Engine::generate_secret();
    // We don't save it yet, only when they save the form. 
    // Actually, to ensure the QR matches what is eventually saved, we might want to suggest saving this secret.
    // However, standard flow is: show secret -> user scans -> user enters code to verify (ideal) -> save.
    // For this MVP, we will generate it and expect the user to save the settings which will persist it.
    // To avoid changing secret on every refresh before saving, we could store in transient or just rely on the user saving immediately.
    // Let's rely on hidden input.
}

$otpauth = "otpauth://totp/SpectrusGuard:" . wp_get_current_user()->user_email . "?secret=" . $secret . "&issuer=SpectrusGuard";
?>

<div class="sg-form-group">
    <label class="sg-label">
        <?php esc_html_e('Authentication Method', 'spectrus-guard'); ?>
    </label>
    <select name="spectrus_2fa_method" id="spectrus_2fa_method" class="sg-form-control" style="max-width: 300px;">
        <option value="" <?php selected($current_method, ''); ?>>
            <?php esc_html_e('Disabled', 'spectrus-guard'); ?>
        </option>
        <option value="app" <?php selected($current_method, 'app'); ?>>
            <?php esc_html_e('Mobile App (Google Auth / Authy)', 'spectrus-guard'); ?>
        </option>
        <option value="email" <?php selected($current_method, 'email'); ?>>
            <?php esc_html_e('Email Verification', 'spectrus-guard'); ?>
        </option>
    </select>
    <p class="description">
        <?php esc_html_e('Choose how you want to verify your login.', 'spectrus-guard'); ?>
    </p>
</div>

<!-- App Configuration Section -->
<div id="sg-2fa-app-config"
    style="display: none; margin-top: 20px; padding: 20px; background: rgba(0,0,0,0.2); border-radius: 8px;">
    <h3 style="margin-top: 0; color: var(--sg-text-primary);">
        <?php esc_html_e('Setup Authenticator App', 'spectrus-guard'); ?>
    </h3>

    <div style="display: flex; gap: 30px; align-items: flex-start;">
        <div style="background: white; padding: 10px; border-radius: 4px;">
            <div id="sg-qrcode"></div>
        </div>
        <div>
            <p style="margin-top: 0;"><strong>1. Scan the QR code</strong> with your authenticator app.</p>
            <p><strong>2. Or enter this code manually:</strong></p>
            <code
                style="display: block; background: #0f172a; padding: 10px; border-radius: 4px; color: #f8fafc; font-family: monospace; font-size: 1.2em; letter-spacing: 2px; margin: 10px 0;">
                    <?php echo esc_html($secret); ?>
                </code>
            <input type="hidden" name="spectrus_2fa_secret" value="<?php echo esc_attr($secret); ?>">

            <p style="margin-top: 20px;"><strong>3. Verify Setup:</strong></p>
            <p class="description">Enter the 6-digit code from your app to confirm it's working.</p>
            <input type="text" name="spectrus_2fa_verify_code" class="sg-input-text" placeholder="000000" maxlength="6"
                pattern="[0-9]*" inputmode="numeric"
                style="background: #0f172a; border: 1px solid #334155; color: #fff; padding: 8px; border-radius: 4px; width: 150px; text-align: center; letter-spacing: 4px; font-size: 1.2em;">
        </div>
    </div>
</div>

<!-- Load QRCode.js from CDN -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>
    jQuery(document).ready(function ($) {
        var qrcode = new QRCode(document.getElementById("sg-qrcode"), {
            text: "<?php echo $otpauth; ?>",
            width: 128,
            height: 128,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });

        function toggleAppConfig() {
            if ($('#spectrus_2fa_method').val() === 'app') {
                $('#sg-2fa-app-config').slideDown();
            } else {
                $('#sg-2fa-app-config').slideUp();
            }
        }

        $('#spectrus_2fa_method').on('change', toggleAppConfig);
        toggleAppConfig(); // Init
    });
</script>