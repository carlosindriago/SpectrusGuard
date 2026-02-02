<?php
/**
 * SpectrusGuard Onboarding Wizard Template
 *
 * Full-page wizard for first-run setup.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

$presets = $this->get_presets();
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>

<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>
        <?php esc_html_e('SpectrusGuard Setup Wizard', 'spectrus-guard'); ?>
    </title>
    <?php wp_head(); ?>
</head>

<body class="sg-wizard-body" style="background: #0f172a !important; background-color: #0f172a !important;">
    <div class="sg-wizard-container">
        <!-- Progress Bar -->
        <div class="sg-wizard-progress">
            <div class="sg-progress-bar">
                <div class="sg-progress-fill" id="progress-fill"></div>
            </div>
            <div class="sg-progress-steps">
                <span class="sg-step active" data-step="1">1</span>
                <span class="sg-step" data-step="2">2</span>
                <span class="sg-step" data-step="3">3</span>
            </div>
        </div>

        <!-- Step 1: Welcome -->
        <div class="sg-wizard-step active" id="step-1">
            <div class="sg-wizard-content">
                <div class="sg-wizard-icon">🛡️</div>
                <h1>
                    <?php esc_html_e('Welcome to SpectrusGuard', 'spectrus-guard'); ?>
                </h1>
                <p class="sg-wizard-subtitle">
                    <?php esc_html_e('Your WordPress security fortress. Let\'s configure the protection that\'s right for your site.', 'spectrus-guard'); ?>
                </p>

                <div class="sg-features-grid">
                    <div class="sg-feature-card">
                        <span class="sg-feature-icon">🔥</span>
                        <h3>
                            <?php esc_html_e('Web Application Firewall', 'spectrus-guard'); ?>
                        </h3>
                        <p>
                            <?php esc_html_e('Blocks SQL injection, XSS, and malicious attacks in real-time', 'spectrus-guard'); ?>
                        </p>
                    </div>
                    <div class="sg-feature-card">
                        <span class="sg-feature-icon">🔐</span>
                        <h3>
                            <?php esc_html_e('Login Protection', 'spectrus-guard'); ?>
                        </h3>
                        <p>
                            <?php esc_html_e('Prevents brute force attacks and secures your admin area', 'spectrus-guard'); ?>
                        </p>
                    </div>
                    <div class="sg-feature-card">
                        <span class="sg-feature-icon">🔍</span>
                        <h3>
                            <?php esc_html_e('Malware Scanner', 'spectrus-guard'); ?>
                        </h3>
                        <p>
                            <?php esc_html_e('Deep scans to detect backdoors, malware, and suspicious code', 'spectrus-guard'); ?>
                        </p>
                    </div>
                    <div class="sg-feature-card">
                        <span class="sg-feature-icon">🌍</span>
                        <h3>
                            <?php esc_html_e('Geo-Blocking', 'spectrus-guard'); ?>
                        </h3>
                        <p>
                            <?php esc_html_e('Block access from specific countries and Tor exit nodes', 'spectrus-guard'); ?>
                        </p>
                    </div>
                </div>

                <div class="sg-wizard-actions">
                    <button type="button" class="sg-btn sg-btn-primary sg-btn-lg" id="btn-start">
                        <?php esc_html_e('Get Started', 'spectrus-guard'); ?>
                        <span class="sg-btn-arrow">→</span>
                    </button>
                </div>

                <div class="sg-wizard-skip">
                    <a href="#" id="btn-skip-wizard">
                        <?php esc_html_e('Skip for now', 'spectrus-guard'); ?>
                    </a>
                </div>
            </div>
        </div>

        <!-- Step 2: Site Type Selection -->
        <div class="sg-wizard-step" id="step-2">
            <div class="sg-wizard-content">
                <h1>
                    <?php esc_html_e('What type of site is this?', 'spectrus-guard'); ?>
                </h1>
                <p class="sg-wizard-subtitle">
                    <?php esc_html_e('We\'ll recommend the best security settings based on your site type.', 'spectrus-guard'); ?>
                </p>

                <div class="sg-preset-grid">
                    <?php foreach ($presets as $key => $preset): ?>
                        <div class="sg-preset-card" data-preset="<?php echo esc_attr($key); ?>">
                            <div class="sg-preset-icon">
                                <?php echo esc_html($preset['icon']); ?>
                            </div>
                            <h3>
                                <?php echo esc_html($preset['name']); ?>
                            </h3>
                            <p>
                                <?php echo esc_html($preset['description']); ?>
                            </p>
                            <div class="sg-preset-check">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                                    <polyline points="20 6 9 17 4 12"></polyline>
                                </svg>
                            </div>
                        </div>
                    <?php endforeach; ?>

                    <div class="sg-preset-card" data-preset="custom">
                        <div class="sg-preset-icon">⚙️</div>
                        <h3>
                            <?php esc_html_e('Custom Setup', 'spectrus-guard'); ?>
                        </h3>
                        <p>
                            <?php esc_html_e('Choose exactly which features to enable', 'spectrus-guard'); ?>
                        </p>
                        <div class="sg-preset-check">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                        </div>
                    </div>
                </div>

                <div class="sg-wizard-actions">
                    <button type="button" class="sg-btn sg-btn-secondary" id="btn-back-1">
                        <span class="sg-btn-arrow">←</span>
                        <?php esc_html_e('Back', 'spectrus-guard'); ?>
                    </button>
                    <button type="button" class="sg-btn sg-btn-primary" id="btn-next-2" disabled>
                        <?php esc_html_e('Continue', 'spectrus-guard'); ?>
                        <span class="sg-btn-arrow">→</span>
                    </button>
                </div>
            </div>
        </div>

        <!-- Step 3: Confirm & Features -->
        <div class="sg-wizard-step" id="step-3">
            <div class="sg-wizard-content">
                <h1 id="step3-title">
                    <?php esc_html_e('Recommended Settings', 'spectrus-guard'); ?>
                </h1>
                <p class="sg-wizard-subtitle">
                    <?php esc_html_e('These features will be enabled based on your selection. You can adjust them later in Settings.', 'spectrus-guard'); ?>
                </p>

                <div class="sg-settings-list" id="settings-list">
                    <!-- Filled by JavaScript -->
                </div>

                <!-- Custom Settings (shown when custom preset selected) -->
                <div class="sg-custom-settings" id="custom-settings" style="display: none;">
                    <div class="sg-settings-group">
                        <h3 class="sg-settings-group-title sg-critical">
                            <span class="sg-badge sg-badge-critical">
                                <?php esc_html_e('Critical', 'spectrus-guard'); ?>
                            </span>
                            <?php esc_html_e('Essential Protection', 'spectrus-guard'); ?>
                        </h3>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Web Application Firewall (WAF)', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Blocks SQL injection, XSS, path traversal attacks', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[waf_enabled]" value="1" checked
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Login Attempt Limiting', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Blocks brute force attacks on your login page', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[login_limit_enabled]" value="1" checked
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Hide WordPress Version', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Removes version info that hackers use to find vulnerabilities', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[hide_wp_version]" value="1" checked
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>
                    </div>

                    <div class="sg-settings-group">
                        <h3 class="sg-settings-group-title sg-recommended">
                            <span class="sg-badge sg-badge-warning">
                                <?php esc_html_e('Recommended', 'spectrus-guard'); ?>
                            </span>
                            <?php esc_html_e('Enhanced Security', 'spectrus-guard'); ?>
                        </h3>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Two-Factor Authentication', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Require a code from your phone to log in', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[enable_2fa_admins]" value="1" class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Custom Login URL', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Hide wp-login.php to prevent targeted attacks', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[custom_login_enabled]" value="1"
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Security Headers', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Add HTTP headers that protect against common attacks', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[security_headers_enabled]" value="1"
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>
                    </div>

                    <div class="sg-settings-group">
                        <h3 class="sg-settings-group-title sg-optional">
                            <span class="sg-badge sg-badge-info">
                                <?php esc_html_e('Optional', 'spectrus-guard'); ?>
                            </span>
                            <?php esc_html_e('Advanced Features', 'spectrus-guard'); ?>
                        </h3>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Geo-Blocking', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Block visitors from specific countries', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[geo_blocking_enabled]" value="1"
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('File Change Monitoring', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Get alerts when core files are modified', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[file_monitor_enabled]" value="1"
                                class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>

                        <label class="sg-toggle-row">
                            <span class="sg-toggle-info">
                                <strong>
                                    <?php esc_html_e('Automatic Malware Scanning', 'spectrus-guard'); ?>
                                </strong>
                                <small>
                                    <?php esc_html_e('Scheduled daily scans for malware detection', 'spectrus-guard'); ?>
                                </small>
                            </span>
                            <input type="checkbox" name="settings[auto_scan_enabled]" value="1" class="sg-toggle-input">
                            <span class="sg-toggle"></span>
                        </label>
                    </div>
                </div>

                <div class="sg-wizard-actions">
                    <button type="button" class="sg-btn sg-btn-secondary" id="btn-back-2">
                        <span class="sg-btn-arrow">←</span>
                        <?php esc_html_e('Back', 'spectrus-guard'); ?>
                    </button>
                    <button type="button" class="sg-btn sg-btn-success sg-btn-lg" id="btn-finish">
                        <span class="sg-btn-icon">🛡️</span>
                        <?php esc_html_e('Activate Protection', 'spectrus-guard'); ?>
                    </button>
                </div>
            </div>
        </div>

        <!-- Skip Modal -->
        <div class="sg-modal" id="skip-modal" style="display: none;">
            <div class="sg-modal-backdrop"></div>
            <div class="sg-modal-content">
                <div class="sg-modal-icon">⚠️</div>
                <h2>
                    <?php esc_html_e('Skip Setup?', 'spectrus-guard'); ?>
                </h2>
                <p>
                    <?php esc_html_e('Without completing setup, critical security features like the WAF will remain disabled. Your site may be vulnerable to attacks.', 'spectrus-guard'); ?>
                </p>

                <div class="sg-modal-actions">
                    <button type="button" class="sg-btn sg-btn-secondary" id="btn-remind-later">
                        <?php esc_html_e('Remind me later', 'spectrus-guard'); ?>
                    </button>
                    <button type="button" class="sg-btn sg-btn-danger" id="btn-skip-anyway">
                        <?php esc_html_e('Skip anyway', 'spectrus-guard'); ?>
                    </button>
                </div>

                <button type="button" class="sg-btn sg-btn-primary sg-btn-block" id="btn-continue-setup">
                    <?php esc_html_e('Continue Setup', 'spectrus-guard'); ?>
                </button>
            </div>
        </div>

        <!-- Loading Overlay -->
        <div class="sg-loading-overlay" id="loading-overlay" style="display: none;">
            <div class="sg-loading-spinner"></div>
            <p>
                <?php esc_html_e('Applying security settings...', 'spectrus-guard'); ?>
            </p>
        </div>

        <!-- Footer -->
        <div class="sg-wizard-footer">
            <p>
                SpectrusGuard v
                <?php echo esc_html(SG_VERSION); ?> ·
                <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard')); ?>">
                    <?php esc_html_e('Go to Dashboard', 'spectrus-guard'); ?>
                </a>
            </p>
        </div>
    </div>

    <?php wp_footer(); ?>
</body>

</html>