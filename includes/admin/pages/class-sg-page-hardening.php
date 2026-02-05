<?php
/**
 * Page Controller: Security Hardening (Login, Cloak, Stealth)
 */
if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Hardening
{
    private $loader;

    public function __construct($loader)
    {
        $this->loader = $loader;
        add_action('wp_ajax_sg_write_htaccess', array($this, 'ajax_write_htaccess'));
        add_action('admin_init', array($this, 'save_user_security_settings'));
    }

    /**
     * Render the Hardening Page (Cloak + Login + Stealth)
     */
    public function render()
    {
        $settings = $this->loader->get_settings();
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'cloak';
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1><span class="sg-logo">👻</span>
                    <?php esc_html_e('Security Hardening', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <?php if ($active_tab === 'cloak'): ?>
                        <button type="submit" form="sg-cloak-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Configuration', 'spectrus-guard'); ?>
                        </button>
                    <?php elseif ($active_tab === 'stealth'): ?>
                        <button type="submit" form="sg-hardening-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Settings', 'spectrus-guard'); ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <h2 class="nav-tab-wrapper" style="margin-bottom: 20px; border-bottom: 1px solid #334155;">
                <a href="?page=spectrus-guard-hardening&tab=cloak"
                    class="nav-tab <?php echo $active_tab == 'cloak' ? 'nav-tab-active' : ''; ?>">
                    👻
                    <?php esc_html_e('Ghost Cloak', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-hardening&tab=login"
                    class="nav-tab <?php echo $active_tab == 'login' ? 'nav-tab-active' : ''; ?>">
                    🔐
                    <?php esc_html_e('Login & 2FA', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-hardening&tab=stealth"
                    class="nav-tab <?php echo $active_tab == 'stealth' ? 'nav-tab-active' : ''; ?>">
                    🥷
                    <?php esc_html_e('Stealth Mode', 'spectrus-guard'); ?>
                </a>
            </h2>

            <?php if ($active_tab === 'cloak'): ?>
                <form method="post" action="options.php" id="sg-cloak-form">
                    <?php
                    settings_fields('spectrus_shield_settings_group');
                    $settings_view = SG_PLUGIN_DIR . 'includes/hardening/views/settings-cloak.php';
                    if (file_exists($settings_view)) {
                        include $settings_view;
                    }
                    ?>
                </form>

            <?php elseif ($active_tab === 'login'): ?>
                <?php
                $view = SG_PLUGIN_DIR . 'includes/hardening/views/login-security.php';
                if (file_exists($view)) {
                    include $view;
                }
                ?>

            <?php elseif ($active_tab === 'stealth'): ?>
                <form method="post" action="options.php" id="sg-hardening-form">
                    <?php settings_fields('spectrus_shield_settings_group'); ?>
                    <input type="hidden" name="spectrus_shield_settings[form_context]" value="stealth">

                    <div class="sg-main-layout">
                        <div class="sg-content-column" style="grid-column: span 12;">

                            <!-- Card 1: Identity Protection -->
                            <div class="sg-card" style="margin-bottom: 24px;">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('Identity Protection', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Hide WordPress Version', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Prevent scanners from identifying your WordPress version.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[hide_wp_version]" value="1"
                                                    <?php checked($settings['hide_wp_version'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Card 2: API & Protocols -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2><?php esc_html_e('API & Protocols', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Disable XML-RPC', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Blocks XML-RPC requests. Recommended if you do not use Jetpack or the mobile app.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[block_xmlrpc]" value="1" <?php checked($settings['block_xmlrpc'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Protect REST API', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Restricts REST API access to authenticated users to prevent user enumeration.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[protect_api]" value="1" <?php checked($settings['protect_api'] ?? true); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- Card 3: REST API Stealth -->
                            <?php
                            $api_settings = $settings['api_hardening'] ?? [];
                            $custom_prefix = $api_settings['custom_prefix'] ?? '';
                            $hide_index = !empty($api_settings['hide_index']);
                            ?>
                            <div class="sg-card" style="margin-top: 24px;">
                                <div class="sg-card-header">
                                    <h2>🔐 <?php esc_html_e('REST API Stealth', 'spectrus-guard'); ?></h2>
                                </div>
                                <div class="sg-settings-card-body">
                                    <p style="color: var(--sg-text-secondary); margin-bottom: 20px;">
                                        <?php esc_html_e('Hide the WordPress REST API endpoint from bots and scanners. When enabled, /wp-json/ returns 404 for non-authenticated users.', 'spectrus-guard'); ?>
                                    </p>

                                    <div class="sg-control-group">
                                        <div class="sg-control-info">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Hide API Index', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Returns 404 on /wp-json/ discovery endpoint for non-admins.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                        <div class="sg-control-input">
                                            <label class="sg-switch">
                                                <input type="checkbox" name="spectrus_shield_settings[api_hardening][hide_index]"
                                                    value="1" <?php checked($hide_index); ?>>
                                                <span class="sg-slider"></span>
                                            </label>
                                        </div>
                                    </div>

                                    <div class="sg-control-group" style="margin-top: 20px;">
                                        <div class="sg-control-info" style="flex: 1;">
                                            <label
                                                class="sg-control-label"><?php esc_html_e('Custom API Prefix', 'spectrus-guard'); ?></label>
                                            <p class="sg-control-desc">
                                                <?php esc_html_e('Replace /wp-json/ with a custom path. Bots scanning for /wp-json/ will get 404.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                    </div>

                                    <div style="display: flex; gap: 12px; align-items: center; margin-top: 12px;">
                                        <code
                                            style="color: var(--sg-text-muted); background: var(--sg-bg-app); padding: 8px 12px; border-radius: 6px;"><?php echo esc_html(home_url('/')); ?></code>
                                        <input type="text" name="spectrus_shield_settings[api_hardening][custom_prefix]"
                                            value="<?php echo esc_attr($custom_prefix); ?>" placeholder="api/v1/secure"
                                            style="flex: 1; max-width: 250px; background: var(--sg-bg-app); border: 1px solid var(--sg-border); color: var(--sg-text-primary); padding: 10px 14px; border-radius: 6px; font-family: monospace;">
                                        <code style="color: var(--sg-text-muted);">/</code>
                                    </div>

                                    <p style="color: var(--sg-text-secondary); margin: 12px 0 0 0; font-size: 13px;">
                                        <?php esc_html_e('Example: api/v1/secure → your API will be at', 'spectrus-guard'); ?>
                                        <code
                                            style="background: rgba(59, 130, 246, 0.1); padding: 2px 6px; border-radius: 4px; color: var(--sg-primary);">
                                                                    <?php echo esc_html(home_url('/api/v1/secure/')); ?>
                                                                </code>
                                    </p>

                                    <div
                                        style="background: rgba(245, 158, 11, 0.1); border-left: 4px solid var(--sg-warning); padding: 12px; margin-top: 20px; border-radius: 4px;">
                                        <p style="margin: 0; font-size: 13px; color: var(--sg-text-primary);">
                                            ⚠️ <strong><?php esc_html_e('Important:', 'spectrus-guard'); ?></strong>
                                            <?php esc_html_e('If using a custom prefix, ensure your REST API clients (mobile apps, external integrations) are updated to use the new URL.', 'spectrus-guard'); ?>
                                        </p>
                                    </div>

                                    <!-- API Exceptions / Whitelist Section -->
                                    <div style="margin-top: 32px; padding-top: 24px; border-top: 1px solid var(--sg-border);">
                                        <div
                                            style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
                                            <div>
                                                <h4 style="margin: 0 0 4px 0; font-size: 16px; color: var(--sg-text-primary);">
                                                    📋 <?php esc_html_e('API Exceptions (Whitelist)', 'spectrus-guard'); ?>
                                                </h4>
                                                <p style="color: var(--sg-text-muted); margin: 0; font-size: 13px;">
                                                    <?php esc_html_e('Allow specific API routes to bypass authentication requirements.', 'spectrus-guard'); ?>
                                                </p>
                                            </div>
                                            <button type="button" id="sg-auto-detect-plugins" class="sg-btn sg-btn-secondary"
                                                style="white-space: nowrap; padding: 8px 16px; font-size: 13px;">
                                                🔍 <?php esc_html_e('Auto-Detect Plugins', 'spectrus-guard'); ?>
                                            </button>
                                        </div>

                                        <!-- Detected Plugins Display -->
                                        <div id="sg-detected-plugins" style="margin-bottom: 16px; display: none;">
                                            <p style="color: var(--sg-text-secondary); font-size: 13px; margin: 0 0 8px 0;">
                                                <strong><?php esc_html_e('Detected plugins using REST API:', 'spectrus-guard'); ?></strong>
                                            </p>
                                            <div id="sg-plugin-chips" style="display: flex; flex-wrap: wrap; gap: 8px;"></div>
                                        </div>

                                        <?php
                                        $user_whitelist = $api_settings['whitelist'] ?? [];
                                        $whitelist_text = is_array($user_whitelist) ? implode("\n", $user_whitelist) : '';
                                        ?>
                                        <div class="sg-control-group">
                                            <label class="sg-control-label"
                                                style="font-weight: 500; margin-bottom: 8px; display: block;">
                                                <?php esc_html_e('Custom Whitelist', 'spectrus-guard'); ?>
                                            </label>
                                            <p style="color: var(--sg-text-muted); margin: 0 0 8px 0; font-size: 13px;">
                                                <?php esc_html_e('Enter route prefixes to whitelist (one per line). Examples: contact-form-7/v1, wc/v3, jetpack/v4', 'spectrus-guard'); ?>
                                            </p>
                                            <textarea name="spectrus_shield_settings[api_hardening][whitelist_raw]"
                                                id="sg-api-whitelist" rows="4"
                                                placeholder="contact-form-7/v1&#10;wc/v3&#10;jetpack/v4"
                                                style="width: 100%; background: var(--sg-bg-app); border: 1px solid var(--sg-border); color: var(--sg-text-primary); padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; resize: vertical;"><?php echo esc_textarea($whitelist_text); ?></textarea>
                                        </div>

                                        <div
                                            style="background: rgba(59, 130, 246, 0.1); border-left: 4px solid var(--sg-primary); padding: 12px; margin-top: 16px; border-radius: 4px;">
                                            <p style="margin: 0; font-size: 13px; color: var(--sg-text-primary);">
                                                💡 <strong><?php esc_html_e('Tip:', 'spectrus-guard'); ?></strong>
                                                <?php esc_html_e('WordPress Core routes (posts, pages, media) and detected plugins are automatically whitelisted. Only add custom routes if you experience issues with specific integrations.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>

                                        <div
                                            style="background: rgba(245, 158, 11, 0.1); border-left: 4px solid var(--sg-warning); padding: 12px; margin-top: 12px; border-radius: 4px;">
                                            <p style="margin: 0; font-size: 13px; color: var(--sg-text-primary);">
                                                ⚠️ <strong><?php esc_html_e('Balance:', 'spectrus-guard'); ?></strong>
                                                <?php esc_html_e('A permissive whitelist reduces stealth effectiveness. Only whitelist routes that are essential for your site functionality.', 'spectrus-guard'); ?>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                        </div>
                    </div>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * AJAX: Write .htaccess rules for Ghost Cloak
     */
    public function ajax_write_htaccess()
    {
        // Use same nonce as rest of plugin
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(__('Insufficient permissions.', 'spectrus-guard'));
        }

        if (!class_exists('Spectrus_Cloak_Engine')) {
            $engine_path = SG_PLUGIN_DIR . 'includes/hardening/class-sg-cloak-engine.php';
            if (file_exists($engine_path)) {
                require_once $engine_path;
            } else {
                wp_send_json_error(__('Cloak Engine not found.', 'spectrus-guard'));
            }
        }

        $htaccess_path = ABSPATH . '.htaccess';

        // Check if .htaccess exists and is writable
        if (!file_exists($htaccess_path)) {
            // Attempt to create it
            if (@file_put_contents($htaccess_path, '') === false) {
                wp_send_json_error(__('Could not create .htaccess file. Please check directory permissions.', 'spectrus-guard'));
            }
        }

        if (!is_writable($htaccess_path)) {
            wp_send_json_error(__('The .htaccess file is not writable. Please set permissions to 644 or 664.', 'spectrus-guard'));
        }

        // Use WordPress core function to write safely
        require_once ABSPATH . 'wp-admin/includes/misc.php';

        // Get dynamic mappings from engine
        $engine = new Spectrus_Cloak_Engine();
        $mappings = method_exists($engine, 'get_public_mappings')
            ? $engine->get_public_mappings()
            : [
                'wp-content/themes' => 'content/skins',
                'wp-content/plugins' => 'content/modules',
                'wp-content/uploads' => 'content/media',
                'wp-includes' => 'core/lib',
            ];

        // Build dynamic rules
        $lines = [];
        $lines[] = '<IfModule mod_rewrite.c>';
        $lines[] = 'RewriteEngine On';

        foreach ($mappings as $real => $fake) {
            // When request comes as FAKE, serve REAL
            $lines[] = "RewriteRule ^{$fake}/(.*) {$real}/\$1 [L,QSA]";
        }

        $lines[] = '</IfModule>';

        // Marker name must match what htaccess_has_rules() checks
        $result = insert_with_markers($htaccess_path, 'SpectrusGuardCloak', $lines);

        if ($result) {
            wp_send_json_success(['message' => __('Rules successfully written to .htaccess', 'spectrus-guard')]);
        } else {
            wp_send_json_error(__('Could not write to .htaccess. Please check file permissions.', 'spectrus-guard'));
        }
    }

    /**
     * Save 2FA settings for the current user
     */
    public function save_user_security_settings()
    {
        if (isset($_POST['spectrus_2fa_method']) && isset($_POST['spectrus_security_nonce'])) {
            if (!wp_verify_nonce($_POST['spectrus_security_nonce'], 'spectrus_save_security')) {
                return;
            }

            $user_id = get_current_user_id();
            $method = sanitize_text_field($_POST['spectrus_2fa_method']);

            // Validate App Setup if selected
            if ($method === 'app') {
                $code = isset($_POST['spectrus_2fa_verify_code']) ? sanitize_text_field($_POST['spectrus_2fa_verify_code']) : '';
                $secret = isset($_POST['spectrus_2fa_secret']) ? sanitize_text_field($_POST['spectrus_2fa_secret']) : '';

                if (empty($code)) {
                    $redirect = add_query_arg(array('page' => 'spectrus-guard-hardening', 'tab' => 'login', 'error' => 'missing_code'), admin_url('admin.php'));
                    wp_redirect($redirect);
                    exit;
                }

                if (class_exists('Spectrus_TOTP_Engine') && !Spectrus_TOTP_Engine::verify_code($secret, $code)) {
                    $redirect = add_query_arg(array('page' => 'spectrus-guard-hardening', 'tab' => 'login', 'error' => 'invalid_code'), admin_url('admin.php'));
                    wp_redirect($redirect);
                    exit;
                }

                // If valid, save the secret
                update_user_meta($user_id, 'spectrus_2fa_secret', $secret);
            }

            update_user_meta($user_id, 'spectrus_2fa_method', $method);

            // Redirect to avoid resubmission
            $redirect = add_query_arg(array('page' => 'spectrus-guard-hardening', 'tab' => 'login', 'updated' => 'true'), admin_url('admin.php'));
            wp_redirect($redirect);
            exit;
        }
    }
}
