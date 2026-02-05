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
