<?php
/**
 * Page Controller: Global Settings
 */
if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Settings
{
    private $loader;

    public function __construct($loader)
    {
        $this->loader = $loader;
    }

    /**
     * Render the settings page
     */
    public function render()
    {
        $settings = $this->loader->get_settings();
        $active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'general';
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">⚙️</span>
                    <?php esc_html_e('SpectrusGuard Settings', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <?php if ($active_tab === 'security'): ?>
                        <button type="submit" form="sg-security-form" class="sg-btn sg-btn-primary">
                            <span class="dashicons dashicons-saved"></span>
                            <?php esc_html_e('Save Security', 'spectrus-guard'); ?>
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <?php
            if (isset($_GET['error'])) {
                $error_message = '';
                if ($_GET['error'] === 'invalid_code') {
                    $error_message = __('Invalid verification code. Please scan the QR code and try again.', 'spectrus-guard');
                } elseif ($_GET['error'] === 'missing_code') {
                    $error_message = __('Please enter the verification code from your authenticator app.', 'spectrus-guard');
                }

                if ($error_message) {
                    echo '<div class="notice notice-error is-dismissible" style="margin: 20px 0 10px;"><p>' . esc_html($error_message) . '</p></div>';
                }
            }
            if (isset($_GET['updated']) && $_GET['updated'] === 'true') {
                echo '<div class="notice notice-success is-dismissible" style="margin: 20px 0 10px;"><p>' . esc_html__('Settings saved successfully.', 'spectrus-guard') . '</p></div>';
            }
            ?>

            <h2 class="nav-tab-wrapper" style="margin-bottom: 20px; border-bottom: 1px solid #334155;">
                <a href="?page=spectrus-guard-settings&tab=general"
                    class="nav-tab <?php echo $active_tab == 'general' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('General', 'spectrus-guard'); ?>
                </a>
                <a href="?page=spectrus-guard-settings&tab=license"
                    class="nav-tab <?php echo $active_tab == 'license' ? 'nav-tab-active' : ''; ?>">
                    <?php esc_html_e('License', 'spectrus-guard'); ?>
                </a>
            </h2>

            <?php if ($active_tab === 'general'): ?>
                <div class="sg-main-layout">
                    <div class="sg-content-column" style="grid-column: span 12;">

                        <!-- Hero Status -->
                        <div class="sg-card"
                            style="background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%); margin-bottom: 24px; border: 1px solid #334155;">
                            <div class="sg-card-body"
                                style="padding: 24px; display: flex; align-items: center; justify-content: space-between;">
                                <div style="display: flex; align-items: center; gap: 16px;">
                                    <div
                                        style="width: 48px; height: 48px; background: rgba(59, 130, 246, 0.1); border-radius: 12px; display: flex; align-items: center; justify-content: center;">
                                        <span class="dashicons dashicons-shield"
                                            style="font-size: 24px; color: #3b82f6; width: 24px; height: 24px;"></span>
                                    </div>
                                    <div>
                                        <h2 style="margin: 0 0 4px 0; color: #fff; font-size: 18px;">SpectrusGuard is Active</h2>
                                        <p style="margin: 0; color: #94a3b8;">Your site is currently protected against malicious
                                            traffic.</p>
                                    </div>
                                </div>
                                <div>
                                    <span class="sg-badge sg-badge-success"
                                        style="font-size: 13px; padding: 6px 12px; border-radius: 20px;">v
                                        <?php echo esc_html(SG_VERSION); ?>
                                    </span>
                                </div>
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px;">

                            <!-- Configuration Navigation -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2>
                                        <?php esc_html_e('Security Modules', 'spectrus-guard'); ?>
                                    </h2>
                                </div>
                                <div class="sg-card-body">
                                    <p style="color: var(--sg-text-secondary); margin-bottom: 20px; font-size: 13px;">
                                        <?php esc_html_e('Quickly access and configure your security policies.', 'spectrus-guard'); ?>
                                    </p>
                                    <div class="sg-nav-grid" style="display: grid; gap: 12px;">
                                        <a href="?page=spectrus-guard-firewall"
                                            style="display: flex; align-items: center; padding: 16px; background: rgba(59, 130, 246, 0.05); border: 1px solid rgba(59, 130, 246, 0.1); border-radius: 8px; text-decoration: none; transition: all 0.2s;">
                                            <span class="dashicons dashicons-shield-alt"
                                                style="font-size: 20px; width: 20px; height: 20px; margin-right: 16px; color: #3b82f6;"></span>
                                            <div>
                                                <strong style="display: block; color: #e2e8f0; margin-bottom: 2px;">Firewall &
                                                    Geo-Defense</strong>
                                                <span style="font-size: 12px; color: #94a3b8;">Configure WAF rules and Country
                                                    Blocking</span>
                                            </div>
                                            <span class="dashicons dashicons-arrow-right-alt2"
                                                style="margin-left: auto; color: #475569;"></span>
                                        </a>

                                        <a href="?page=spectrus-guard-hardening"
                                            style="display: flex; align-items: center; padding: 16px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.1); border-radius: 8px; text-decoration: none; transition: all 0.2s;">
                                            <span class="dashicons dashicons-lock"
                                                style="font-size: 20px; width: 20px; height: 20px; margin-right: 16px; color: #10b981;"></span>
                                            <div>
                                                <strong
                                                    style="display: block; color: #e2e8f0; margin-bottom: 2px;">Hardening</strong>
                                                <span style="font-size: 12px; color: #94a3b8;">Login Guard, Ghost Cloak, Stealth
                                                    Mode</span>
                                            </div>
                                            <span class="dashicons dashicons-arrow-right-alt2"
                                                style="margin-left: auto; color: #475569;"></span>
                                        </a>

                                        <a href="?page=spectrus-guard-scanner"
                                            style="display: flex; align-items: center; padding: 16px; background: rgba(245, 158, 11, 0.05); border: 1px solid rgba(245, 158, 11, 0.1); border-radius: 8px; text-decoration: none; transition: all 0.2s;">
                                            <span class="dashicons dashicons-search"
                                                style="font-size: 20px; width: 20px; height: 20px; margin-right: 16px; color: #f59e0b;"></span>
                                            <div>
                                                <strong style="display: block; color: #e2e8f0; margin-bottom: 2px;">Security
                                                    Scanner</strong>
                                                <span style="font-size: 12px; color: #94a3b8;">Run malware scans and file integrity
                                                    checks</span>
                                            </div>
                                            <span class="dashicons dashicons-arrow-right-alt2"
                                                style="margin-left: auto; color: #475569;"></span>
                                        </a>
                                    </div>
                                </div>
                            </div>

                            <!-- System Environment -->
                            <div class="sg-card">
                                <div class="sg-card-header">
                                    <h2>
                                        <?php esc_html_e('System Environment', 'spectrus-guard'); ?>
                                    </h2>
                                </div>
                                <div class="sg-card-body">
                                    <ul style="margin: 0; padding: 0; list-style: none;">
                                        <li
                                            style="display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #334155;">
                                            <span
                                                style="color: var(--sg-text-secondary); display: flex; align-items: center; gap: 8px;">
                                                <span class="dashicons dashicons-wordpress" style="color: #64748b;"></span>
                                                WordPress
                                            </span>
                                            <strong style="color: #e2e8f0;">
                                                <?php echo esc_html(get_bloginfo('version')); ?>
                                            </strong>
                                        </li>
                                        <li
                                            style="display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #334155;">
                                            <span
                                                style="color: var(--sg-text-secondary); display: flex; align-items: center; gap: 8px;">
                                                <span class="dashicons dashicons-editor-code" style="color: #64748b;"></span> PHP
                                                Version
                                            </span>
                                            <strong style="color: #e2e8f0;">
                                                <?php echo esc_html(phpversion()); ?>
                                            </strong>
                                        </li>
                                        <li
                                            style="display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #334155;">
                                            <span
                                                style="color: var(--sg-text-secondary); display: flex; align-items: center; gap: 8px;">
                                                <span class="dashicons dashicons-networking" style="color: #64748b;"></span> Server
                                            </span>
                                            <strong style="color: #e2e8f0; font-size: 12px;">
                                                <?php echo esc_html(substr($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown', 0, 25)); ?>
                                            </strong>
                                        </li>
                                        <li style="display: flex; justify-content: space-between; padding: 12px 0;">
                                            <span
                                                style="color: var(--sg-text-secondary); display: flex; align-items: center; gap: 8px;">
                                                <span class="dashicons dashicons-database" style="color: #64748b;"></span> Database
                                            </span>
                                            <strong style="color: #e2e8f0;">MySQL</strong>
                                        </li>
                                    </ul>

                                    <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #334155;">
                                        <a href="?page=spectrus-guard-settings&tab=license"
                                            style="font-size: 12px; color: #94a3b8; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 6px;">
                                            View License Details <span class="dashicons dashicons-external"
                                                style="font-size: 14px;"></span>
                                        </a>
                                    </div>
                                </div>
                            </div>

                        </div>
                    </div>
                </div>

            <?php elseif ($active_tab === 'license'): ?>
                <div class="sg-main-layout">
                    <div class="sg-content-column" style="grid-column: span 12; display: flex; justify-content: center;">
                        <div class="sg-card" style="width: 100%; max-width: 600px;">
                            <div class="sg-card-header">
                                <h2>
                                    <?php esc_html_e('License', 'spectrus-guard'); ?>
                                </h2>
                            </div>
                            <div class="sg-settings-card-body">
                                <div class="sg-control-group">
                                    <label class="sg-control-label">Community Edition</label>
                                    <p class="sg-control-desc">You are using the free version of SpectrusGuard. Upgrade to Pro for
                                        advanced features.</p>
                                </div>
                                <div style="margin-top: 20px; text-align: center;">
                                    <button class="sg-btn sg-btn-primary" disabled>
                                        <?php esc_html_e('Manage License', 'spectrus-guard'); ?> (Pro Only)
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <?php
    }
}
