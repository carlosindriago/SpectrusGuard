<?php
/**
 * Whitelist View
 *
 * Template for displaying and managing whitelisted files.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap sg-dashboard">
    <div class="sg-dashboard-header">
        <h1>
            <span class="sg-logo">✓</span>
            <?php esc_html_e('Whitelist Management', 'spectrus-guard'); ?>
        </h1>
        <div class="sg-header-actions">
            <a href="<?php echo admin_url('admin.php?page=spectrus-guard-scanner'); ?>" class="sg-btn">
                <span class="dashicons dashicons-search"></span>
                <?php esc_html_e('Run Scan', 'spectrus-guard'); ?>
            </a>
        </div>
    </div>

    <div class="sg-main-layout">
        <div class="sg-content-column" style="grid-column: span 12;">

            <!-- Warning Banner -->
            <div class="sg-card"
                style="margin-bottom: 24px; padding: 20px; background: linear-gradient(135deg, rgba(234, 179, 8, 0.1), rgba(161, 98, 7, 0.1)); border: 2px solid rgba(234, 179, 8, 0.4);">
                <div style="display: flex; align-items: start;">
                    <div
                        style="background: rgba(234, 179, 8, 0.2); border-radius: 50%; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; margin-right: 16px; flex-shrink: 0;">
                        <span class="dashicons dashicons-warning" style="font-size: 24px; color: #eab308;"></span>
                    </div>
                    <div>
                        <h3
                            style="margin: 0 0 8px 0; color: var(--sg-text-primary); font-size: 18px; font-weight: 700;">
                            <?php esc_html_e('⚠️ Use Whitelist with Extreme Caution', 'spectrus-guard'); ?>
                        </h3>
                        <p style="margin: 0; color: var(--sg-text-secondary); font-size: 14px; line-height: 1.6;">
                            <?php esc_html_e('Files in this list will be PERMANENTLY ignored by the scanner. Only whitelist files you have personally verified are 100% safe. You are fully responsible for any security consequences.', 'spectrus-guard'); ?>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Whitelist List -->
            <div class="sg-card">
                <div class="sg-card-header">
                    <h2>
                        <?php esc_html_e('Whitelisted Files', 'spectrus-guard'); ?>
                    </h2>
                    <button type="button" class="sg-btn sg-btn-secondary sg-btn-sm" id="sg-refresh-whitelist">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e('Refresh', 'spectrus-guard'); ?>
                    </button>
                </div>

                <div class="sg-card-body" style="padding: 0;">
                    <!-- Loading State -->
                    <div id="sg-whitelist-loading" style="padding: 60px 20px; text-align: center;">
                        <div class="sg-spinner-ring" style="margin: 0 auto 20px auto;"></div>
                        <p style="color: var(--sg-text-secondary);">
                            <?php esc_html_e('Loading whitelisted files...', 'spectrus-guard'); ?>
                        </p>
                    </div>

                    <!-- Empty State -->
                    <div id="sg-whitelist-empty" style="display: none; padding: 60px 20px; text-align: center;">
                        <div style="font-size: 64px; margin-bottom: 24px; opacity: 0.5;">✓</div>
                        <h3 style="margin: 0 0 12px 0;">
                            <?php esc_html_e('No Whitelisted Files', 'spectrus-guard'); ?>
                        </h3>
                        <p style="color: var(--sg-text-secondary); max-width: 500px; margin: 0 auto;">
                            <?php esc_html_e('No files are currently whitelisted. The scanner will flag all suspicious files.', 'spectrus-guard'); ?>
                        </p>
                    </div>

                    <!-- Files Table -->
                    <div id="sg-whitelist-list" style="display: none;">
                        <table class="sg-logs-table">
                            <thead>
                                <tr>
                                    <th style="width: 50px;"></th>
                                    <th>
                                        <?php esc_html_e('File Path', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 180px;">
                                        <?php esc_html_e('SHA-256 Hash', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 160px;">
                                        <?php esc_html_e('Whitelisted By', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 140px;">
                                        <?php esc_html_e('Date Added', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 100px;">
                                        <?php esc_html_e('Actions', 'spectrus-guard'); ?>
                                    </th>
                                </tr>
                            </thead>
                            <tbody id="sg-whitelist-table-body">
                                <!-- Dynamic content -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <style>
        /* Full dark mode background */
        #wpcontent,
        #wpfooter {
            background: var(--sg-bg-primary, #0f172a) !important;
        }

        #wpbody-content {
            padding-bottom: 0 !important;
        }

        #wpfooter {
            color: var(--sg-text-muted, #64748b);
            border-top: 1px solid var(--sg-border, #334155);
            margin-left: 0;
            padding: 20px;
        }

        #wpfooter a {
            color: var(--sg-primary, #6366f1);
        }
    </style>
</div>