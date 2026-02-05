<?php
/**
 * Quarantine View
 *
 * Template for displaying and managing quarantined files.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}
?>
<div class="wrap sg-dashboard">
    <div class="sg-dashboard-header">
        <h1>
            <span class="sg-logo">🔒</span>
            <?php esc_html_e('Quarantine Vault', 'spectrus-guard'); ?>
        </h1>
        <div class="sg-header-actions">
            <a href="<?php echo admin_url('admin.php?page=spectrus-guard-scanner'); ?>" class="sg-btn">
                <span class="dashicons dashicons-arrow-left-alt"></span>
                <?php esc_html_e('Back to Scanner', 'spectrus-guard'); ?>
            </a>
        </div>
    </div>

    <div class="sg-main-layout">
        <div class="sg-content-column" style="grid-column: span 12;">

            <!-- Info Card -->
            <div class="sg-card"
                style="margin-bottom: 24px; padding: 24px; background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)); border: 1px solid rgba(102, 126, 234, 0.2);">
                <div style="display: flex; align-items: start;">
                    <div
                        style="background: rgba(102, 126, 234, 0.2); border-radius: 50%; width: 56px; height: 56px; display: flex; align-items: center; justify-content: center; margin-right: 20px; flex-shrink: 0;">
                        <span class="dashicons dashicons-lock" style="font-size: 28px; color: #667eea;"></span>
                    </div>
                    <div>
                        <h3
                            style="margin: 0 0 8px 0; color: var(--sg-text-primary); font-size: 20px; font-weight: 700;">
                            <?php esc_html_e('Security Quarantine', 'spectrus-guard'); ?>
                        </h3>
                        <p style="margin: 0; color: var(--sg-text-secondary); font-size: 14px; line-height: 1.6;">
                            <?php esc_html_e('Suspicious files are moved here to prevent them from executing. You can review files, restore false positives, or permanently delete confirmed threats.', 'spectrus-guard'); ?>
                        </p>
                    </div>
                </div>
            </div>

            <!-- Quarantine List -->
            <div class="sg-card">
                <div class="sg-card-header">
                    <h2>
                        <?php esc_html_e('Quarantined Files', 'spectrus-guard'); ?>
                    </h2>
                    <button type="button" class="sg-btn sg-btn-secondary sg-btn-sm" id="sg-refresh-quarantine">
                        <span class="dashicons dashicons-update"></span>
                        <?php esc_html_e('Refresh', 'spectrus-guard'); ?>
                    </button>
                </div>

                <div class="sg-card-body" style="padding: 0;">
                    <!-- Loading State -->
                    <div id="sg-quarantine-loading" style="padding: 60px 20px; text-align: center;">
                        <div class="sg-spinner-ring" style="margin: 0 auto 20px auto;"></div>
                        <p style="color: var(--sg-text-secondary);">
                            <?php esc_html_e('Loading quarantined files...', 'spectrus-guard'); ?>
                        </p>
                    </div>

                    <!-- Empty State -->
                    <div id="sg-quarantine-empty" style="display: none; padding: 60px 20px; text-align: center;">
                        <div style="font-size: 64px; margin-bottom: 24px; opacity: 0.5;">✅</div>
                        <h3 style="margin: 0 0 12px 0;">
                            <?php esc_html_e('No Files in Quarantine', 'spectrus-guard'); ?>
                        </h3>
                        <p style="color: var(--sg-text-secondary); max-width: 500px; margin: 0 auto;">
                            <?php esc_html_e('Great! There are no suspicious files currently quarantined. Your site is clean.', 'spectrus-guard'); ?>
                        </p>
                    </div>

                    <!-- Files Table -->
                    <div id="sg-quarantine-list" style="display: none;">
                        <table class="sg-logs-table">
                            <thead>
                                <tr>
                                    <th style="width: 50px;"></th>
                                    <th>
                                        <?php esc_html_e('Original Filename', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 180px;">
                                        <?php esc_html_e('Quarantine Date', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 100px;">
                                        <?php esc_html_e('File Size', 'spectrus-guard'); ?>
                                    </th>
                                    <th style="width: 220px;">
                                        <?php esc_html_e('Actions', 'spectrus-guard'); ?>
                                    </th>
                                </tr>
                            </thead>
                            <tbody id="sg-quarantine-table-body">
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