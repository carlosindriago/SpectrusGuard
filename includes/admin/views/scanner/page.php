<?php
/**
 * Scanner Page View
 *
 * Main template for the Security Scanner page.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/** @var array|null $results */
/** @var string|null $last_scan */
?>
<div class="wrap sg-dashboard">
    <div class="sg-dashboard-header">
        <h1>
            <span class="sg-logo">🛡️</span>
            <?php esc_html_e('Security Scanner', 'spectrus-guard'); ?>
        </h1>
        <div class="sg-header-actions">
            <button type="button" class="sg-btn sg-btn-primary" id="sg-run-scan">
                <span class="dashicons dashicons-search"></span>
                <?php esc_html_e('Run Deep Scan', 'spectrus-guard'); ?>
            </button>
        </div>
    </div>

    <div class="sg-main-layout">
        <div class="sg-content-column" style="grid-column: span 12;">

            <!-- Last Scan Info -->
            <?php if ($last_scan): ?>
                <div class="sg-card"
                    style="margin-bottom: 24px; padding: 20px; display: flex; align-items: center; justify-content: space-between; background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)); border: 1px solid rgba(102, 126, 234, 0.2);">
                    <div style="display: flex; align-items: center;">
                        <div
                            style="background: rgba(102, 126, 234, 0.2); border-radius: 50%; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; margin-right: 16px;">
                            <span class="dashicons dashicons-clock" style="font-size: 24px; color: #667eea;"></span>
                        </div>
                        <div>
                            <div style="font-weight: 600; color: var(--sg-text-primary); margin-bottom: 4px;">
                                <?php esc_html_e('Last Completed Scan', 'spectrus-guard'); ?>
                            </div>
                            <div style="color: var(--sg-text-secondary); font-size: 14px;">
                                <?php echo esc_html($last_scan); ?>
                            </div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 24px; margin-bottom: 4px;">📊</div>
                        <div style="color: var(--sg-text-secondary); font-size: 12px;">
                            <?php esc_html_e('Scan History', 'spectrus-guard'); ?>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Scan Progress Overlay/Area -->
            <div id="sg-scan-progress" class="sg-card" style="display: none; padding: 48px;">
                <!-- Scan Progress Header -->
                <div id="sg-progress-header" style="text-align: center; margin-bottom: 40px;">
                    <div class="sg-spinner-ring" style="margin: 0 auto 24px auto;"></div>
                    <h3 style="margin: 0; color: var(--sg-text-primary); font-size: 24px; font-weight: 700;">
                        <?php esc_html_e('Security Scan in Progress', 'spectrus-guard'); ?>
                    </h3>
                    <p style="margin: 12px 0 0 0; color: var(--sg-text-secondary); font-size: 15px;">
                        <?php esc_html_e('Analyzing your WordPress installation for security threats...', 'spectrus-guard'); ?>
                    </p>
                </div>

                <!-- Progress Bar -->
                <div id="sg-progress-section" style="margin-bottom: 40px;">
                    <div
                        style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <span style="color: var(--sg-text-primary); font-weight: 600; font-size: 15px;"
                            id="sg-progress-label">
                            <?php esc_html_e('Starting scan...', 'spectrus-guard'); ?>
                        </span>
                        <span
                            style="background: linear-gradient(135deg, #667eea, #764ba2); color: #fff; padding: 6px 16px; border-radius: 20px; font-weight: 700; font-size: 16px; min-width: 60px; text-align: center; display: inline-block;"
                            id="sg-progress-percent">0%</span>
                    </div>
                    <div
                        style="height: 16px; background: var(--sg-border); border-radius: 8px; overflow: hidden; position: relative;">
                        <div id="sg-progress-bar"
                            style="height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); width: 0%; transition: width 0.5s ease; border-radius: 8px; position: relative;">
                            <div
                                style="position: absolute; right: 2px; top: 50%; transform: translateY(-50%); width: 4px; height: 70%; background: rgba(255, 255, 255, 0.3); border-radius: 2px;">
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Activity Log -->
                <div id="sg-activity-log"
                    style="background: var(--sg-bg-dark); border: 1px solid var(--sg-border); border-radius: 12px; padding: 24px; max-height: 320px; overflow-y: auto; font-family: 'Monaco', 'Consolas', monospace; font-size: 13px; line-height: 1.8;">
                    <div class="sg-log-entry"
                        style="padding: 8px 12px; margin-bottom: 6px; border-radius: 4px; background: rgba(102, 126, 234, 0.05); color: var(--sg-text-secondary);">
                        <span style="color: #667eea; font-weight: 600;">●</span> <span
                            style="color: #667eea; font-weight: 600;">[START]</span>
                        <?php esc_html_e('Initializing scanner...', 'spectrus-guard'); ?>
                    </div>
                </div>
            </div>

            <!-- Scan History Graph -->
            <div class="sg-card" style="padding: 24px;">
                <h3 class="sg-card-title"
                    style="margin-bottom: 20px; font-size: 18px; color: var(--sg-text-primary); display: flex; align-items: center;">
                    <span class="dashicons dashicons-chart-area"
                        style="margin-right: 10px; font-size: 24px; width: 24px; height: 24px;"></span>
                    <?php esc_html_e('Threat Detection History', 'spectrus-guard'); ?>
                </h3>
                <div class="sg-chart-container" style="position: relative; height: 350px; width: 100%;">
                    <canvas id="sgHistoryChart" role="img"
                        aria-label="<?php esc_attr_e('Threat Detection History Chart', 'spectrus-guard'); ?>">
                        <p><?php esc_html_e('Bar chart showing the number of threats detected over the last 10 scans.', 'spectrus-guard'); ?></p>
                    </canvas>
                </div>
            </div>

            <!-- Inject History Data -->
            <script>
                window.spectrusGuardHistory = <?php echo json_encode(isset($history) ? $history : []); ?>;
            </script>

        </div>
    </div>
</div>