<?php
/**
 * Scan Results Template
 *
 * Template for displaying scan results or empty state.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/** @var array|null $results */
?>

<?php if ($results && $results['has_results']): ?>

    <!-- Summary Cards -->
    <div class="sg-threat-intel-grid" style="margin-bottom: 24px;">
        <div class="sg-stat-card <?php echo $results['summary']['critical'] > 0 ? 'danger-border' : ''; ?>">
            <div class="sg-stat-icon critical">🚨</div>
            <div class="sg-stat-data">
                <span class="sg-stat-number">
                    <?php echo esc_html($results['summary']['critical']); ?>
                </span>
                <span class="sg-stat-label">Critical Issues</span>
            </div>
        </div>
        <div class="sg-stat-card <?php echo $results['summary']['high'] > 0 ? 'warning-border' : ''; ?>">
            <div class="sg-stat-icon high">🔥</div>
            <div class="sg-stat-data">
                <span class="sg-stat-number">
                    <?php echo esc_html($results['summary']['high']); ?>
                </span>
                <span class="sg-stat-label">High Priority</span>
            </div>
        </div>
        <div class="sg-stat-card">
            <div class="sg-stat-icon medium">⚠️</div>
            <div class="sg-stat-data">
                <span class="sg-stat-number">
                    <?php echo esc_html($results['summary']['medium']); ?>
                </span>
                <span class="sg-stat-label">Medium Priority</span>
            </div>
        </div>
        <div class="sg-stat-card">
            <div class="sg-stat-icon low">ℹ️</div>
            <div class="sg-stat-data">
                <span class="sg-stat-number">
                    <?php echo esc_html($results['summary']['low']); ?>
                </span>
                <span class="sg-stat-label">Low Priority</span>
            </div>
        </div>
    </div>

    <!-- Issues List -->
    <div class="sg-card">
        <div class="sg-card-header">
            <h2>
                <?php esc_html_e('Vulnerabilities Found', 'spectrus-guard'); ?>
            </h2>
            <button type="button" class="sg-btn sg-btn-primary" onclick="document.getElementById('sg-run-scan').click()">
                <span class="dashicons dashicons-search"></span>
                <?php esc_html_e('Run New Scan', 'spectrus-guard'); ?>
            </button>
        </div>
        <div class="sg-card-body" style="padding: 0;">
            <?php if (!empty($results['issues'])): ?>
                <table class="sg-logs-table" id="sg-issues-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">
                                <?php esc_html_e('Severity', 'spectrus-guard'); ?>
                            </th>
                            <th style="width: 120px;">
                                <?php esc_html_e('Category', 'spectrus-guard'); ?>
                            </th>
                            <th>
                                <?php esc_html_e('Location', 'spectrus-guard'); ?>
                            </th>
                            <th>
                                <?php esc_html_e('Issue Description', 'spectrus-guard'); ?>
                            </th>
                            <th style="width: 260px;">
                                <?php esc_html_e('Actions', 'spectrus-guard'); ?>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($results['issues'] as $index => $issue): ?>
                            <?php
                            $can_delete = $issue['category'] !== 'core';
                            $severity_colors = array(
                                'critical' => '#e94560',
                                'high' => '#ff8e53',
                                'medium' => '#ffc107',
                                'low' => '#6c757d',
                                'info' => '#17a2b8'
                            );
                            $color = isset($severity_colors[$issue['severity']]) ? $severity_colors[$issue['severity']] : '#6c757d';
                            ?>
                            <tr id="threat-<?php echo esc_attr($index); ?>">
                                <td>
                                    <span class="sg-badge sg-badge-<?php echo esc_attr(strtolower($issue['severity'])); ?>">
                                        <?php echo esc_html(ucfirst($issue['severity'])); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="sg-tag">
                                        <?php echo esc_html(ucfirst($issue['category'])); ?>
                                    </span>
                                </td>
                                <td style="font-family: monospace; color: var(--sg-text-muted); word-break: break-all;">
                                    <?php echo esc_html($issue['file']); ?>
                                </td>
                                <td style="color: var(--sg-text-primary);">
                                    <?php echo esc_html($issue['message']); ?>
                                </td>
                                <td>
                                    <?php if ($can_delete): ?>
                                        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                            <button type="button" class="sg-btn sg-btn-whitelist sg-btn-sm"
                                                data-file="<?php echo esc_attr($issue['file']); ?>"
                                                data-index="<?php echo esc_attr($index); ?>"
                                                aria-label="<?php echo esc_attr(sprintf(__('Whitelist %s', 'spectrus-guard'), $issue['file'])); ?>"
                                                style="background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.4); color: #22c55e; padding: 8px 16px; font-size: 12px; border-radius: 6px; font-weight: 600;">
                                                ✓ Whitelist
                                            </button>
                                            <button type="button" class="sg-btn sg-btn-quarantine sg-btn-sm"
                                                data-file="<?php echo esc_attr($issue['file']); ?>"
                                                data-index="<?php echo esc_attr($index); ?>"
                                                aria-label="<?php echo esc_attr(sprintf(__('Quarantine %s', 'spectrus-guard'), $issue['file'])); ?>"
                                                style="background: rgba(255, 193, 7, 0.15); border: 1px solid rgba(255, 193, 7, 0.4); color: #ffc107; padding: 8px 16px; font-size: 12px; border-radius: 6px; font-weight: 600;">
                                                🔒 Quarantine
                                            </button>
                                            <button type="button" class="sg-btn sg-btn-delete sg-btn-sm"
                                                data-file="<?php echo esc_attr($issue['file']); ?>"
                                                data-index="<?php echo esc_attr($index); ?>"
                                                aria-label="<?php echo esc_attr(sprintf(__('Delete %s', 'spectrus-guard'), $issue['file'])); ?>"
                                                style="background: rgba(233, 69, 96, 0.15); border: 1px solid rgba(233, 69, 96, 0.4); color: #e94560; padding: 8px 16px; font-size: 12px; border-radius: 6px; font-weight: 600;">
                                                🗑️ Delete
                                            </button>
                                        </div>
                                    <?php else: ?>
                                        <button type="button" class="sg-btn sg-btn-sm" disabled
                                            style="background: rgba(255,255,255,0.05); color: var(--sg-text-secondary); padding: 8px 16px; font-size: 12px; border-radius: 6px; opacity: 0.5;">
                                            ⚠️ Restore from WordPress core
                                        </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div style="padding: 40px; text-align: center;">
                    <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
                    <h3 style="margin: 0;">
                        <?php esc_html_e('Clean Scan!', 'spectrus-guard'); ?>
                    </h3>
                    <p style="color: var(--sg-text-secondary);">
                        <?php esc_html_e('No vulnerabilities detected in the last scan.', 'spectrus-guard'); ?>
                    </p>
                </div>
            <?php endif; ?>
        </div>
    </div>

<?php else: ?>
    <!-- Empty State -->
    <div class="sg-card" style="text-align: center; padding: 60px 20px;">
        <div style="font-size: 64px; margin-bottom: 24px; opacity: 0.5;">🔍</div>
        <h2>
            <?php esc_html_e('No Scan Results Yet', 'spectrus-guard'); ?>
        </h2>
        <p style="color: var(--sg-text-secondary); max-width: 500px; margin: 0 auto 24px;">
            <?php esc_html_e('Run your first security scan to detect malware, backdoors, and configuration issues on your WordPress site.', 'spectrus-guard'); ?>
        </p>
        <button type="button" class="sg-btn sg-btn-primary sg-btn-lg"
            onclick="document.getElementById('sg-run-scan').click();">
            <?php esc_html_e('Start Initial Scan', 'spectrus-guard'); ?>
        </button>
    </div>
<?php endif; ?>
