<?php
/**
 * Page Controller: Security Scanner
 */
if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Scanner
{
    private $loader;

    public function __construct($loader)
    {
        $this->loader = $loader;
        add_action('wp_ajax_sg_run_scan', array($this, 'ajax_run_scan'));
    }

    /**
     * Render the scanner page
     */
    public function render()
    {
        $scanner = $this->loader->get_scanner();
        $results = $scanner ? $scanner->get_display_results() : null;
        $last_scan = $scanner ? $scanner->get_last_scan_time() : null;
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">🛡️</span>
                    <?php esc_html_e('Security Scanner', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-header-actions">
                    <div class="sg-last-scan-badge">
                        <?php if ($last_scan): ?>
                            <span class="dashicons dashicons-clock"></span>
                            <?php printf(esc_html__('Last scan: %s', 'spectrus-guard'), esc_html($last_scan)); ?>
                        <?php else: ?>
                            <?php esc_html_e('No scans yet', 'spectrus-guard'); ?>
                        <?php endif; ?>
                    </div>
                    <button type="button" class="sg-btn sg-btn-primary" id="sg-run-scan">
                        <span class="dashicons dashicons-search"></span>
                        <?php esc_html_e('Run Deep Scan', 'spectrus-guard'); ?>
                    </button>
                </div>
            </div>

            <div class="sg-main-layout">
                <div class="sg-content-column" style="grid-column: span 12;">

                    <!-- Scan Progress Overlay/Area -->
                    <div id="sg-scan-progress" class="sg-card" style="display: none; text-align: center; padding: 40px;">
                        <div class="sg-spinner-ring"></div>
                        <h3 style="margin-top: 20px; color: var(--sg-text-primary);">
                            <?php esc_html_e('Scanning your site...', 'spectrus-guard'); ?>
                        </h3>
                        <p style="color: var(--sg-text-secondary);">
                            <?php esc_html_e('This may take a few moments. We are checking core files, plugins, and configurations.', 'spectrus-guard'); ?>
                        </p>
                    </div>

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
                            </div>
                            <div class="sg-card-body" style="padding: 0;">
                                <?php if (!empty($results['issues'])): ?>
                                    <table class="sg-logs-table">
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
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($results['issues'] as $issue): ?>
                                                <tr>
                                                    <td>
                                                        <span
                                                            class="sg-badge sg-badge-<?php echo esc_attr(strtolower($issue['severity'])); ?>">
                                                            <?php echo esc_html(ucfirst($issue['severity'])); ?>
                                                        </span>
                                                    </td>
                                                    <td><span class="sg-tag">
                                                            <?php echo esc_html(ucfirst($issue['category'])); ?>
                                                        </span>
                                                    </td>
                                                    <td style="font-family: monospace; color: var(--sg-text-muted);">
                                                        <?php echo esc_html($issue['file']); ?>
                                                    </td>
                                                    <td style="color: var(--sg-text-primary);">
                                                        <?php echo esc_html($issue['message']); ?>
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

                </div>
            </div>
        </div>

         <script>
              jQuery(document).ready(function ($) {
                  $('#sg-run-scan').on('click', function () {
                      var $btn = $(this);
                      $btn.prop('disabled', true).addClass('loading');
                      // Hide results, show progress
                      $('.sg-threat-intel-grid, .sg-card:not(#sg-scan-progress)').fadeOut();
                      $('#sg-scan-progress').fadeIn();

                      $.ajax({
                          url: SpectrusGuard.ajax_url,
                          type: 'POST',
                          data: {
                              action: 'sg_run_scan',
                              _ajax_nonce: SpectrusGuard.nonce
                          },
                          success: function (response) {
                              if (response.success) {
                                  location.reload();
                              } else {
                                  alert(response.data.message || '<?php esc_html_e('Scan failed', 'spectrus-guard'); ?>');
                                  location.reload();
                              }
                          },
                          error: function () {
                              alert('<?php esc_html_e('An error occurred during the scan.', 'spectrus-guard'); ?>');
                              location.reload();
                          }
                      });
                  });
              });
         </script>
        <?php
    }

    /**
     * AJAX: Run security scan
     */
    public function ajax_run_scan()
    {
        // Verify nonce - consistent with loader
        check_ajax_referer('spectrus_guard_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('Unauthorized', 'spectrus-guard')));
        }

        $scanner = $this->loader->get_scanner();
        if (!$scanner) {
            wp_send_json_error(array('message' => __('Scanner not available.', 'spectrus-guard')));
        }

        // Check if scanner is already running to prevent duplicate scans
        $scan_lock = get_transient('spectrus_guard_scan_lock');
        if ($scan_lock) {
            wp_send_json_error(array('message' => __('A scan is already in progress. Please wait.', 'spectrus-guard')));
        }

        // Set scan lock for 5 minutes
        set_transient('spectrus_guard_scan_lock', true, 300);

        try {
            // Run fresh scan
            $results = $scanner->run_full_scan(true);

            // Clear scan lock
            delete_transient('spectrus_guard_scan_lock');

            wp_send_json_success(array(
                'message' => __('Scan completed successfully.', 'spectrus-guard'),
                'results' => $scanner->get_display_results(),
            ));
        } catch (Exception $e) {
            // Clear scan lock on error
            delete_transient('spectrus_guard_scan_lock');

            // Log error
            error_log('SpectrusGuard Scan Error: ' . $e->getMessage());

            wp_send_json_error(array(
                'message' => __('Scan failed: ' . $e->getMessage(), 'spectrus-guard'),
                'debug' => $e->getMessage(),
            ));
        }
    }
}
