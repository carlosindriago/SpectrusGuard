<?php
/**
 * SpectrusGuard Geo-Defense Settings View
 *
 * @package SpectrusGuard
 * @since   1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

// Load countries list
$countries_file = SG_PLUGIN_DIR . 'includes/geo/countries.json';
$countries = file_exists($countries_file) ? json_decode(file_get_contents($countries_file), true) : array();

// Get current settings
$settings = get_option('spectrus_shield_settings', array());
$blocked_countries = isset($settings['geo_blocked_countries']) ? (array) $settings['geo_blocked_countries'] : array();
$block_tor = !empty($settings['geo_block_tor']);
$geo_action = isset($settings['geo_action']) ? $settings['geo_action'] : '403';

// Get database status
require_once SG_PLUGIN_DIR . 'includes/geo/class-sg-geo-engine.php';
$geo_engine = new SG_Geo_Engine();
$db_info = $geo_engine->get_database_info();
$geo_stats = $geo_engine->get_stats();

// Get updater status
require_once SG_PLUGIN_DIR . 'includes/geo/class-sg-geo-updater.php';
$updater = new SG_Geo_Updater();
$updater_status = $updater->get_status();
?>

<div class="sg-settings-section">
    <input type="hidden" name="spectrus_shield_settings[form_context]" value="geo">
    <!-- Database Status Card -->
    <div class="sg-card sg-card-status">
        <div class="sg-card-header">
            <h3>📡 GeoIP Database Status</h3>
        </div>
        <div class="sg-card-body">
            <div class="sg-status-grid">
                <div class="sg-status-item">
                    <span class="sg-status-label">Status</span>
                    <span class="sg-status-value">
                        <?php if ($db_info['installed']): ?>
                            <span class="sg-badge sg-badge-success">✓ Installed</span>
                        <?php else: ?>
                            <span class="sg-badge sg-badge-warning">⚠ Not Installed</span>
                        <?php endif; ?>
                    </span>
                </div>

                <?php if ($db_info['installed']): ?>
                    <div class="sg-status-item">
                        <span class="sg-status-label">Database Size</span>
                        <span class="sg-status-value">
                            <?php echo esc_html(size_format($db_info['size'])); ?>
                        </span>
                    </div>
                    <div class="sg-status-item">
                        <span class="sg-status-label">Last Updated</span>
                        <span class="sg-status-value">
                            <?php
                            echo $db_info['modified']
                                ? esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), $db_info['modified']))
                                : 'Unknown';
                            ?>
                        </span>
                    </div>
                <?php endif; ?>

                <div class="sg-status-item">
                    <span class="sg-status-label">Tor Exit Nodes</span>
                    <span class="sg-status-value">
                        <?php echo esc_html(number_format($db_info['tor_nodes_count'])); ?> IPs
                        <?php if ($db_info['last_tor_update']): ?>
                            <small>(Updated:
                                <?php echo esc_html(date_i18n('M j', $db_info['last_tor_update'])); ?>)
                            </small>
                        <?php endif; ?>
                    </span>
                </div>
            </div>

            <!-- MaxMind License Key -->
            <?php if (!$db_info['installed'] || !$updater_status['has_license']): ?>
                <div class="sg-license-setup">
                    <h4>🔑 Setup MaxMind Database</h4>
                    <p class="sg-description">
                        SpectrusGuard uses MaxMind's free GeoLite2 database for IP geolocation.
                        <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank" rel="noopener">
                            Get your free license key here →
                        </a>
                    </p>

                    <!-- Tab navigation for setup methods -->
                    <div class="sg-setup-tabs">
                        <button type="button" class="sg-tab-btn active" data-tab="auto">⚡ Auto Download</button>
                        <button type="button" class="sg-tab-btn" data-tab="manual">📂 Manual Upload</button>
                    </div>

                    <!-- Auto Download Tab -->
                    <div class="sg-tab-content active" id="sg-tab-auto">
                        <div class="sg-license-form">
                            <input type="text" id="sg-maxmind-license" class="sg-input"
                                placeholder="Enter your MaxMind License Key" style="width: 350px;">
                            <button type="button" id="sg-download-db" class="sg-btn sg-btn-primary">
                                <span class="sg-btn-text">Download Database</span>
                                <span class="sg-btn-loading" style="display:none;">⏳ Processing...</span>
                            </button>
                        </div>
                        <!-- Progress section -->
                        <div id="sg-download-progress" class="sg-progress-container" style="display:none;">
                            <div class="sg-progress-bar">
                                <div class="sg-progress-fill" id="sg-progress-fill"></div>
                            </div>
                            <div class="sg-progress-status" id="sg-progress-status">Initializing...</div>
                        </div>
                        <div id="sg-db-download-status" class="sg-notice" style="display:none;"></div>
                    </div>

                    <!-- Manual Upload Tab -->
                    <div class="sg-tab-content" id="sg-tab-manual">
                        <div class="sg-manual-instructions">
                            <p><strong>Having trouble with auto download?</strong> Follow these steps:</p>
                            <ol>
                                <li>Go to <a href="https://www.maxmind.com/en/accounts/current/geoip/downloads"
                                        target="_blank" rel="noopener">MaxMind Downloads</a> (login required)</li>
                                <li>Download <code>GeoLite2-Country</code> → <code>Download GZIP</code></li>
                                <li>Extract the <code>.mmdb</code> file from the downloaded archive</li>
                                <li>Upload the <code>GeoLite2-Country.mmdb</code> file below:</li>
                            </ol>
                            <div class="sg-upload-form">
                                <input type="file" id="sg-mmdb-file" accept=".mmdb" class="sg-file-input">
                                <button type="button" id="sg-upload-mmdb" class="sg-btn sg-btn-primary">
                                    📤 Upload Database File
                                </button>
                            </div>
                            <div id="sg-upload-status" class="sg-notice" style="display:none;"></div>
                        </div>
                    </div>
                </div>
            <?php else: ?>
                <div class="sg-update-actions">
                    <button type="button" id="sg-update-db" class="sg-btn sg-btn-secondary">
                        🔄 Update GeoIP Database
                    </button>
                    <button type="button" id="sg-update-tor" class="sg-btn sg-btn-secondary">
                        🧅 Update Tor Nodes List
                    </button>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Stats Card -->
    <?php if ($geo_stats['total_blocked'] > 0): ?>
        <div class="sg-card sg-card-stats">
            <div class="sg-card-header">
                <h3>📊 Geo-Block Statistics</h3>
            </div>
            <div class="sg-card-body">
                <div class="sg-stat-big">
                    <span class="sg-stat-number">
                        <?php echo esc_html(number_format($geo_stats['total_blocked'])); ?>
                    </span>
                    <span class="sg-stat-label">Total Blocked Requests</span>
                </div>

                <?php if (!empty($geo_stats['by_country'])):
                    arsort($geo_stats['by_country']);
                    $top_countries = array_slice($geo_stats['by_country'], 0, 5, true);
                    ?>
                    <div class="sg-top-countries">
                        <h4>Top Blocked Countries</h4>
                        <ul class="sg-country-stats">
                            <?php foreach ($top_countries as $code => $count):
                                $country_name = isset($countries[$code]) ? $countries[$code]['name'] : $code;
                                $flag = isset($countries[$code]) ? $countries[$code]['flag'] : '🌐';
                                ?>
                                <li>
                                    <span class="sg-country-flag">
                                        <?php echo esc_html($flag); ?>
                                    </span>
                                    <span class="sg-country-name">
                                        <?php echo esc_html($country_name); ?>
                                    </span>
                                    <span class="sg-country-count">
                                        <?php echo esc_html(number_format($count)); ?>
                                    </span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>

    <!-- Country Selector -->
    <div class="sg-card">
        <div class="sg-card-header">
            <h3>🌍 Geo-Defense Strategy</h3>
            <p>Block access from specific countries. Use with caution.</p>
        </div>
        <div class="sg-card-body">
            <div class="sg-geo-grid">
                <!-- Available Countries -->
                <div class="sg-geo-panel">
                    <h4>Available Countries</h4>
                    <input type="text" id="sg-country-search" class="sg-input sg-search-input"
                        placeholder="Search country (e.g., Russia)...">
                    <div class="sg-country-list" id="sg-available-list">
                        <?php foreach ($countries as $code => $country):
                            if (in_array($code, $blocked_countries))
                                continue;
                            ?>
                            <div class="sg-country-item" data-code="<?php echo esc_attr($code); ?>">
                                <span class="sg-country-flag">
                                    <?php echo esc_html($country['flag']); ?>
                                </span>
                                <span class="sg-country-name">
                                    <?php echo esc_html($country['name']); ?>
                                </span>
                                <span class="sg-country-code">
                                    <?php echo esc_html($code); ?>
                                </span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <!-- Blocked Countries -->
                <div class="sg-geo-panel sg-geo-blocked-panel">
                    <h4>🚫 Blocked Countries (Red Zone)</h4>
                    <div class="sg-blocked-zone" id="sg-blocked-list">
                        <?php if (empty($blocked_countries)): ?>
                            <div class="sg-empty-state" id="sg-blocked-empty">
                                Click on a country to block it
                            </div>
                        <?php endif; ?>

                        <?php foreach ($blocked_countries as $code):
                            if (!isset($countries[$code]))
                                continue;
                            $country = $countries[$code];
                            ?>
                            <div class="sg-country-tag" data-code="<?php echo esc_attr($code); ?>">
                                <span class="sg-country-flag">
                                    <?php echo esc_html($country['flag']); ?>
                                </span>
                                <span class="sg-country-name">
                                    <?php echo esc_html($country['name']); ?>
                                </span>
                                <span class="sg-country-remove" title="Remove">×</span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    <!-- Hidden inputs for form submission -->
                    <div id="sg-blocked-inputs">
                        <?php foreach ($blocked_countries as $code): ?>
                            <input type="hidden" name="spectrus_shield_settings[geo_blocked_countries][]"
                                value="<?php echo esc_attr($code); ?>">
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Additional Settings -->
    <div class="sg-card">
        <div class="sg-card-header">
            <h3>⚙️ Advanced Geo Settings</h3>
        </div>
        <div class="sg-card-body">
            <table class="form-table sg-form-table">
                <tr>
                    <th scope="row">
                        <label for="sg-block-tor">Block Tor Exit Nodes</label>
                    </th>
                    <td>
                        <label class="sg-toggle">
                            <input type="checkbox" id="sg-block-tor" name="spectrus_shield_settings[geo_block_tor]"
                                value="1" <?php checked($block_tor); ?>>
                            <span class="sg-toggle-slider"></span>
                        </label>
                        <p class="description">
                            Block requests from known Tor exit nodes. Recommended for high-security sites.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="sg-geo-action">Block Action</label>
                    </th>
                    <td>
                        <select id="sg-geo-action" name="spectrus_shield_settings[geo_action]" class="sg-select">
                            <option value="403" <?php selected($geo_action, '403'); ?>>
                                Show 403 Forbidden
                            </option>
                            <option value="redirect" <?php selected($geo_action, 'redirect'); ?>>
                                Redirect to Homepage
                            </option>
                            <option value="custom" <?php selected($geo_action, 'custom'); ?>>
                                Show Custom Message
                            </option>
                        </select>
                    </td>
                </tr>
            </table>
        </div>
    </div>
</div>

<style>
    /* Geo Settings Styles */
    .sg-status-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
        gap: 15px;
        margin-bottom: 20px;
    }

    .sg-status-item {
        display: flex;
        flex-direction: column;
        gap: 5px;
    }

    .sg-status-label {
        font-size: 12px;
        color: #94a3b8;
        text-transform: uppercase;
    }

    .sg-status-value {
        font-size: 14px;
        color: #e2e8f0;
    }

    .sg-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }

    .sg-badge-success {
        background: rgba(34, 197, 94, 0.2);
        color: #22c55e;
    }

    .sg-badge-warning {
        background: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
    }

    .sg-license-setup {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.3);
        border-radius: 8px;
        padding: 20px;
        margin-top: 15px;
    }

    .sg-license-setup h4 {
        margin: 0 0 10px 0;
        color: #e2e8f0;
    }

    .sg-license-form {
        display: flex;
        gap: 10px;
        margin-top: 15px;
        flex-wrap: wrap;
    }

    .sg-update-actions {
        display: flex;
        gap: 10px;
        margin-top: 15px;
    }

    .sg-geo-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
    }

    @media (max-width: 900px) {
        .sg-geo-grid {
            grid-template-columns: 1fr;
        }
    }

    .sg-geo-panel {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    .sg-geo-panel h4 {
        margin: 0;
        color: #e2e8f0;
    }

    .sg-search-input {
        margin-bottom: 10px;
    }

    .sg-country-list {
        height: 350px;
        overflow-y: auto;
        border: 1px solid #334155;
        background: #1e293b;
        border-radius: 8px;
        padding: 5px;
    }

    .sg-country-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px;
        cursor: pointer;
        border-radius: 6px;
        transition: all 0.2s ease;
    }

    .sg-country-item:hover {
        background: #3b82f6;
        color: white;
    }

    .sg-country-flag {
        font-size: 20px;
    }

    .sg-country-name {
        flex: 1;
    }

    .sg-country-code {
        font-size: 11px;
        color: #64748b;
        font-family: monospace;
    }

    .sg-country-item:hover .sg-country-code {
        color: rgba(255, 255, 255, 0.7);
    }

    .sg-blocked-zone {
        min-height: 350px;
        border: 2px dashed #ef4444;
        background: rgba(239, 68, 68, 0.05);
        border-radius: 8px;
        padding: 15px;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-content: flex-start;
    }

    .sg-empty-state {
        width: 100%;
        text-align: center;
        color: #64748b;
        padding: 50px 20px;
    }

    .sg-country-tag {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        color: white;
        padding: 8px 12px;
        border-radius: 20px;
        font-size: 13px;
        animation: slideIn 0.2s ease;
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: scale(0.8);
        }

        to {
            opacity: 1;
            transform: scale(1);
        }
    }

    .sg-country-tag .sg-country-flag {
        font-size: 16px;
    }

    .sg-country-remove {
        cursor: pointer;
        opacity: 0.7;
        font-size: 18px;
        font-weight: bold;
        margin-left: 5px;
        transition: opacity 0.2s;
    }

    .sg-country-remove:hover {
        opacity: 1;
    }

    .sg-stat-big {
        text-align: center;
        padding: 20px;
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%);
        border-radius: 12px;
        margin-bottom: 20px;
    }

    .sg-stat-number {
        font-size: 48px;
        font-weight: 700;
        color: #ef4444;
        display: block;
    }

    .sg-stat-label {
        color: #94a3b8;
        font-size: 14px;
    }

    .sg-country-stats {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    .sg-country-stats li {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px;
        border-bottom: 1px solid #334155;
    }

    .sg-country-stats li:last-child {
        border-bottom: none;
    }

    .sg-country-stats .sg-country-name {
        flex: 1;
    }

    .sg-country-stats .sg-country-count {
        background: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }

    /* Form table styling for dark mode */
    .sg-form-table th,
    .sg-form-table td {
        color: #e2e8f0;
    }

    .sg-form-table th label {
        color: #f1f5f9;
        font-weight: 600;
    }

    .sg-form-table .description {
        color: #94a3b8 !important;
    }

    .sg-form-table tr {
        border-bottom: 1px solid #334155;
    }

    .sg-form-table tr:last-child {
        border-bottom: none;
    }

    /* Select styling */
    .sg-select {
        background: #1e293b;
        border: 1px solid #475569;
        color: #e2e8f0;
        padding: 8px 12px;
        border-radius: 6px;
        min-width: 200px;
    }

    .sg-select option {
        background: #1e293b;
        color: #e2e8f0;
    }

    /* Card header styling for dark mode */
    .sg-card-header h3 {
        color: #f1f5f9;
        margin: 0 0 8px 0;
    }

    .sg-card-header p {
        color: #94a3b8;
        margin: 0;
    }

    /* Progress bar styles */
    .sg-progress-container {
        margin-top: 15px;
        padding: 15px;
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.3);
        border-radius: 8px;
    }

    .sg-progress-bar {
        height: 8px;
        background: #1e293b;
        border-radius: 4px;
        overflow: hidden;
        margin-bottom: 10px;
    }

    .sg-progress-fill {
        height: 100%;
        width: 0%;
        background: linear-gradient(90deg, #3b82f6, #60a5fa);
        border-radius: 4px;
        transition: width 0.3s ease;
        animation: progressPulse 1.5s ease-in-out infinite;
    }

    @keyframes progressPulse {

        0%,
        100% {
            opacity: 1;
        }

        50% {
            opacity: 0.7;
        }
    }

    .sg-progress-status {
        font-size: 13px;
        color: #94a3b8;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .sg-progress-status::before {
        content: '';
        width: 8px;
        height: 8px;
        background: #3b82f6;
        border-radius: 50%;
        animation: statusBlink 1s ease-in-out infinite;
    }

    @keyframes statusBlink {

        0%,
        100% {
            opacity: 1;
        }

        50% {
            opacity: 0.3;
        }
    }

    /* Notice styles */
    .sg-notice {
        margin-top: 15px;
        padding: 12px 16px;
        border-radius: 8px;
        font-size: 14px;
    }

    .sg-notice-success {
        background: rgba(34, 197, 94, 0.15);
        border: 1px solid rgba(34, 197, 94, 0.3);
        color: #22c55e;
    }

    .sg-notice-error {
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.3);
        color: #ef4444;
    }

    /* Tab styles */
    .sg-setup-tabs {
        display: flex;
        gap: 0;
        margin: 15px 0;
        border-bottom: 2px solid #334155;
    }

    .sg-tab-btn {
        padding: 10px 20px;
        background: transparent;
        border: none;
        color: #94a3b8;
        font-size: 14px;
        cursor: pointer;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
        transition: all 0.2s;
    }

    .sg-tab-btn:hover {
        color: #e2e8f0;
    }

    .sg-tab-btn.active {
        color: #3b82f6;
        border-bottom-color: #3b82f6;
    }

    .sg-tab-content {
        display: none;
        padding: 15px 0;
    }

    .sg-tab-content.active {
        display: block;
    }

    /* Manual upload styles */
    .sg-manual-instructions {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.2);
        border-radius: 8px;
        padding: 15px;
    }

    .sg-manual-instructions p {
        margin: 0 0 10px 0;
        color: #e2e8f0;
    }

    .sg-manual-instructions ol {
        margin: 0 0 15px 20px;
        padding: 0;
        color: #94a3b8;
    }

    .sg-manual-instructions li {
        margin-bottom: 8px;
    }

    .sg-manual-instructions code {
        background: #1e293b;
        padding: 2px 6px;
        border-radius: 4px;
        color: #60a5fa;
        font-size: 13px;
    }

    .sg-upload-form {
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
    }

    .sg-file-input {
        padding: 8px;
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 6px;
        color: #e2e8f0;
        cursor: pointer;
    }

    .sg-file-input::file-selector-button {
        background: #334155;
        border: none;
        padding: 6px 12px;
        border-radius: 4px;
        color: #e2e8f0;
        cursor: pointer;
        margin-right: 10px;
    }
</style>


<script>
    jQuery(document).ready(function ($) {
        // Alias SpectrusGuard to sgAdmin for compatibility
        var sgAdmin = window.SpectrusGuard || {};
        console.log('SG: Initialized with nonce:', sgAdmin.nonce);
        // Tab switching
        $('.sg-tab-btn').on('click', function () {
            var tab = $(this).data('tab');

            // Update tab buttons
            $('.sg-tab-btn').removeClass('active');
            $(this).addClass('active');

            // Update tab content
            $('.sg-tab-content').removeClass('active');
            $('#sg-tab-' + tab).addClass('active');
        });

        // Manual MMDB upload
        $('#sg-upload-mmdb').on('click', function () {
            var fileInput = $('#sg-mmdb-file')[0];
            var $status = $('#sg-upload-status');

            if (!fileInput.files || !fileInput.files[0]) {
                $status
                    .removeClass('sg-notice-success')
                    .addClass('sg-notice-error')
                    .html('❌ Please select a .mmdb file first.')
                    .show();
                return;
            }

            var file = fileInput.files[0];

            // Validate file extension
            if (!file.name.endsWith('.mmdb')) {
                $status
                    .removeClass('sg-notice-success')
                    .addClass('sg-notice-error')
                    .html('❌ Invalid file type. Please select a .mmdb file.')
                    .show();
                return;
            }

            // Create FormData
            var formData = new FormData();
            formData.append('action', 'sg_upload_mmdb');
            formData.append('mmdb_file', file);
            formData.append('_ajax_nonce', sgAdmin.nonce);

            $status
                .removeClass('sg-notice-error sg-notice-success')
                .html('📤 Uploading file...')
                .show();

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                success: function (response) {
                    if (response.success) {
                        $status
                            .removeClass('sg-notice-error')
                            .addClass('sg-notice-success')
                            .html('✅ ' + response.data.message + ' Reloading...')
                            .show();
                        setTimeout(function () {
                            location.reload();
                        }, 1500);
                    } else {
                        $status
                            .removeClass('sg-notice-success')
                            .addClass('sg-notice-error')
                            .html('❌ ' + (response.data || 'Upload failed'))
                            .show();
                    }
                },
                error: function () {
                    $status
                        .removeClass('sg-notice-success')
                        .addClass('sg-notice-error')
                        .html('❌ Network error. Please try again.')
                        .show();
                }
            });
        });

        // Country search filter
        $('#sg-country-search').on('input', function () {
            var search = $(this).val().toLowerCase();
            $('#sg-available-list .sg-country-item').each(function () {
                var name = $(this).find('.sg-country-name').text().toLowerCase();
                var code = $(this).data('code').toLowerCase();
                $(this).toggle(name.indexOf(search) > -1 || code.indexOf(search) > -1);
            });
        });

        // Add country to blocked list
        $('#sg-available-list').on('click', '.sg-country-item', function () {
            var $item = $(this);
            var code = $item.data('code');
            var flag = $item.find('.sg-country-flag').text();
            var name = $item.find('.sg-country-name').text();

            // Hide empty state
            $('#sg-blocked-empty').hide();

            // Add to blocked zone
            var $tag = $('<div class="sg-country-tag" data-code="' + code + '">' +
                '<span class="sg-country-flag">' + flag + '</span>' +
                '<span class="sg-country-name">' + name + '</span>' +
                '<span class="sg-country-remove" title="Remove">×</span>' +
                '</div>');

            $('#sg-blocked-list').append($tag);

            // Add hidden input
            $('#sg-blocked-inputs').append(
                '<input type="hidden" name="spectrus_shield_settings[geo_blocked_countries][]" value="' + code + '">'
            );

            // Remove from available list
            $item.slideUp(200, function () {
                $(this).remove();
            });
        });

        // Remove country from blocked list
        $('#sg-blocked-list').on('click', '.sg-country-remove', function () {
            var $tag = $(this).closest('.sg-country-tag');
            var code = $tag.data('code');

            // Remove hidden input
            $('#sg-blocked-inputs input[value="' + code + '"]').remove();

            // Get country data to add back
            var flag = $tag.find('.sg-country-flag').text();
            var name = $tag.find('.sg-country-name').text();

            // Remove tag
            $tag.remove();

            // Check if list is empty
            if ($('#sg-blocked-list .sg-country-tag').length === 0) {
                $('#sg-blocked-empty').show();
            }

            // Add back to available list (in alphabetical order)
            var $newItem = $('<div class="sg-country-item" data-code="' + code + '">' +
                '<span class="sg-country-flag">' + flag + '</span>' +
                '<span class="sg-country-name">' + name + '</span>' +
                '<span class="sg-country-code">' + code + '</span>' +
                '</div>').hide();

            var inserted = false;
            $('#sg-available-list .sg-country-item').each(function () {
                if ($(this).find('.sg-country-name').text() > name) {
                    $newItem.insertBefore($(this));
                    inserted = true;
                    return false;
                }
            });

            if (!inserted) {
                $('#sg-available-list').append($newItem);
            }

            $newItem.slideDown(200);
        });

        // Download database with progress tracking
        $('#sg-download-db').on('click', function () {
            var $btn = $(this);
            var license = $('#sg-maxmind-license').val().trim();

            if (!license) {
                $('#sg-db-download-status')
                    .removeClass('sg-notice-success')
                    .addClass('sg-notice-error')
                    .html('Please enter your MaxMind license key.')
                    .show();
                return;
            }

            // Hide any previous status
            $('#sg-db-download-status').hide();

            // Show progress container
            $('#sg-download-progress').show();

            var progressInterval;
            var downloadComplete = false;

            function updateProgress(percent, message) {
                $('#sg-progress-fill').css('width', percent + '%');
                $('#sg-progress-status').text(message);
            }

            // Poll for real progress from server
            var noProgressCount = 0;
            var lastProgress = 0;
            var waitingMessages = [
                'Waiting to start...',
                'Validating license key...',
                'Connecting to MaxMind...',
                'Downloading database (~5MB)...',
                'Please wait, this may take 1-2 minutes...',
                'Still downloading, please be patient...'
            ];

            function pollProgress() {
                if (downloadComplete) return;

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'sg_get_download_progress',
                        _ajax_nonce: sgAdmin.nonce
                    },
                    success: function (response) {
                        if (downloadComplete) return;

                        if (response.success) {
                            var data = response.data;

                            // If status is 'waiting' or progress hasn't changed, show animated message
                            if (data.status === 'waiting' || data.progress === lastProgress) {
                                noProgressCount++;
                                var msgIndex = Math.min(noProgressCount, waitingMessages.length - 1);
                                var animProgress = Math.min(noProgressCount * 8, 50); // Slowly animate to 50%
                                updateProgress(animProgress, waitingMessages[msgIndex]);
                            } else {
                                // Real progress from server
                                noProgressCount = 0;
                                lastProgress = data.progress;
                                updateProgress(data.progress, data.message);
                            }

                            // Check if download errored
                            if (data.status === 'error' && data.error) {
                                downloadComplete = true;
                                clearInterval(progressInterval);
                                $('#sg-download-progress').hide();
                                $('#sg-db-download-status')
                                    .removeClass('sg-notice-success')
                                    .addClass('sg-notice-error')
                                    .html('❌ ' + data.message + (data.error ? ': ' + data.error : ''))
                                    .show();
                            }
                        }
                    },
                    error: function (xhr, status, error) {
                        // Silent fail on progress polling, main request will handle errors
                    }
                });
            }

            // Start polling every 2 seconds
            updateProgress(5, 'Starting download...');
            progressInterval = setInterval(pollProgress, 2000);

            $btn.find('.sg-btn-text').hide();
            $btn.find('.sg-btn-loading').show();
            $btn.prop('disabled', true);

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                timeout: 180000, // 3 minute timeout for large downloads
                data: {
                    action: 'sg_download_geoip_db',
                    license_key: license,
                    _ajax_nonce: sgAdmin.nonce
                },
                success: function (response) {
                    downloadComplete = true;
                    clearInterval(progressInterval);

                    if (response.success) {
                        updateProgress(100, 'Installation complete!');

                        setTimeout(function () {
                            $('#sg-download-progress').hide();
                            $('#sg-db-download-status')
                                .removeClass('sg-notice-error')
                                .addClass('sg-notice-success')
                                .html('✓ ' + (response.data.message || 'Database downloaded successfully!') +
                                    (response.data.size ? ' (' + response.data.size + ')' : '') +
                                    ' Reloading page...')
                                .show();

                            setTimeout(function () {
                                location.reload();
                            }, 1500);
                        }, 500);
                    } else {
                        $('#sg-download-progress').hide();
                        $('#sg-db-download-status')
                            .removeClass('sg-notice-success')
                            .addClass('sg-notice-error')
                            .html('❌ Error: ' + (response.data || 'Unknown error. Please check your license key and try again.'))
                            .show();
                    }
                },
                error: function (xhr, status, error) {
                    downloadComplete = true;
                    clearInterval(progressInterval);
                    $('#sg-download-progress').hide();

                    var errorMsg = 'Network error. ';
                    if (status === 'timeout') {
                        errorMsg = 'Request timed out. Try using Manual Upload instead. The database file is available at MaxMind.com.';
                    } else if (xhr.status === 0) {
                        errorMsg = 'Connection failed. Please check your internet connection or use Manual Upload.';
                    } else if (xhr.status === 500) {
                        errorMsg = 'Server error. Please check PHP error logs or use Manual Upload.';
                    } else {
                        errorMsg += 'Status: ' + status + '. Try Manual Upload if the issue persists.';
                    }

                    $('#sg-db-download-status')
                        .removeClass('sg-notice-success')
                        .addClass('sg-notice-error')
                        .html('❌ ' + errorMsg)
                        .show();
                },
                complete: function () {
                    $btn.find('.sg-btn-text').show();
                    $btn.find('.sg-btn-loading').hide();
                    $btn.prop('disabled', false);
                }
            });
        });

        // Update database
        $('#sg-update-db').on('click', function () {
            var $btn = $(this);
            $btn.prop('disabled', true).text('Updating...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'sg_update_geoip_db',
                    _ajax_nonce: sgAdmin.nonce
                },
                success: function (response) {
                    if (response.success) {
                        alert('Database updated successfully!');
                        location.reload();
                    } else {
                        alert('Error: ' + (response.data || 'Unknown error'));
                    }
                },
                complete: function () {
                    $btn.prop('disabled', false).text('🔄 Update GeoIP Database');
                }
            });
        });

        // Update Tor nodes
        $('#sg-update-tor').on('click', function () {
            var $btn = $(this);
            $btn.prop('disabled', true).text('Updating...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'sg_update_tor_nodes',
                    _ajax_nonce: sgAdmin.nonce
                },
                success: function (response) {
                    if (response.success) {
                        alert('Tor nodes list updated! ' + response.data.count + ' nodes loaded.');
                        location.reload();
                    } else {
                        alert('Error: ' + (response.data || 'Unknown error'));
                    }
                },
                complete: function () {
                    $btn.prop('disabled', false).text('🧅 Update Tor Nodes List');
                }
            });
        });
    });
</script>