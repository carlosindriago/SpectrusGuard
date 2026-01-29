<?php
/**
 * View: Ghost Cloak Settings Wizard
 */

// Basic security check
if (!defined('ABSPATH'))
    die('Direct access forbidden.');

// Get current settings
$settings = get_option('spectrus_shield_settings', []);
$env_type = class_exists('Spectrus_Cloak_Engine') ? Spectrus_Cloak_Engine::detect_server_environment() : 'unknown';
$has_rules = class_exists('Spectrus_Cloak_Engine') ? Spectrus_Cloak_Engine::htaccess_has_rules() : false;
$rescue_key = $settings['rescue_key'] ?? substr(md5(uniqid()), 0, 10); // Fallback key if not set
$rescue_url = site_url("?ghost_rescue={$rescue_key}");

// Determine current step index for UI
$step = 1;
if ($env_type === 'apache' || $env_type === 'litespeed') {
    $step = $has_rules ? 3 : 2;
} elseif ($env_type === 'nginx') {
    $step = 2; // Manual step needed
}
// If enabled, we are effectively done/managing
if (!empty($settings['url_cloaking_enabled'])) {
    $step = 3;
}
?>

<style>
    /* Ghost Cloak Specific Styles */
    .sg-gc-wizard {
        max_width: 800px;
        margin: 0 auto;
    }

    .sg-gc-stepper {
        display: flex;
        justify-content: space-between;
        margin-bottom: 40px;
        position: relative;
        padding: 0 20px;
    }

    .sg-gc-stepper::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 20px;
        right: 20px;
        height: 2px;
        background: var(--sg-bg-hover);
        z-index: 0;
        transform: translateY(-50%);
    }

    .sg-gc-step {
        position: relative;
        z-index: 1;
        background: var(--sg-bg-app);
        padding: 0 10px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 8px;
        color: var(--sg-text-muted);
        transition: all 0.3s;
    }

    .sg-gc-step-circle {
        width: 32px;
        height: 32px;
        border-radius: 50%;
        background: var(--sg-bg-card);
        border: 2px solid var(--sg-border);
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 14px;
        transition: all 0.3s;
    }

    .sg-gc-step.active .sg-gc-step-circle {
        border-color: var(--sg-primary);
        background: var(--sg-primary);
        color: white;
        box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2);
    }

    .sg-gc-step.completed .sg-gc-step-circle {
        background: var(--sg-success);
        border-color: var(--sg-success);
        color: white;
    }

    .sg-gc-step-label {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
    }

    .sg-gc-step.active .sg-gc-step-label {
        color: var(--sg-text-primary);
    }

    .sg-gc-panel {
        background: var(--sg-bg-card);
        border: 1px solid var(--sg-border);
        border-radius: var(--sg-radius-lg);
        padding: 32px;
        margin-bottom: 24px;
        animation: sg-fade-in 0.4s ease-out;
    }

    .sg-gc-status-icon {
        font-size: 48px;
        margin-bottom: 16px;
        display: block;
    }

    .sg-server-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 8px 16px;
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.2);
        border-radius: 8px;
        color: var(--sg-text-primary);
        font-weight: 600;
        margin-bottom: 20px;
    }

    .sg-server-badge.apache {
        color: #fed7aa;
        border-color: #fdba74;
        background: rgba(253, 186, 116, 0.1);
    }

    .sg-server-badge.nginx {
        color: #86efac;
        border-color: #4ade80;
        background: rgba(74, 222, 128, 0.1);
    }

    .sg-server-badge.iis {
        color: #fca5a5;
        border-color: #f87171;
        background: rgba(248, 113, 113, 0.1);
    }

    .sg-code-box {
        background: #000;
        color: #a5f3fc;
        padding: 16px;
        border-radius: 8px;
        font-family: monospace;
        font-size: 13px;
        line-height: 1.5;
        overflow-x: auto;
        border: 1px solid var(--sg-border);
        margin: 16px 0;
        position: relative;
    }

    .sg-rescue-box {
        background: rgba(245, 158, 11, 0.05);
        /* Amber tint */
        border: 1px solid rgba(245, 158, 11, 0.3);
        border-radius: 8px;
        padding: 20px;
        display: flex;
        gap: 16px;
        margin-top: 24px;
    }

    .sg-rescue-icon {
        font-size: 24px;
        flex-shrink: 0;
    }

    @keyframes sg-fade-in {
        from {
            opacity: 0;
            transform: translateY(10px);
        }

        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    /* Toggle Switch Enhancement */
    .sg-switch-large {
        position: relative;
        display: inline-block;
        width: 60px;
        height: 34px;
        margin-right: 12px;
    }

    .sg-switch-large input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .sg-slider-large {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: var(--sg-bg-hover);
        transition: .4s;
        border-radius: 34px;
    }

    .sg-slider-large:before {
        position: absolute;
        content: "";
        height: 26px;
        width: 26px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        transition: .4s;
        border-radius: 50%;
    }

    input:checked+.sg-slider-large {
        background-color: var(--sg-success);
    }

    input:checked+.sg-slider-large:before {
        transform: translateX(26px);
    }
</style>

<div class="sg-gc-wizard">

    <!-- Hero Header -->
    <div style="text-align: center; margin-bottom: 40px;">
        <h2
            style="font-size: 28px; display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 8px;">
            👻 <?php esc_html_e('Ghost Cloak', 'spectrus-guard'); ?>
        </h2>
        <p style="color: var(--sg-text-secondary); font-size: 16px; margin: 0;">
            <?php esc_html_e('Hide your WordPress structure from hackers and bots.', 'spectrus-guard'); ?>
        </p>
    </div>

    <!-- Stepper Navigation -->
    <div class="sg-gc-stepper">
        <div class="sg-gc-step <?php echo $step >= 1 ? 'active' : ''; ?> <?php echo $step > 1 ? 'completed' : ''; ?>">
            <div class="sg-gc-step-circle">
                <?php echo $step > 1 ? '✓' : '1'; ?>
            </div>
            <div class="sg-gc-step-label"><?php esc_html_e('Environment', 'spectrus-guard'); ?></div>
        </div>
        <div class="sg-gc-step <?php echo $step >= 2 ? 'active' : ''; ?> <?php echo $step > 2 ? 'completed' : ''; ?>">
            <div class="sg-gc-step-circle">
                <?php echo $step > 2 ? '✓' : '2'; ?>
            </div>
            <div class="sg-gc-step-label"><?php esc_html_e('Rewrite Rules', 'spectrus-guard'); ?></div>
        </div>
        <div class="sg-gc-step <?php echo $step >= 3 ? 'active' : ''; ?>">
            <div class="sg-gc-step-circle">3</div>
            <div class="sg-gc-step-label"><?php esc_html_e('Activation', 'spectrus-guard'); ?></div>
        </div>
    </div>

    <!-- MAIN CONTENT AREA -->

    <!-- STEP 1 & 2: SERVER CHECK & RULES -->
    <div class="sg-gc-panel">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
                <h3 style="margin: 0 0 16px 0; font-size: 18px; color: var(--sg-text-primary);">
                    <?php esc_html_e('Server Detection', 'spectrus-guard'); ?>
                </h3>

                <?php if ($env_type === 'apache' || $env_type === 'litespeed'): ?>
                    <div class="sg-server-badge apache">
                        <span class="dashicons dashicons-yes"></span>
                        Apache / LiteSpeed Detected
                    </div>
                <?php elseif ($env_type === 'nginx'): ?>
                    <div class="sg-server-badge nginx">
                        <span class="dashicons dashicons-yes"></span>
                        Nginx Detected
                    </div>
                <?php else: ?>
                    <div class="sg-server-badge iis">
                        <span class="dashicons dashicons-warning"></span>
                        <?php echo ucfirst($env_type); ?> (<?php esc_html_e('Manual Setup Required', 'spectrus-guard'); ?>)
                    </div>
                <?php endif; ?>
            </div>
            <div style="font-size: 32px; opacity: 0.5;">🖥️</div>
        </div>

        <!-- Rule Application Logic -->
        <?php if ($env_type === 'apache' || $env_type === 'litespeed'): ?>
            <p style="color: var(--sg-text-secondary); margin-bottom: 24px;">
                <?php esc_html_e('Great! We can automatically write the necessary rewrite rules to your .htaccess file.', 'spectrus-guard'); ?>
            </p>

            <?php if ($has_rules): ?>
                <div
                    style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); padding: 12px; border-radius: 6px; color: var(--sg-success); display: flex; align-items: center; gap: 8px;">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <strong><?php esc_html_e('Rules are successfully applied.', 'spectrus-guard'); ?></strong>
                </div>
            <?php else: ?>
                <button type="button" id="sg-write-rules" class="sg-btn sg-btn-primary">
                    <span class="dashicons dashicons-edit"></span>
                    <?php esc_html_e('Write Rules to .htaccess', 'spectrus-guard'); ?>
                </button>
            <?php endif; ?>

        <?php elseif ($env_type === 'nginx'): ?>
            <p style="color: var(--sg-text-secondary);">
                <?php esc_html_e('For Nginx, you need to add these rules to your server block configuration manually.', 'spectrus-guard'); ?>
            </p>
            <div class="sg-code-box">
                <?php echo esc_html(Spectrus_Cloak_Engine::generate_nginx_rules()); ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- STEP 3: ACTIVATION -->
    <div class="sg-gc-panel" style="<?php echo ($step < 2) ? 'opacity: 0.5; pointer-events: none;' : ''; ?>">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;">
            <div>
                <h3 style="margin: 0 0 8px 0; font-size: 18px; color: var(--sg-text-primary);">
                    <?php esc_html_e('Enable Cloaking', 'spectrus-guard'); ?>
                </h3>
                <p style="color: var(--sg-text-secondary); margin: 0;">
                    <?php esc_html_e('Activate the cloak to hide paths on the frontend.', 'spectrus-guard'); ?>
                </p>
            </div>

            <label class="sg-switch-large">
                <input type="hidden" name="spectrus_shield_settings[form_context]" value="cloak">
                <input type="checkbox" name="spectrus_shield_settings[url_cloaking_enabled]" value="1" <?php checked($settings['url_cloaking_enabled'] ?? false); ?>>
                <span class="sg-slider-large"></span>
            </label>
        </div>

        <!-- Emergency Rescue Box -->
        <div class="sg-rescue-box">
            <div class="sg-rescue-icon">⛑️</div>
            <div style="flex: 1;">
                <h4 style="margin: 0 0 8px 0; color: var(--sg-warning); font-size: 14px; text-transform: uppercase;">
                    <?php esc_html_e('Emergency Rescue Link', 'spectrus-guard'); ?>
                </h4>
                <p style="color: var(--sg-text-secondary); font-size: 13px; margin: 0 0 12px 0;">
                    <?php esc_html_e('Save this URL! If cloaking breaks your site styles, use this link to regain access. For security, you will be asked to verify your identity via Admin Email or 2FA Code before the site is unlocked.', 'spectrus-guard'); ?>
                </p>
                <div style="display: flex; gap: 8px;">
                    <input type="text" readonly value="<?php echo esc_url($rescue_url); ?>"
                        style="flex: 1; background: rgba(0,0,0,0.2); border: 1px solid rgba(245, 158, 11, 0.3); color: var(--sg-text-primary); padding: 8px 12px; border-radius: 4px; font-family: monospace;"
                        onclick="this.select();">
                    <a href="<?php echo esc_url($rescue_url); ?>" target="_blank" class="sg-btn"
                        style="background: rgba(245, 158, 11, 0.1); color: var(--sg-warning); border: 1px solid rgba(245, 158, 11, 0.2);">
                        <?php esc_html_e('Test Link', 'spectrus-guard'); ?>
                    </a>
                </div>
            </div>
        </div>
    </div>



    <!-- NEW: Plugin Masking Studio (Visible in Step 3) -->
    <div class="sg-gc-panel" style="<?php echo ($step < 2) ? 'opacity: 0.5; pointer-events: none;' : ''; ?>">
        <h3 style="margin: 0 0 16px 0; font-size: 18px; color: var(--sg-text-primary);">
            🎭 <?php esc_html_e('Plugin Masking Studio', 'spectrus-guard'); ?>
        </h3>
        <p style="color: var(--sg-text-secondary); margin-bottom: 20px;">
            <?php esc_html_e('Assign fake names to your plugins to confuse scanners.', 'spectrus-guard'); ?>
        </p>

        <style>
            .sg-table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 16px;
            }

            .sg-table th,
            .sg-table td {
                text-align: left;
                padding: 12px;
                border-bottom: 1px solid var(--sg-border);
            }

            .sg-table th {
                color: var(--sg-text-muted);
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
            }

            .sg-table input[type="text"] {
                width: 100%;
                background: var(--sg-bg-app);
                border: 1px solid var(--sg-border);
                color: var(--sg-text-primary);
                padding: 8px;
                border-radius: 4px;
            }

            .sg-input-group {
                display: flex;
                gap: 8px;
            }

            .sg-btn-icon {
                background: transparent;
                border: 1px solid var(--sg-border);
                color: var(--sg-text-secondary);
                cursor: pointer;
                padding: 8px;
                border-radius: 4px;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .sg-btn-icon:hover {
                background: var(--sg-bg-hover);
                color: var(--sg-text-primary);
            }

            .sg-notice.warning {
                background: rgba(245, 158, 11, 0.1);
                border-left: 4px solid var(--sg-warning);
                padding: 12px;
                margin-top: 20px;
                color: var(--sg-text-primary);
            }
        </style>

        <table class="sg-table" id="sg-mapping-table">
            <thead>
                <tr>
                    <th><?php esc_html_e('Real Name (Folder)', 'spectrus-guard'); ?></th>
                    <th><?php esc_html_e('Mask Name (Public)', 'spectrus-guard'); ?></th>
                    <th style="width: 50px;"><?php esc_html_e('Action', 'spectrus-guard'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php
                $mappings = get_option('sg_cloak_plugin_map', []);
                if (empty($mappings)) {
                    // Default example
                    $mappings = ['woocommerce' => 'shop-core'];
                }
                foreach ($mappings as $real => $fake):
                    ?>
                    <tr>
                        <td><input type="text" name="sg_map_real[]" value="<?php echo esc_attr($real); ?>"
                                placeholder="e.g. elementor"></td>
                        <td>
                            <div class="sg-input-group">
                                <input type="text" name="sg_map_fake[]" value="<?php echo esc_attr($fake); ?>"
                                    placeholder="e.g. ui-builder">
                                <button type="button" class="sg-btn-icon sg-randomize" title="Generate Random">🎲</button>
                            </div>
                        </td>
                        <td><button type="button" class="sg-btn-icon sg-remove-row">❌</button></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <button type="button" class="sg-btn sg-btn-secondary" id="sg-add-mapping"
            style="background: var(--sg-bg-app); border: 1px solid var(--sg-border); color: var(--sg-text-primary); margin-top: 8px;">
            + <?php esc_html_e('Add Mapping', 'spectrus-guard'); ?>
        </button>

        <div class="sg-notice warning">
            <p style="margin: 0; font-size: 13px;">
                ⚠️ <strong><?php esc_html_e('Important:', 'spectrus-guard'); ?></strong>
                <?php esc_html_e('After saving changes, you must update your server rules (Apache/Nginx) for the new paths to work.', 'spectrus-guard'); ?>
            </p>
        </div>
    </div>

</div>

<script>
    jQuery(document).ready(function ($) {
        // Handle AJAX Rule Writing
        $('#sg-write-rules').on('click', function () {
            var $btn = $(this);
            var originalText = $btn.html();

            $btn.addClass('disabled').prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> Writing...');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'sg_write_htaccess',
                    nonce: SpectrusGuard.nonce
                },
                success: function (res) {
                    if (res.success) {
                        $btn.removeClass('sg-btn-primary').addClass('sg-btn-success').html('<span class="dashicons dashicons-yes"></span> Applied!');
                        setTimeout(function () {
                            location.reload();
                        }, 1000);
                    } else {
                        alert('Error: ' + (res.data || 'Unknown error'));
                        $btn.removeClass('disabled').prop('disabled', false).html(originalText);
                    }
                },
                error: function () {
                    alert('Server error occurred.');
                    $btn.removeClass('disabled').prop('disabled', false).html(originalText);
                }
            });
        });

        // --- Plugin Masking Studio Logic ---

        // Add Row
        $('#sg-add-mapping').on('click', function () {
            var row = '<tr>' +
                '<td><input type="text" name="sg_map_real[]" placeholder="e.g. elementor"></td>' +
                '<td><div class="sg-input-group"><input type="text" name="sg_map_fake[]" placeholder="e.g. ui-builder"><button type="button" class="sg-btn-icon sg-randomize" title="Generate Random">🎲</button></div></td>' +
                '<td><button type="button" class="sg-btn-icon sg-remove-row">❌</button></td>' +
                '</tr>';
            $('#sg-mapping-table tbody').append(row);
        });

        // Remove Row
        $(document).on('click', '.sg-remove-row', function () {
            // Allows removing even the last row if user wants empty
            $(this).closest('tr').remove();
        });

        // Randomize
        $(document).on('click', '.sg-randomize', function () {
            var fakes = ['core-sys', 'app-data', 'ui-kit', 'auth-module', 'xyz-lib', 'content-hub', 'media-grid', 'form-engine', 'seo-pro', 'site-core'];
            var random = fakes[Math.floor(Math.random() * fakes.length)];
            // Optionally add number to ensure uniqueness
            // random += '-' + Math.floor(Math.random() * 100);
            $(this).closest('td').find('input').val(random);
        });
    });
</script>