/**
 * SpectrusGuard Onboarding Wizard JavaScript
 *
 * Handles wizard navigation, preset selection, and form submission.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

(function($) {
    'use strict';

    // State
    let currentStep = 1;
    let selectedPreset = null;

    // DOM elements
    const $steps = $('.sg-wizard-step');
    const $progressFill = $('#progress-fill');
    const $progressSteps = $('.sg-step');
    const $skipModal = $('#skip-modal');
    const $loadingOverlay = $('#loading-overlay');
    const $settingsList = $('#settings-list');
    const $customSettings = $('#custom-settings');

    /**
     * Initialize wizard
     */
    function init() {
        bindEvents();
    }

    /**
     * Bind all event handlers
     */
    function bindEvents() {
        // Step 1 - Start button
        $('#btn-start').on('click', function() {
            goToStep(2);
        });

        // Step 2 - Preset selection
        $('.sg-preset-card').on('click', function() {
            selectPreset($(this));
        });

        // Step 2 - Back button
        $('#btn-back-1').on('click', function() {
            goToStep(1);
        });

        // Step 2 - Next button
        $('#btn-next-2').on('click', function() {
            if (selectedPreset) {
                prepareStep3();
                goToStep(3);
            }
        });

        // Step 3 - Back button
        $('#btn-back-2').on('click', function() {
            goToStep(2);
        });

        // Step 3 - Finish button
        $('#btn-finish').on('click', function() {
            saveOnboarding();
        });

        // Skip wizard link
        $('#btn-skip-wizard').on('click', function(e) {
            e.preventDefault();
            $skipModal.fadeIn(200);
        });

        // Skip modal - Close on backdrop click
        $('.sg-modal-backdrop').on('click', function() {
            $skipModal.fadeOut(200);
        });

        // Skip modal - Continue setup
        $('#btn-continue-setup').on('click', function() {
            $skipModal.fadeOut(200);
        });

        // Skip modal - Remind later
        $('#btn-remind-later').on('click', function() {
            skipWizard(true);
        });

        // Skip modal - Skip anyway
        $('#btn-skip-anyway').on('click', function() {
            skipWizard(false);
        });
    }

    /**
     * Navigate to a specific step
     */
    function goToStep(step) {
        currentStep = step;

        // Update steps visibility
        $steps.removeClass('active');
        $('#step-' + step).addClass('active');

        // Update progress bar
        const progress = (step / 3) * 100;
        $progressFill.css('width', progress + '%');

        // Update progress step indicators
        $progressSteps.each(function() {
            const stepNum = $(this).data('step');
            $(this).removeClass('active completed');
            if (stepNum < step) {
                $(this).addClass('completed');
            } else if (stepNum === step) {
                $(this).addClass('active');
            }
        });

        // Scroll to top
        $('html, body').scrollTop(0);
    }

    /**
     * Select a preset
     */
    function selectPreset($card) {
        // Remove selection from all cards
        $('.sg-preset-card').removeClass('selected');
        
        // Select this card
        $card.addClass('selected');
        selectedPreset = $card.data('preset');

        // Enable next button
        $('#btn-next-2').prop('disabled', false);
    }

    /**
     * Prepare step 3 based on selected preset
     */
    function prepareStep3() {
        if (selectedPreset === 'custom') {
            // Show custom settings toggles
            $settingsList.hide();
            $customSettings.show();
            $('#step3-title').text(sgOnboarding.strings.customTitle || 'Choose Your Settings');
        } else {
            // Show preset summary
            $customSettings.hide();
            $settingsList.show().empty();
            $('#step3-title').text(sgOnboarding.strings.recommendedTitle || 'Recommended Settings');

            const preset = sgOnboarding.presets[selectedPreset];
            if (preset && preset.settings) {
                const settingsInfo = getSettingsInfo();
                
                for (const key in preset.settings) {
                    if (preset.settings[key] && settingsInfo[key]) {
                        const info = settingsInfo[key];
                        $settingsList.append(`
                            <div class="sg-setting-item">
                                <span class="sg-setting-icon">${info.icon}</span>
                                <div class="sg-setting-info">
                                    <h4>${info.name}</h4>
                                    <p>${info.description}</p>
                                </div>
                            </div>
                        `);
                    }
                }
            }
        }
    }

    /**
     * Get information about each setting
     */
    function getSettingsInfo() {
        return {
            'waf_enabled': {
                icon: '🔥',
                name: 'Web Application Firewall',
                description: 'Blocks SQL injection, XSS, and malicious attacks'
            },
            'login_limit_enabled': {
                icon: '🔐',
                name: 'Login Protection',
                description: 'Limits failed login attempts to prevent brute force'
            },
            'hide_wp_version': {
                icon: '🙈',
                name: 'Hide WordPress Version',
                description: 'Removes version info that hackers exploit'
            },
            'disable_xmlrpc': {
                icon: '🚫',
                name: 'Disable XML-RPC',
                description: 'Blocks a common attack vector for brute force'
            },
            'enable_2fa_admins': {
                icon: '📱',
                name: 'Two-Factor Authentication',
                description: 'Require a code from your phone to log in'
            },
            'file_monitor_enabled': {
                icon: '👁️',
                name: 'File Monitoring',
                description: 'Alerts when core files are modified'
            },
            'security_headers_enabled': {
                icon: '📋',
                name: 'Security Headers',
                description: 'HTTP headers that protect against attacks'
            },
            'rate_limiting_enabled': {
                icon: '⏱️',
                name: 'Rate Limiting',
                description: 'Prevents request flooding and DDoS'
            },
            'auto_scan_enabled': {
                icon: '🔍',
                name: 'Automatic Scanning',
                description: 'Daily malware scans for your site'
            },
            'custom_login_url': {
                icon: '🔗',
                name: 'Custom Login URL',
                description: 'Hides wp-login.php from attackers'
            }
        };
    }

    /**
     * Save onboarding settings
     */
    function saveOnboarding() {
        $loadingOverlay.fadeIn(200);

        let data = {
            action: 'sg_save_onboarding',
            nonce: sgOnboarding.nonce
        };

        if (selectedPreset === 'custom') {
            // Collect custom settings
            data.settings = {};
            $customSettings.find('.sg-toggle-input').each(function() {
                const name = $(this).attr('name').replace('settings[', '').replace(']', '');
                data.settings[name] = $(this).is(':checked') ? '1' : '0';
            });
        } else {
            data.preset = selectedPreset;
        }

        $.post(sgOnboarding.ajaxUrl, data)
            .done(function(response) {
                if (response.success) {
                    // Redirect to dashboard
                    window.location.href = response.data.redirect || sgOnboarding.dashboardUrl;
                } else {
                    alert(response.data.message || sgOnboarding.strings.error);
                    $loadingOverlay.fadeOut(200);
                }
            })
            .fail(function() {
                alert(sgOnboarding.strings.error);
                $loadingOverlay.fadeOut(200);
            });
    }

    /**
     * Skip the wizard
     */
    function skipWizard(remindLater) {
        $skipModal.fadeOut(200);
        $loadingOverlay.fadeIn(200);

        $.post(sgOnboarding.ajaxUrl, {
            action: 'sg_skip_onboarding',
            nonce: sgOnboarding.nonce,
            remind_later: remindLater ? 'true' : 'false'
        })
        .done(function(response) {
            if (response.success) {
                window.location.href = response.data.redirect || sgOnboarding.dashboardUrl;
            }
        })
        .fail(function() {
            $loadingOverlay.fadeOut(200);
        });
    }

    // Initialize on DOM ready
    $(document).ready(init);

})(jQuery);
