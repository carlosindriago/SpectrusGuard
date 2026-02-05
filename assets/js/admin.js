/**
 * SpectrusGuard Admin JavaScript
 *
 * Dashboard interactions and AJAX functionality.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

(function ($) {
    'use strict';

    /**
     * SpectrusGuard Admin Module
     */
    var SpectrusGuardAdmin = {

        /**
         * Initialize
         */
        init: function () {
            this.bindEvents();
            this.initTooltips();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function () {
            // Copy button functionality
            $(document).on('click', '.sg-copy-btn', this.handleCopy);

            // Whitelist IP button
            $('#sg-whitelist-my-ip').on('click', this.handleWhitelistIP);

            // Clear logs button
            $('#sg-clear-logs').on('click', this.handleClearLogs);

            // Refresh logs button
            $('#sg-refresh-logs').on('click', function () {
                location.reload();
            });

            // Toggle sections
            $(document).on('click', '.sg-toggle-section', this.handleToggleSection);

            // Quick Actions (Dashboard Alerts)
            $(document).on('click', '.sg-quick-action-btn', this.handleQuickAction);

            // Auto-detect API plugins button
            $('#sg-auto-detect-plugins').on('click', this.handleAutoDetectPlugins);

            // Add routes to whitelist when clicking plugin chip
            $(document).on('click', '.sg-plugin-chip-add', this.handleAddPluginRoutes);
        },

        /**
         * Initialize tooltips
         */
        initTooltips: function () {
            if (typeof $.fn.tooltip === 'function') {
                $('[data-tooltip]').tooltip();
            }
        },

        /**
         * Handle copy to clipboard
         */
        handleCopy: function (e) {
            e.preventDefault();

            var $btn = $(this);
            var textToCopy = $btn.data('copy');
            var originalText = $btn.text();

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(textToCopy).then(function () {
                    $btn.text(SpectrusGuard.i18n.copied || 'Copied!');
                    setTimeout(function () {
                        $btn.text(originalText);
                    }, 2000);
                });
            } else {
                // Fallback for older browsers
                var $temp = $('<textarea>');
                $('body').append($temp);
                $temp.val(textToCopy).select();
                document.execCommand('copy');
                $temp.remove();

                $btn.text(SpectrusGuard.i18n.copied || 'Copied!');
                setTimeout(function () {
                    $btn.text(originalText);
                }, 2000);
            }
        },

        /**
         * Handle whitelist current IP
         */
        handleWhitelistIP: function (e) {
            e.preventDefault();

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_whitelist_ip',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message || SpectrusGuard.i18n.error);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', SpectrusGuard.i18n.error);
                },
                complete: function () {
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Handle clear logs
         */
        handleClearLogs: function (e) {
            e.preventDefault();

            if (!confirm(SpectrusGuard.i18n.confirm_clear || 'Are you sure you want to clear all logs?')) {
                return;
            }

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_clear_logs',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        setTimeout(function () {
                            location.reload();
                        }, 1000);
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message || SpectrusGuard.i18n.error);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', SpectrusGuard.i18n.error);
                },
                complete: function () {
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Handle section toggle
         */
        handleToggleSection: function (e) {
            e.preventDefault();

            var $section = $(this).closest('.sg-settings-section');
            $section.find('.sg-section-content').slideToggle(200);
            $(this).toggleClass('active');
        },

        /**
         * Handle Quick Actions (Dashboard Alerts)
         */
        handleQuickAction: function (e) {
            e.preventDefault();

            var $btn = $(this);
            var $alert = $btn.closest('.sg-alert');
            var action = $btn.data('action');
            var nonce = $btn.data('nonce');
            var originalText = $btn.text();

            if ($btn.prop('disabled')) return;

            // Loading state
            $btn.prop('disabled', true).text('Processing...');

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_quick_action',
                    security_action: action,
                    nonce: nonce
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $btn.text('Done!');

                        // Remove alert with animation
                        setTimeout(function () {
                            $alert.slideUp(400, function () {
                                $(this).remove();
                                // If no more alerts, remove wrapper
                                if ($('.sg-alert').length === 0) {
                                    $('.sg-alerts-wrapper').slideUp();
                                }
                            });
                        }, 500);
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message || SpectrusGuard.i18n.error);
                        $btn.prop('disabled', false).text(originalText);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', SpectrusGuard.i18n.error);
                    $btn.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Show admin notice (Toast style)
         */
        showNotice: function (type, message) {
            try {
                console.log('SpectrusGuard showNotice:', type, message);

                // Default messages if empty
                if (!message) {
                    if (type === 'success') {
                        message = 'Operation successful';
                    } else if (type === 'error') {
                        message = 'An error occurred';
                    } else {
                        message = 'Notification';
                    }
                }

                // Ensure container exists
                var $container = $('.sg-toast-container');
                if ($container.length === 0) {
                    $container = $('<div class="sg-toast-container"></div>');
                    $('body').append($container);
                }

                // Icons map
                var icons = {
                    'success': '✅',
                    'error': '🚨',
                    'warning': '⚠️',
                    'info': 'ℹ️'
                };

                // Custom styles for Error type (Red background, Bold white text)
                var containerStyle = 'color: #ffffff;';
                var messageStyle = 'color: #ffffff; font-weight: 500;';

                if (type === 'error') {
                    containerStyle += ' background: #e94560; border-left-color: #ffffff;';
                    messageStyle = 'color: #ffffff; font-weight: 700; font-size: 15px;';
                }

                var $toast = $(
                    '<div class="sg-toast ' + type + '" style="' + containerStyle + '">' +
                    '<div class="sg-toast-icon">' + icons[type] + '</div>' +
                    '<div class="sg-toast-content">' +
                    '<div class="sg-toast-message" style="' + messageStyle + '">' + message + '</div>' + // Explicit styles
                    '</div>' +
                    '<button type="button" class="sg-toast-close" style="color: rgba(255,255,255,0.8);">&times;</button>' +
                    '</div>'
                );

                // Append to container
                $container.append($toast);

                // Trigger animation
                requestAnimationFrame(function () {
                    $toast.addClass('show');
                });

                // Helper to dismiss (hoisted or defined here)
                var dismissToast = function ($t) {
                    $t.removeClass('show');
                    setTimeout(function () {
                        $t.remove();
                    }, 300); // Wait for transition
                };

                // Auto dismiss
                // longer duration for errors
                var duration = (type === 'error' || type === 'warning') ? 10000 : 5000;

                var dismissTimeout = setTimeout(function () {
                    dismissToast($toast);
                }, duration);

                // Click to dismiss
                $toast.on('click', function () {
                    clearTimeout(dismissTimeout);
                    dismissToast($toast);
                });

            } catch (e) {
                console.error('SpectrusGuard Toast Error:', e);
                // Fallback
                alert(message || 'Notification');
            }
        },

        /**
         * Format number with commas
         */
        formatNumber: function (num) {
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        /**
         * Debounce function
         */
        debounce: function (func, wait) {
            var timeout;
            return function () {
                var context = this, args = arguments;
                clearTimeout(timeout);
                timeout = setTimeout(function () {
                    func.apply(context, args);
                }, wait);
            };
        },

        /**
         * Handle auto-detect API plugins
         */
        handleAutoDetectPlugins: function (e) {
            e.preventDefault();

            var $btn = $(this);
            var originalText = $btn.text();
            $btn.prop('disabled', true).text('🔄 Detecting...');

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_get_detected_api_plugins',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    if (response.success && response.data) {
                        var plugins = response.data.plugins || {};
                        var $container = $('#sg-detected-plugins');
                        var $chips = $('#sg-plugin-chips');

                        $chips.empty();

                        // Build chips for each detected plugin
                        $.each(plugins, function (key, plugin) {
                            var isCore = plugin.core || false;
                            var chipClass = isCore ? 'sg-chip sg-chip-core' : 'sg-chip sg-chip-plugin';
                            var routes = plugin.routes.join(', ');

                            var $chip = $(
                                '<span class="' + chipClass + '" style="display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 20px; font-size: 13px; ' +
                                (isCore ? 'background: rgba(59, 130, 246, 0.15); color: var(--sg-primary);' : 'background: rgba(16, 185, 129, 0.15); color: #10b981;') +
                                '">' +
                                '<span>' + plugin.name + '</span>' +
                                (isCore ? '' : '<button type="button" class="sg-plugin-chip-add" data-routes="' + routes + '" ' +
                                    'style="background: none; border: none; cursor: pointer; padding: 2px 6px; margin: -2px -6px -2px 0; color: inherit; opacity: 0.7;" ' +
                                    'title="Add to whitelist">➕</button>') +
                                '</span>'
                            );

                            $chips.append($chip);
                        });

                        $container.slideDown();
                        SpectrusGuardAdmin.showToast('success', 'Detected ' + Object.keys(plugins).length + ' plugins using REST API');
                    } else {
                        SpectrusGuardAdmin.showToast('error', response.data || 'Detection failed');
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showToast('error', 'Network error during detection');
                },
                complete: function () {
                    $btn.prop('disabled', false).text(originalText);
                }
            });
        },

        /**
         * Handle adding plugin routes to whitelist
         */
        handleAddPluginRoutes: function (e) {
            e.preventDefault();
            e.stopPropagation();

            var routes = $(this).data('routes');
            if (!routes) return;

            var $textarea = $('#sg-api-whitelist');
            var currentValue = $textarea.val().trim();
            var routeArray = routes.split(', ');
            var newRoutes = [];

            // Check for duplicates
            routeArray.forEach(function (route) {
                if (currentValue.indexOf(route) === -1) {
                    newRoutes.push(route);
                }
            });

            if (newRoutes.length > 0) {
                var separator = currentValue ? '\n' : '';
                $textarea.val(currentValue + separator + newRoutes.join('\n'));
                SpectrusGuardAdmin.showToast('success', 'Added ' + newRoutes.length + ' route(s) to whitelist');

                // Visual feedback on chip
                $(this).text('✓').prop('disabled', true);
            } else {
                SpectrusGuardAdmin.showToast('info', 'Routes already in whitelist');
            }
        }
    };

    /**
     * Document ready
     */
    $(document).ready(function () {
        SpectrusGuardAdmin.init();
    });

    // Expose to global scope for external access
    window.SpectrusGuardAdmin = SpectrusGuardAdmin;

})(jQuery);
