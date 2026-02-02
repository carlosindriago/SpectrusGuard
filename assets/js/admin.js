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
                    // Added role and aria-label for accessibility
                    $container = $('<div class="sg-toast-container" role="region" aria-label="Notifications"></div>');
                    $('body').append($container);
                }

                // Icons map
                var icons = {
                    'success': '✅',
                    'error': '🚨',
                    'warning': '⚠️',
                    'info': 'ℹ️'
                };

                var icon = icons[type] || icons.info;

                // Custom styles for Error type (Red background, Bold white text)
                var containerStyle = 'color: #ffffff;';
                var messageStyle = 'color: #ffffff; font-weight: 500;';

                if (type === 'error') {
                    containerStyle += ' background: #e94560; border-left-color: #ffffff;';
                    messageStyle = 'color: #ffffff; font-weight: 700; font-size: 15px;';
                }

                // Accessibility attributes: dynamic role and aria-live based on severity
                var role = (type === 'error' || type === 'warning') ? 'alert' : 'status';
                var ariaLive = (type === 'error' || type === 'warning') ? 'assertive' : 'polite';

                var $toast = $(
                    '<div class="sg-toast ' + type + '" role="' + role + '" aria-live="' + ariaLive + '" style="' + containerStyle + '">' +
                    // Added aria-hidden to decorative icon
                    '<div class="sg-toast-icon" aria-hidden="true">' + icon + '</div>' +
                    '<div class="sg-toast-content">' +
                    '<div class="sg-toast-message" style="' + messageStyle + '">' + message + '</div>' + // Explicit styles
                    '</div>' +
                    // Added aria-label to close button
                    '<button type="button" class="sg-toast-close" aria-label="Close notification" style="color: rgba(255,255,255,0.8);">&times;</button>' +
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
