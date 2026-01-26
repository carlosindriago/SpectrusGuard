/**
 * GhostShield Admin JavaScript
 *
 * Dashboard interactions and AJAX functionality.
 *
 * @package GhostShield
 * @since   1.0.0
 */

(function ($) {
    'use strict';

    /**
     * GhostShield Admin Module
     */
    var GhostShieldAdmin = {

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
            $(document).on('click', '.gs-copy-btn', this.handleCopy);

            // Whitelist IP button
            $('#gs-whitelist-my-ip').on('click', this.handleWhitelistIP);

            // Clear logs button
            $('#gs-clear-logs').on('click', this.handleClearLogs);

            // Refresh logs button
            $('#gs-refresh-logs').on('click', function () {
                location.reload();
            });

            // Toggle sections
            $(document).on('click', '.gs-toggle-section', this.handleToggleSection);
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
                    $btn.text(GhostShield.i18n.copied || 'Copied!');
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

                $btn.text(GhostShield.i18n.copied || 'Copied!');
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
                url: GhostShield.ajax_url,
                type: 'POST',
                data: {
                    action: 'gs_whitelist_ip',
                    nonce: GhostShield.nonce
                },
                success: function (response) {
                    if (response.success) {
                        GhostShieldAdmin.showNotice('success', response.data.message);
                    } else {
                        GhostShieldAdmin.showNotice('error', response.data.message || GhostShield.i18n.error);
                    }
                },
                error: function () {
                    GhostShieldAdmin.showNotice('error', GhostShield.i18n.error);
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

            if (!confirm(GhostShield.i18n.confirm_clear || 'Are you sure you want to clear all logs?')) {
                return;
            }

            var $btn = $(this);
            $btn.prop('disabled', true);

            $.ajax({
                url: GhostShield.ajax_url,
                type: 'POST',
                data: {
                    action: 'gs_clear_logs',
                    nonce: GhostShield.nonce
                },
                success: function (response) {
                    if (response.success) {
                        GhostShieldAdmin.showNotice('success', response.data.message);
                        setTimeout(function () {
                            location.reload();
                        }, 1000);
                    } else {
                        GhostShieldAdmin.showNotice('error', response.data.message || GhostShield.i18n.error);
                    }
                },
                error: function () {
                    GhostShieldAdmin.showNotice('error', GhostShield.i18n.error);
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

            var $section = $(this).closest('.gs-settings-section');
            $section.find('.gs-section-content').slideToggle(200);
            $(this).toggleClass('active');
        },

        /**
         * Show admin notice
         */
        showNotice: function (type, message) {
            var $notice = $(
                '<div class="notice notice-' + type + ' is-dismissible gs-notice">' +
                '<p>' + message + '</p>' +
                '<button type="button" class="notice-dismiss">' +
                '<span class="screen-reader-text">Dismiss</span>' +
                '</button>' +
                '</div>'
            );

            // Remove existing notices
            $('.gs-notice').remove();

            // Insert at top of content
            $('.wrap h1').first().after($notice);

            // Auto dismiss after 5 seconds
            setTimeout(function () {
                $notice.fadeOut(300, function () {
                    $(this).remove();
                });
            }, 5000);

            // Dismiss button handler
            $notice.find('.notice-dismiss').on('click', function () {
                $notice.fadeOut(300, function () {
                    $(this).remove();
                });
            });
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
        GhostShieldAdmin.init();
    });

    // Expose to global scope for external access
    window.GhostShieldAdmin = GhostShieldAdmin;

})(jQuery);
