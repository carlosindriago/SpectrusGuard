/**
 * SpectrusGuard Whitelist Module
 *
 * Handles whitelisted files management including listing
 * and removing files from whitelist.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

(function ($) {
    'use strict';

    // Only run on whitelist page
    if (!$('#sg-refresh-whitelist').length) {
        return;
    }

    var Whitelist = {
        /**
         * Initialize whitelist module
         */
        init: function () {
            this.bindEvents();
            this.loadWhitelist();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function () {
            var self = this;

            // Refresh button
            $('#sg-refresh-whitelist').on('click', function () {
                self.loadWhitelist();
            });

            // Remove from whitelist button
            $(document).on('click', '.sg-btn-remove-whitelist', function () {
                self.removeWhitelist($(this));
            });
        },

        /**
         * Load whitelisted files
         */
        loadWhitelist: function () {
            var self = this;

            // Show loading
            $('#sg-whitelist-loading').show();
            $('#sg-whitelist-empty').hide();
            $('#sg-whitelist-list').hide();

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_list_whitelist',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    $('#sg-whitelist-loading').hide();

                    if (response.success && response.data.files && response.data.files.length > 0) {
                        self.renderFileList(response.data.files);
                    } else {
                        self.showEmptyState();
                    }
                },
                error: function () {
                    $('#sg-whitelist-loading').hide();
                    self.showEmptyState();
                    SpectrusGuardAdmin.showNotice('error', 'Failed to load whitelist.');
                }
            });
        },

        /**
         * Render file list table
         */
        renderFileList: function (files) {
            var $tbody = $('#sg-whitelist-table-body');
            $tbody.empty();

            $.each(files, function (index, file) {
                var $row = $('<tr>').attr('data-id', file.id);

                $row.append(
                    $('<td>').html('<span style="font-size: 24px;">✓</span>')
                );

                // File path - truncate if too long
                var displayPath = file.file_path.length > 80 ?
                    file.file_path.substring(0, 40) + '...' + file.file_path.substring(file.file_path.length - 37) :
                    file.file_path;

                $row.append(
                    $('<td>').html(
                        '<div style="font-family: \'Monaco\', \'Consolas\', monospace; font-size: 12px; color: var(--sg-text-primary); word-break: break-all;" title="' +
                        $('<div/>').text(file.file_path).html() + '">' +
                        $('<div/>').text(displayPath).html() +
                        '</div>'
                    )
                );

                // Hash - show first 16 and last 16 chars
                var shortHash = file.file_hash.substring(0, 16) + '...' + file.file_hash.substring(file.file_hash.length - 16);

                $row.append(
                    $('<td>').html(
                        '<span style="font-family: \'Monaco\', \'Consolas\', monospace; font-size: 11px; color: var(--sg-text-muted);" title="' +
                        $('<div/>').text(file.file_hash).html() + '">' +
                        $('<div/>').text(shortHash).html() +
                        '</span>'
                    )
                );

                // User
                $row.append(
                    $('<td>').html(
                        '<span style="color: var(--sg-text-secondary); font-size: 13px;">User #' + file.whitelisted_by + '</span>'
                    )
                );

                // Date
                var dateStr = new Date(file.whitelisted_at.replace(/-/g, '/')).toLocaleDateString() + ' ' +
                             new Date(file.whitelisted_at.replace(/-/g, '/')).toLocaleTimeString().substring(0, 5);

                $row.append(
                    $('<td>').html(
                        '<span style="color: var(--sg-text-secondary); font-size: 13px;">' + dateStr + '</span>'
                    )
                );

                // Actions
                var $actions = $('<td>').html(
                    '<button type="button" class="sg-btn sg-btn-remove-whitelist sg-btn-sm" ' +
                    'data-id="' + file.id + '" ' +
                    'data-file="' + $('<div/>').text(file.file_path).html() + '" ' +
                    'style="background: rgba(233, 69, 96, 0.15); border: 1px solid rgba(233, 69, 96, 0.4); color: #e94560;">' +
                    '<span class="dashicons dashicons-no"></span> Remove' +
                    '</button>'
                );

                $row.append($actions);
                $tbody.append($row);

                // Notes row (if notes exist)
                if (file.notes) {
                    var $notesRow = $('<tr>').attr('data-notes-for', file.id);
                    $notesRow.append('<td colspan="6" style="padding: 8px 16px; background: rgba(102, 126, 234, 0.05); border-top: none;">' +
                        '<span style="color: var(--sg-text-muted); font-size: 12px;"><strong>Notes:</strong> ' +
                        $('<div/>').text(file.notes).html() +
                        '</span></td>');
                    $tbody.append($notesRow);
                }
            });

            $('#sg-whitelist-list').show();
        },

        /**
         * Show empty state
         */
        showEmptyState: function () {
            $('#sg-whitelist-empty').show();
            $('#sg-whitelist-list').hide();
        },

        /**
         * Remove file from whitelist
         */
        removeWhitelist: function ($btn) {
            var self = this;
            var whitelistId = $btn.data('id');
            var fileName = $btn.data('file');

            // Truncate filename for display
            var displayName = fileName.length > 60 ?
                fileName.substring(0, 30) + '...' + fileName.substring(fileName.length - 27) :
                fileName;

            if (!confirm('Remove from whitelist?\n\nFile: ' + displayName + '\n\nThis file will be scanned again in future scans.')) {
                return;
            }

            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_remove_whitelist',
                    nonce: SpectrusGuard.nonce,
                    whitelist_id: whitelistId
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $btn.closest('tr').fadeOut(300, function () {
                            // Also remove notes row if exists
                            var notesRow = $('[data-notes-for="' + whitelistId + '"]');
                            if (notesRow.length) {
                                notesRow.remove();
                            }

                            $(this).remove();

                            if ($('#sg-whitelist-table-body tr:not([data-notes-for])').length === 0) {
                                self.showEmptyState();
                            }
                        });
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message);
                        $btn.prop('disabled', false);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', 'Failed to remove from whitelist.');
                    $btn.prop('disabled', false);
                }
            });
        }
    };

    // Initialize when DOM is ready
    $(document).ready(function () {
        Whitelist.init();
    });

    // Expose to global scope
    window.SpectrusGuardWhitelist = Whitelist;

})(jQuery);
