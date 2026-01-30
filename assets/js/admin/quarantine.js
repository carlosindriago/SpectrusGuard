/**
 * SpectrusGuard Quarantine Module
 *
 * Handles quarantined files management including listing,
 * restoring, and permanently deleting files.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

(function ($) {
    'use strict';

    // Only run on quarantine page
    if (!$('#sg-refresh-quarantine').length) {
        return;
    }

    var Quarantine = {
        /**
         * Initialize quarantine module
         */
        init: function () {
            this.bindEvents();
            this.loadQuarantine();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function () {
            var self = this;

            // Refresh button
            $('#sg-refresh-quarantine').on('click', function () {
                self.loadQuarantine();
            });

            // Restore button
            $(document).on('click', '.sg-btn-restore', function () {
                self.restoreFile($(this));
            });

            // Delete permanently button
            $(document).on('click', '.sg-btn-delete-perm', function () {
                self.deleteFile($(this));
            });
        },

        /**
         * Load quarantined files
         */
        loadQuarantine: function () {
            var self = this;

            // Show loading
            $('#sg-quarantine-loading').show();
            $('#sg-quarantine-empty').hide();
            $('#sg-quarantine-list').hide();

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_list_quarantine',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    $('#sg-quarantine-loading').hide();

                    if (response.success && response.data.files && response.data.files.length > 0) {
                        self.renderFileList(response.data.files);
                    } else {
                        self.showEmptyState();
                    }
                },
                error: function () {
                    $('#sg-quarantine-loading').hide();
                    self.showEmptyState();
                    SpectrusGuardAdmin.showNotice('error', 'Failed to load quarantine list.');
                }
            });
        },

        /**
         * Render file list table
         */
        renderFileList: function (files) {
            var $tbody = $('#sg-quarantine-table-body');
            $tbody.empty();

            $.each(files, function (index, file) {
                var $row = $('<tr>').attr('data-index', index);

                $row.append(
                    $('<td>').html('<span style="font-size: 24px;">🔒</span>')
                );

                $row.append(
                    $('<td>').html(
                        '<span style="font-family: \'Monaco\', \'Consolas\', monospace; font-size: 13px; color: var(--sg-text-primary); font-weight: 600;">' +
                        $('<div/>').text(file.original_name).html() +
                        '</span>'
                    )
                );

                $row.append(
                    $('<td>').html(
                        '<span style="color: var(--sg-text-secondary); font-size: 14px;">' +
                        file.date +
                        '</span>'
                    )
                );

                $row.append(
                    $('<td>').html(
                        '<span style="color: var(--sg-text-muted); font-size: 13px;">' +
                        file.size +
                        '</span>'
                    )
                );

                var $actions = $('<td>').html(
                    '<button type="button" class="sg-btn sg-btn-restore sg-btn-sm" ' +
                    'data-file="' + $('<div/>').text(file.quarantine_name).html() + '" ' +
                    'data-original="' + $('<div/>').text(file.original_name).html() + '" ' +
                    'style="margin-right: 8px; background: rgba(102, 126, 234, 0.15); border: 1px solid rgba(102, 126, 234, 0.4); color: #667eea;">' +
                    '<span class="dashicons dashicons-undo"></span> Restore' +
                    '</button>' +
                    '<button type="button" class="sg-btn sg-btn-delete-perm sg-btn-sm" ' +
                    'data-file="' + $('<div/>').text(file.quarantine_name).html() + '" ' +
                    'style="background: rgba(233, 69, 96, 0.15); border: 1px solid rgba(233, 69, 96, 0.4); color: #e94560;">' +
                    '<span class="dashicons dashicons-trash"></span> Delete' +
                    '</button>'
                );

                $row.append($actions);
                $tbody.append($row);
            });

            $('#sg-quarantine-list').show();
        },

        /**
         * Show empty state
         */
        showEmptyState: function () {
            $('#sg-quarantine-empty').show();
            $('#sg-quarantine-list').hide();
        },

        /**
         * Restore file from quarantine
         */
        restoreFile: function ($btn) {
            var self = this;
            var fileName = $btn.data('file');
            var originalName = $btn.data('original');

            if (!confirm('Restore this file to its original location?\n\nFile: ' + originalName + '\n\nThis will move the file back from quarantine.')) {
                return;
            }

            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_restore_quarantine',
                    nonce: SpectrusGuard.nonce,
                    quarantine_name: fileName
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $btn.closest('tr').fadeOut(300, function () {
                            $(this).remove();
                            if ($('#sg-quarantine-table-body tr').length === 0) {
                                self.showEmptyState();
                            }
                        });
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message);
                        $btn.prop('disabled', false);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', 'Failed to restore file.');
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Delete file permanently
         */
        deleteFile: function ($btn) {
            var self = this;
            var fileName = $btn.data('file');
            var originalName = $btn.data('original');

            if (!confirm('PERMANENTLY DELETE this file?\n\nFile: ' + originalName + '\n\n⚠️ WARNING: This action cannot be undone! The file will be permanently deleted from quarantine.')) {
                return;
            }

            if (!confirm('Are you REALLY sure? This will permanently delete:\n\n' + originalName)) {
                return;
            }

            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_delete_quarantine',
                    nonce: SpectrusGuard.nonce,
                    quarantine_name: fileName
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $btn.closest('tr').fadeOut(300, function () {
                            $(this).remove();
                            if ($('#sg-quarantine-table-body tr').length === 0) {
                                self.showEmptyState();
                            }
                        });
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message);
                        $btn.prop('disabled', false);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', 'Failed to delete file.');
                    $btn.prop('disabled', false);
                }
            });
        }
    };

    // Initialize when DOM is ready
    $(document).ready(function () {
        Quarantine.init();
    });

    // Expose to global scope
    window.SpectrusGuardQuarantine = Quarantine;

})(jQuery);
