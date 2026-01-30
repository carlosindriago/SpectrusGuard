/**
 * SpectrusGuard Scanner Module
 *
 * Handles all scanner-specific JavaScript functionality including
 * running scans, displaying results, and managing threats.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

(function ($) {
    'use strict';

    var Scanner = {
        /**
         * Module state
         */
        lastMessage: '',
        pollingInterval: null,
        isScanning: false,

        /**
         * Initialize scanner module
         */
        init: function () {
            this.bindEvents();
            this.initPolling();
        },

        /**
         * Bind event handlers
         */
        bindEvents: function () {
            var self = this;

            // Run scan button
            $('#sg-run-scan').on('click', function () {
                self.runScan();
            });

            // Delete threat button
            $(document).on('click', '.sg-btn-delete', function () {
                self.deleteThreat($(this));
            });

            // Quarantine threat button
            $(document).on('click', '.sg-btn-quarantine', function () {
                self.quarantineThreat($(this));
            });
        },

        /**
         * Run security scan
         */
        runScan: function () {
            var self = this;
            var $btn = $('#sg-run-scan');
            var originalText = $btn.html();

            // Prevent multiple simultaneous scans
            if (this.isScanning) {
                return;
            }

            this.isScanning = true;
            $btn.prop('disabled', true).addClass('loading').data('original-text', originalText);

            // Clear log and reset state
            $('#sg-activity-log').empty();
            this.lastMessage = '';

            // Hide results, show progress
            $('.sg-threat-intel-grid').not('#sg-scan-progress').fadeOut();
            $('#sg-scan-progress').fadeIn();

            // Start polling for progress
            this.startPolling();

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_run_scan',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    // Stop polling
                    self.stopPolling();
                    self.isScanning = false;

                    if (response.success) {
                        // Show completion
                        self.updateProgress({
                            percentage: 100,
                            message: SpectrusGuard.i18n.scan_complete || 'Scan Complete!'
                        });

                        // Show results in the progress panel
                        setTimeout(function () {
                            self.showResults(response.data.results);
                        }, 500);
                    } else {
                        self.showError(response.data.message || SpectrusGuard.i18n.scan_failed || 'Scan failed');
                        $btn.prop('disabled', false).removeClass('loading').html(originalText);
                    }
                },
                error: function () {
                    self.stopPolling();
                    self.isScanning = false;
                    self.showError(SpectrusGuard.i18n.scan_error || 'An error occurred during scan.');
                    $btn.prop('disabled', false).removeClass('loading').html(originalText);
                }
            });
        },

        /**
         * Show scan progress panel
         */
        showProgress: function () {
            $('#sg-scan-progress').fadeIn();
            $('#sg-activity-log').empty();
            this.lastMessage = '';
        },

        /**
         * Show scan results
         */
        showResults: function (results) {
            var $progressPanel = $('#sg-scan-progress');

            // Check if clean
            if (!results.has_results || !results.issues || results.issues.length === 0) {
                this.showCleanResults();
                return;
            }

            // Group issues by category
            var grouped = {};
            $.each(results.issues, function (i, issue) {
                if (!grouped[issue.category]) {
                    grouped[issue.category] = [];
                }
                grouped[issue.category].push(issue);
            });

            // Build results HTML
            var html = this.buildResultsHTML(results, grouped);

            // Update panel content
            $progressPanel.find('.sg-spinner-ring').parent().fadeOut();
            $('#sg-activity-log').fadeOut();
            $progressPanel.append('<div id="sg-results-content" style="display: none;">' + html + '</div>');
            $('#sg-results-content').fadeIn();

            // Bind continue button
            $('#sg-continue-btn').on('click', function () {
                location.reload();
            });
        },

        /**
         * Build results HTML
         */
        buildResultsHTML: function (results, grouped) {
            var self = this;

            // Header
            var html = '<div style="text-align: center; padding: 40px 0; margin-bottom: 40px;">' +
                '<div style="font-size: 72px; margin-bottom: 20px;">🚨</div>' +
                '<h2 style="margin: 0 0 12px 0; font-size: 32px; font-weight: 700; color: var(--sg-text-primary);">' +
                (SpectrusGuard.i18n.security_issues_found || 'Security Issues Found') + '</h2>' +
                '<p style="color: #e94560; font-size: 18px; font-weight: 600; margin: 0;">' +
                (SpectrusGuard.i18n.we_found_issues || 'We found') + ' <strong style="font-size: 24px;">' +
                results.summary.total_issues + '</strong> ' +
                (SpectrusGuard.i18n.potential_security_issues || 'potential security issues') + '</p>' +
                '</div>';

            // Show summary badges
            html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 20px; margin-bottom: 40px;">';

            if (results.summary.critical > 0) {
                html += this.buildSeverityBadge('critical', results.summary.critical, '🚨', '#e94560');
            }
            if (results.summary.high > 0) {
                html += this.buildSeverityBadge('high', results.summary.high, '🔥', '#ff8e53');
            }
            if (results.summary.medium > 0) {
                html += this.buildSeverityBadge('medium', results.summary.medium, '⚠️', '#ffc107');
            }
            if (results.summary.low > 0) {
                html += this.buildSeverityBadge('low', results.summary.low, 'ℹ️', '#6c757d');
            }

            html += '</div>';

            // Show threats by category
            html += '<div style="background: var(--sg-bg-dark); border: 1px solid var(--sg-border); border-radius: 16px; padding: 32px; margin-bottom: 32px;">';
            html += '<h3 style="margin: 0 0 28px 0; font-size: 22px; font-weight: 700; color: var(--sg-text-primary);">' +
                (SpectrusGuard.i18n.what_threats_mean || 'What These Threats Mean') + '</h3>';

            var categoryOrder = ['malware', 'uploads', 'core', 'suspicious'];
            $.each(categoryOrder, function (i, cat) {
                if (grouped[cat] && grouped[cat].length > 0) {
                    var explanation = self.getThreatExplanation(cat);
                    html += self.buildThreatExplanationCard(explanation, grouped[cat].length);
                }
            });

            html += '</div>';

            // Show file list
            html += '<div style="background: var(--sg-bg-dark); border: 1px solid var(--sg-border); border-radius: 16px; padding: 32px;">';
            html += '<h3 style="margin: 0 0 28px 0; font-size: 22px; font-weight: 700; color: var(--sg-text-primary);">' +
                (SpectrusGuard.i18n.affected_files || 'Affected Files') + '</h3>';
            html += '<div style="max-height: 500px; overflow-y: auto; padding-right: 12px; font-family: \'Monaco\', \'Consolas\', monospace; font-size: 14px; line-height: 1.6;">';

            $.each(results.issues, function (i, issue) {
                html += self.buildIssueCard(issue, i);
            });

            html += '</div></div>';

            // Continue button
            html += '<div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--sg-border);">' +
                '<button type="button" id="sg-continue-btn" class="sg-btn sg-btn-primary sg-btn-lg" style="padding: 18px 56px; font-size: 17px; font-weight: 700; border-radius: 10px;">' +
                (SpectrusGuard.i18n.continue || 'Continue') + ' →' +
                '</button>' +
                '</div>';

            return html;
        },

        /**
         * Build severity badge HTML
         */
        buildSeverityBadge: function (severity, count, icon, color) {
            return '<div style="background: linear-gradient(135deg, ' + color + '15, ' + color + '05); border: 2px solid ' + color + '40; border-radius: 12px; padding: 24px; text-align: center;">' +
                '<div style="font-size: 40px; margin-bottom: 12px; line-height: 1; display: flex; align-items: center; justify-content: center; height: 48px;">' + icon + '</div>' +
                '<div style="font-size: 36px; font-weight: 700; color: ' + color + '; line-height: 1; margin-bottom: 8px;">' + count + '</div>' +
                '<div style="color: ' + color + '; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">' +
                severity.charAt(0).toUpperCase() + severity.slice(1) + '</div>' +
                '</div>';
        },

        /**
         * Build threat explanation card HTML
         */
        buildThreatExplanationCard: function (explanation, count) {
            var html = '<div style="background: linear-gradient(135deg, rgba(102, 126, 234, 0.08), rgba(118, 75, 162, 0.08)); border: 1px solid rgba(102, 126, 234, 0.2); border-radius: 12px; padding: 28px; margin-bottom: 28px;">' +
                '<div style="display: flex; align-items: center; margin-bottom: 16px;">' +
                '<span style="font-size: 32px; margin-right: 16px; line-height: 1;">' + explanation.icon + '</span>' +
                '<div>' +
                '<div style="font-size: 18px; font-weight: 700; color: var(--sg-text-primary); margin-bottom: 4px;">' + explanation.title + '</div>' +
                '<div style="color: #667eea; font-weight: 600; font-size: 14px;">' + count + ' ' +
                (SpectrusGuard.i18n.threats_detected || 'threats detected') + '</div>' +
                '</div>' +
                '</div>' +
                '<p style="color: #cbd5e1; margin: 0 0 20px 0; line-height: 1.7; font-size: 15px;">' + explanation.description + '</p>' +
                '<div style="margin-top: 20px;">' +
                '<div style="font-size: 14px; font-weight: 700; color: var(--sg-text-primary); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.5px;">' +
                (SpectrusGuard.i18n.recommended_actions || 'Recommended Actions:') + '</div>' +
                '<ul style="margin: 0 0 0 28px; color: #cbd5e1; line-height: 1.8; font-size: 14px;">';

            $.each(explanation.actions, function (j, action) {
                html += '<li style="margin-bottom: 8px;">' + action + '</li>';
            });

            html += '</ul></div></div>';
            return html;
        },

        /**
         * Build issue card HTML
         */
        buildIssueCard: function (issue, index) {
            var severityColors = {
                'critical': '#e94560',
                'high': '#ff8e53',
                'medium': '#ffc107',
                'low': '#6c757d',
                'info': '#17a2b8'
            };
            var severityBgColors = {
                'critical': 'rgba(233, 69, 96, 0.15)',
                'high': 'rgba(255, 142, 83, 0.15)',
                'medium': 'rgba(255, 193, 7, 0.15)',
                'low': 'rgba(108, 117, 125, 0.15)',
                'info': 'rgba(23, 162, 184, 0.15)'
            };

            var color = severityColors[issue.severity] || '#6c757d';
            var bgColor = severityBgColors[issue.severity] || 'rgba(0, 0, 0, 0.2)';
            var canDelete = issue.category !== 'core'; // Core files should be restored, not deleted

            var html = '<div id="threat-' + index + '" ' +
                'style="padding: 20px; border-left: 4px solid ' + color + '; background: ' + bgColor + '; margin-bottom: 16px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.05);">' +
                '<div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">' +
                '<div style="flex: 1; margin-right: 20px; min-width: 0;">' +
                '<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">' +
                '<span style="color: #667eea; font-weight: 700; word-break: break-all; font-size: 14px; display: inline-block; max-width: 100%;">' +
                $('<div/>').text(issue.file).html() + '</span>' +
                '<span style="background: ' + color + '; color: #fff; padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; display: inline-flex; align-items: center; justify-content: center; line-height: 1; height: 24px;">' +
                issue.severity + '</span>' +
                '</div>' +
                '<div style="color: #cbd5e1; font-weight: 500; font-size: 14px; line-height: 1.5;">' +
                $('<div/>').text(issue.message).html() + '</div>' +
                '</div>' +
                '<div style="display: flex; gap: 12px; flex-shrink: 0;">';

            if (canDelete) {
                html += '<button type="button" class="sg-btn sg-btn-quarantine" ' +
                    'data-file="' + $('<div/>').text(issue.file).html() + '" ' +
                    'data-index="' + index + '" ' +
                    'style="background: rgba(255, 193, 7, 0.15); border: 1px solid rgba(255, 193, 7, 0.4); color: #ffc107; padding: 10px 20px; font-size: 13px; border-radius: 8px; font-weight: 600; transition: all 0.3s ease;">' +
                    '🔒 ' + (SpectrusGuard.i18n.quarantine || 'Quarantine') +
                    '</button>' +
                    '<button type="button" class="sg-btn sg-btn-delete" ' +
                    'data-file="' + $('<div/>').text(issue.file).html() + '" ' +
                    'data-index="' + index + '" ' +
                    'style="background: rgba(233, 69, 96, 0.15); border: 1px solid rgba(233, 69, 96, 0.4); color: #e94560; padding: 10px 20px; font-size: 13px; border-radius: 8px; font-weight: 600; transition: all 0.3s ease;">' +
                    '🗑️ ' + (SpectrusGuard.i18n.delete || 'Delete') +
                    '</button>';
            } else {
                html += '<button type="button" class="sg-btn" disabled ' +
                    'style="background: rgba(255,255, 255, 0.05); color: var(--sg-text-secondary); padding: 10px 20px; font-size: 13px; border-radius: 8px; opacity: 0.5; font-weight: 600;">' +
                    '⚠️ ' + (SpectrusGuard.i18n.restore_core || 'Restore from WordPress core') +
                    '</button>';
            }

            html += '</div></div></div>';
            return html;
        },

        /**
         * Show clean results
         */
        showCleanResults: function () {
            var $progressPanel = $('#sg-scan-progress');

            var html = '<div style="text-align: center; padding: 60px 40px;">' +
                '<div style="font-size: 96px; margin-bottom: 28px; line-height: 1;">✅</div>' +
                '<h2 style="margin: 0 0 20px 0; font-size: 36px; font-weight: 700; color: var(--sg-text-primary);">' +
                (SpectrusGuard.i18n.site_clean || 'Your Site is Clean!') + '</h2>' +
                '<p style="color: #667eea; font-size: 19px; line-height: 1.7; max-width: 600px; margin: 0 auto 40px auto; font-weight: 500;">' +
                (SpectrusGuard.i18n.clean_scan_message || 'Great news! The scan didn\'t detect any security issues. Your WordPress installation appears to be secure.') +
                '</p>' +
                '<div style="background: linear-gradient(135deg, rgba(102, 126, 234, 0.12), rgba(118, 75, 162, 0.12)); border: 2px solid rgba(102, 126, 234, 0.3); border-radius: 16px; padding: 32px; margin-bottom: 40px; text-align: left;">' +
                '<h3 style="margin: 0 0 24px 0; color: #667eea; font-size: 22px; font-weight: 700;">' +
                (SpectrusGuard.i18n.what_we_checked || 'What We Checked') + '</h3>' +
                '<ul style="margin: 0; padding-left: 32px; color: #cbd5e1; line-height: 2; font-size: 16px;">' +
                '<li style="margin-bottom: 8px;">✅ ' + (SpectrusGuard.i18n.check_core || 'WordPress core file integrity') + '</li>' +
                '<li style="margin-bottom: 8px;">✅ ' + (SpectrusGuard.i18n.check_uploads || 'PHP files in uploads directory') + '</li>' +
                '<li style="margin-bottom: 8px;">✅ ' + (SpectrusGuard.i18n.check_suspicious || 'Hidden and suspicious files') + '</li>' +
                '<li style="margin-bottom: 8px;">✅ ' + (SpectrusGuard.i18n.check_permissions || 'File permissions') + '</li>' +
                '<li style="margin-bottom: 0;">✅ ' + (SpectrusGuard.i18n.check_malware || 'Known malware signatures') + '</li>' +
                '</ul>' +
                '</div>' +
                '<button type="button" id="sg-continue-btn" class="sg-btn sg-btn-primary sg-btn-lg" style="padding: 20px 60px; font-size: 17px; font-weight: 700; border-radius: 12px;">' +
                (SpectrusGuard.i18n.return_scanner || 'Return to Scanner') +
                '</button>' +
                '</div>';

            // Update panel content
            $progressPanel.find('.sg-spinner-ring').parent().fadeOut();
            $('#sg-activity-log').fadeOut();
            $progressPanel.append('<div id="sg-results-content" style="display: none;">' + html + '</div>');
            $('#sg-results-content').fadeIn();

            // Bind continue button
            $('#sg-continue-btn').on('click', function () {
                location.reload();
            });
        },

        /**
         * Get threat explanation by category
         */
        getThreatExplanation: function (category) {
            // Default explanations (can be overridden via wp_localize_script)
            var explanations = {
                'core': {
                    title: SpectrusGuard.i18n.threat_core_title || 'WordPress Core Integrity',
                    icon: '⚙️',
                    description: SpectrusGuard.i18n.threat_core_desc || 'Modified or missing WordPress core files can indicate a compromised installation.',
                    actions: [
                        SpectrusGuard.i18n.threat_core_action1 || 'Restore the modified files from a clean WordPress installation',
                        SpectrusGuard.i18n.threat_core_action2 || 'Check your WordPress version and update if needed',
                        SpectrusGuard.i18n.threat_core_action3 || 'Review the file modifications to understand what was changed'
                    ]
                },
                'uploads': {
                    title: SpectrusGuard.i18n.threat_uploads_title || 'PHP Files in Uploads',
                    icon: '📁',
                    description: SpectrusGuard.i18n.threat_uploads_desc || 'PHP files in the uploads directory are almost always malicious.',
                    actions: [
                        SpectrusGuard.i18n.threat_uploads_action1 || 'Delete all PHP files from the uploads directory',
                        SpectrusGuard.i18n.threat_uploads_action2 || 'Review the file contents to understand what the backdoor does',
                        SpectrusGuard.i18n.threat_uploads_action3 || 'Check your access logs to see how the file was uploaded'
                    ]
                },
                'suspicious': {
                    title: SpectrusGuard.i18n.threat_suspicious_title || 'Suspicious Files',
                    icon: '🔍',
                    description: SpectrusGuard.i18n.threat_suspicious_desc || 'Hidden files or files with dangerous permissions may indicate malware activity.',
                    actions: [
                        SpectrusGuard.i18n.threat_suspicious_action1 || 'Review hidden files to determine if they are legitimate',
                        SpectrusGuard.i18n.threat_suspicious_action2 || 'Fix dangerous file permissions (should be 644 for files, 755 for directories)',
                        SpectrusGuard.i18n.threat_suspicious_action3 || 'Delete files you don\'t recognize'
                    ]
                },
                'malware': {
                    title: SpectrusGuard.i18n.threat_malware_title || 'Malware Detected',
                    icon: '🚨',
                    description: SpectrusGuard.i18n.threat_malware_desc || 'Malware signatures were detected in your files.',
                    actions: [
                        SpectrusGuard.i18n.threat_malware_action1 || 'Review the infected files and the malware patterns detected',
                        SpectrusGuard.i18n.threat_malware_action2 || 'Delete or clean the infected files immediately',
                        SpectrusGuard.i18n.threat_malware_action3 || 'Scan from a clean computer to detect malware on your local system',
                        SpectrusGuard.i18n.threat_malware_action4 || 'Change all passwords (WordPress, FTP, database, hosting)'
                    ]
                }
            };

            return explanations[category] || {
                title: category,
                icon: '⚠️',
                description: SpectrusGuard.i18n.threat_default_desc || 'Potential security issue detected.',
                actions: [SpectrusGuard.i18n.threat_default_action || 'Review the file and determine if it is legitimate']
            };
        },

        /**
         * Start polling for progress
         */
        startPolling: function () {
            var self = this;
            this.pollingInterval = setInterval(function () {
                self.pollProgress();
            }, 500);
        },

        /**
         * Stop polling
         */
        stopPolling: function () {
            if (this.pollingInterval) {
                clearInterval(this.pollingInterval);
                this.pollingInterval = null;
            }
        },

        /**
         * Poll for scan progress
         */
        pollProgress: function () {
            var self = this;

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_get_scan_progress',
                    nonce: SpectrusGuard.nonce
                },
                success: function (response) {
                    if (response.success && response.data && response.data.message) {
                        self.updateProgress(response.data);
                    }
                },
                error: function () {
                    // Continue polling even on error
                }
            });
        },

        /**
         * Update progress UI
         */
        updateProgress: function (data) {
            $('#sg-progress-bar').css('width', data.percentage + '%');
            $('#sg-progress-percent').text(data.percentage + '%');
            $('#sg-progress-label').text(data.message);
            this.addLogEntry(data.message);
        },

        /**
         * Add log entry
         */
        addLogEntry: function (message) {
            if (message === this.lastMessage) {
                return; // Don't duplicate messages
            }
            this.lastMessage = message;

            var timestamp = new Date().toLocaleTimeString();
            var $logEntry = $('<div class="sg-log-entry" style="margin-bottom: 8px; color: var(--sg-text-secondary);"></div>');
            $logEntry.html('<span style="color: #667eea;">●</span> <span style="color: #888;">[' + timestamp + ']</span> ' +
                $('<div/>').text(message).html());

            var $log = $('#sg-activity-log');
            $log.append($logEntry);
            $log.scrollTop($log[0].scrollHeight);
        },

        /**
         * Initialize polling on page load (for scan in progress)
         */
        initPolling: function () {
            // If scan is in progress, start polling
            if ($('#sg-scan-progress').is(':visible')) {
                this.startPolling();
            }
        },

        /**
         * Delete threat file
         */
        deleteThreat: function ($btn) {
            var self = this;
            var filePath = $btn.data('file');

            if (!confirm(SpectrusGuard.i18n.confirm_delete || 'Are you sure you want to delete this file?')) {
                return;
            }

            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_delete_threat',
                    nonce: SpectrusGuard.nonce,
                    file_path: filePath
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $('#threat-' + $btn.data('index')).fadeOut();
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', SpectrusGuard.i18n.delete_failed || 'Failed to delete file.');
                },
                complete: function () {
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Quarantine threat file
         */
        quarantineThreat: function ($btn) {
            var self = this;
            var filePath = $btn.data('file');

            if (!confirm(SpectrusGuard.i18n.confirm_quarantine || 'Are you sure you want to quarantine this file?')) {
                return;
            }

            $btn.prop('disabled', true);

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_quarantine_threat',
                    nonce: SpectrusGuard.nonce,
                    file_path: filePath
                },
                success: function (response) {
                    if (response.success) {
                        SpectrusGuardAdmin.showNotice('success', response.data.message);
                        $('#threat-' + $btn.data('index')).fadeOut();
                    } else {
                        SpectrusGuardAdmin.showNotice('error', response.data.message);
                    }
                },
                error: function () {
                    SpectrusGuardAdmin.showNotice('error', SpectrusGuard.i18n.quarantine_failed || 'Failed to quarantine file.');
                },
                complete: function () {
                    $btn.prop('disabled', false);
                }
            });
        },

        /**
         * Show error message
         */
        showError: function (message) {
            if (typeof SpectrusGuardAdmin !== 'undefined' && SpectrusGuardAdmin.showNotice) {
                SpectrusGuardAdmin.showNotice('error', message);
            } else {
                alert(message);
            }
        }
    };

    // Initialize when DOM is ready
    $(document).ready(function () {
        Scanner.init();
    });

    // Expose to global scope for external access
    window.SpectrusGuardScanner = Scanner;

})(jQuery);
