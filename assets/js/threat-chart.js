/**
 * SpectrusGuard Threat Chart Module
 *
 * Chart.js integration for threat visualization.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

(function ($) {
    'use strict';

    /**
     * SpectrusGuard Chart Module
     */
    var SpectrusGuardChart = {

        // Chart instance
        threatChart: null,

        // Chart colors (dark mode compatible)
        colors: {
            primary: '#6366f1',      // Indigo
            primaryLight: 'rgba(99, 102, 241, 0.1)',
            critical: '#ef4444',     // Red
            warning: '#f59e0b',      // Amber
            info: '#3b82f6',         // Blue
            grid: '#334155',         // Slate
            text: '#94a3b8'          // Slate light
        },

        /**
         * Initialize
         */
        init: function () {
            // Only init if Chart.js is available
            if (typeof Chart === 'undefined') {
                console.warn('SpectrusGuard: Chart.js not loaded');
                return;
            }

            this.initThreatChart();
            this.loadChartData();
            this.bindEvents();
        },

        /**
         * Bind events
         */
        bindEvents: function () {
            // Date picker change
            $(document).on('change', '#sg-chart-date', this.handleDateChange.bind(this));

            // Refresh button
            $(document).on('click', '#sg-refresh-chart', this.loadChartData.bind(this));

            // Period selector
            $(document).on('click', '.sg-chart-period', this.handlePeriodChange.bind(this));
        },

        /**
         * Initialize the threat chart
         */
        initThreatChart: function () {
            var canvas = document.getElementById('threatChart');
            if (!canvas) return;

            var ctx = canvas.getContext('2d');

            // Chart.js default config for dark mode
            Chart.defaults.color = this.colors.text;
            Chart.defaults.borderColor = this.colors.grid;

            this.threatChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Threats Detected',
                        data: [],
                        borderColor: this.colors.primary,
                        backgroundColor: this.colors.primaryLight,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        pointBackgroundColor: this.colors.primary,
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            backgroundColor: '#1e293b',
                            titleColor: '#f8fafc',
                            bodyColor: '#94a3b8',
                            borderColor: this.colors.grid,
                            borderWidth: 1,
                            padding: 12,
                            displayColors: false,
                            callbacks: {
                                title: function (items) {
                                    return items[0].label;
                                },
                                label: function (context) {
                                    var value = context.parsed.y;
                                    return value + ' threat' + (value !== 1 ? 's' : '');
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: this.colors.grid,
                                drawBorder: false
                            },
                            ticks: {
                                stepSize: 1,
                                padding: 10
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                maxRotation: 0,
                                autoSkip: true,
                                maxTicksLimit: 12
                            }
                        }
                    }
                }
            });
        },

        /**
         * Load chart data via AJAX
         */
        loadChartData: function () {
            var self = this;
            var date = $('#sg-chart-date').val() || '';

            // Show loading state
            this.showLoading();

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_get_chart_data',
                    nonce: SpectrusGuard.nonce,
                    date: date
                },
                success: function (response) {
                    if (response.success && response.data) {
                        self.updateChart(response.data);
                        self.updateStats(response.data);
                    } else {
                        self.showError('Failed to load chart data');
                    }
                },
                error: function () {
                    self.showError('Network error loading chart');
                },
                complete: function () {
                    self.hideLoading();
                }
            });
        },

        /**
         * Update chart with new data
         */
        updateChart: function (data) {
            if (!this.threatChart) return;

            this.threatChart.data.labels = data.labels || [];
            this.threatChart.data.datasets[0].data = data.counts || [];
            this.threatChart.update('none'); // No animation for updates
        },

        /**
         * Update stats displays
         */
        updateStats: function (data) {
            if (data.total !== undefined) {
                $('#sg-chart-total').text(data.total);
            }

            if (data.by_level) {
                $('#sg-chart-critical').text(data.by_level.critical || 0);
                $('#sg-chart-warning').text(data.by_level.warning || 0);
                $('#sg-chart-error').text(data.by_level.error || 0);
            }
        },

        /**
         * Handle date change
         */
        handleDateChange: function (e) {
            this.loadChartData();
        },

        /**
         * Handle period button change
         */
        handlePeriodChange: function (e) {
            e.preventDefault();

            var $btn = $(e.currentTarget);
            var period = $btn.data('period');

            // Update active state
            $('.sg-chart-period').removeClass('active');
            $btn.addClass('active');

            // Calculate date based on period
            var date = new Date();
            if (period === 'yesterday') {
                date.setDate(date.getDate() - 1);
            } else if (period === 'week') {
                // Load week summary instead
                this.loadThreatSummary(7);
                return;
            }

            var dateStr = date.toISOString().split('T')[0];
            $('#sg-chart-date').val(dateStr);
            this.loadChartData();
        },

        /**
         * Load threat summary for multiple days
         */
        loadThreatSummary: function (days) {
            var self = this;

            this.showLoading();

            $.ajax({
                url: SpectrusGuard.ajax_url,
                type: 'POST',
                data: {
                    action: 'sg_get_threat_summary',
                    nonce: SpectrusGuard.nonce,
                    days: days
                },
                success: function (response) {
                    if (response.success && response.data) {
                        self.updateChartWithSummary(response.data);
                    }
                },
                complete: function () {
                    self.hideLoading();
                }
            });
        },

        /**
         * Update chart with multi-day summary
         */
        updateChartWithSummary: function (data) {
            if (!this.threatChart || !data.daily_counts) return;

            var labels = Object.keys(data.daily_counts).reverse();
            var counts = labels.map(function (date) {
                return data.daily_counts[date];
            });

            // Format labels to show just month/day
            labels = labels.map(function (date) {
                var parts = date.split('-');
                return parts[1] + '/' + parts[2];
            });

            this.threatChart.data.labels = labels;
            this.threatChart.data.datasets[0].data = counts;
            this.threatChart.update('none');

            // Update total
            $('#sg-chart-total').text(data.total || 0);
        },

        /**
         * Show loading state
         */
        showLoading: function () {
            $('#sg-chart-wrapper').addClass('loading');
        },

        /**
         * Hide loading state
         */
        hideLoading: function () {
            $('#sg-chart-wrapper').removeClass('loading');
        },

        /**
         * Show error message
         */
        showError: function (message) {
            if (window.SpectrusGuardAdmin && SpectrusGuardAdmin.showNotice) {
                SpectrusGuardAdmin.showNotice('error', message);
            } else {
                console.error('SpectrusGuard Chart Error:', message);
            }
        }
    };

    /**
     * Document ready
     */
    $(document).ready(function () {
        SpectrusGuardChart.init();
    });

    // Expose to global scope
    window.SpectrusGuardChart = SpectrusGuardChart;

})(jQuery);
