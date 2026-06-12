<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
// Variables available from Controller: $report, $score_data, $grouped_issues, $trend
$summary            = $report['summary'];
$last_scan          = $report['scan_time'];
$score              = isset( $score_data['score'] ) ? max( 0, min( 100, (int) $score_data['score'] ) ) : 0;
$score_grade        = isset( $score_data['grade'] ) ? (string) $score_data['grade'] : 'F';
$critical_count     = isset( $summary['critical'] ) ? (int) $summary['critical'] : 0;
$high_count         = isset( $summary['high'] ) ? (int) $summary['high'] : 0;
$medium_count       = isset( $summary['medium'] ) ? (int) $summary['medium'] : 0;
$total_issues       = isset( $summary['total_issues'] ) ? (int) $summary['total_issues'] : 0;
$trend              = in_array( $trend, array( 'up', 'down', 'neutral' ), true ) ? $trend : 'neutral';
$trend_stroke_class = $trend === 'up' ? 'stroke-danger' : 'stroke-success';
$trend_path         = sprintf(
	'M0 %d Q 30 %d, 60 %d T 120 %d',
	$trend === 'up' ? 30 : 10,
	$trend === 'up' ? 35 : 5,
	$trend === 'up' ? 20 : 20,
	$trend === 'up' ? 5 : 35
);
$trend_markup       = '<span class="text-muted">→ Stable</span>';
if ( $trend === 'up' ) {
	$trend_markup = '<span class="text-danger">↗ Increasing</span>';
} elseif ( $trend === 'down' ) {
	$trend_markup = '<span class="text-success">↘ Decreasing</span>';
}

// 1. Sniper Adjustment: Color Psychology
$score_color = 'danger'; // Default Red
if ( $score >= 80 ) {
	$score_color = 'success';
} elseif ( $score >= 40 ) {
	$score_color = 'warning';
}
?>
<div class="wrap sg-dashboard sg-enterprise-view">
	
	<!-- 1. HEADER REFINEMENTS -->
	<div class="sg-header-top">
		<div class="sg-header-left">
			<div class="sg-breadcrumbs">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=spectrus-guard-dashboard' ) ); ?>" class="sg-breadcrumb-link"><?php // Phase 5: escaped ?>Dashboard</a>
				<span class="sg-breadcrumb-sep">/</span>
				<span class="sg-breadcrumb-current">Scan Results</span>
			</div>
			<h1 class="wp-heading-inline" style="font-size: 24px; font-weight: 700; color: #f8fafc;">
				Security Score
				<?php if ( $score >= 90 ) : ?>
					<span class="sg-badge sg-badge-gray" style="margin-left: 10px; font-size: 12px;">EXCELLENT</span>
				<?php endif; ?>
			</h1>
		</div>

		<div class="sg-header-actions">
			<?php
			$last_scan_ts = isset( $report['scan_time'] ) && $report['scan_time'] !== 'Never' ? strtotime( $report['scan_time'] ) : false;
			$time_ago     = $last_scan_ts ? human_time_diff( $last_scan_ts, current_time( 'timestamp' ) ) . ' ago' : 'Never';
			?>
			<span class="sg-last-scan">Last scan: <?php echo esc_html( $time_ago ); ?> ⟳</span>
			
			<button type="button" class="sg-btn-secondary-action" onclick="window.print()">
				<span class="dashicons dashicons-pdf"></span> Export PDF
			</button>
			
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=spectrus-guard-scanner' ) ); ?>" class="sg-btn-primary-action"><?php // Phase 5: escaped ?>
				<span class="dashicons dashicons-controls-play"></span> RUN DEEP SCAN
			</a>
		</div>
	</div>

	<!-- 2. METRICS ROW -->
	<div class="sg-metrics-row">
		<!-- Score Card -->
		<div class="sg-card sg-score-card">
			<div class="sg-card-body">
				<div class="sg-score-ring-container">
					<div class="sg-score-ring" style="background: conic-gradient(var(--sg-<?php echo esc_attr( $score_color ); ?>) <?php // Phase 5: escaped ?> <?php echo esc_attr( $score ); ?>%, transparent 0);"><?php // Phase 5: escaped ?>
						<div class="sg-score-inner">
							<span class="sg-score-grade text-<?php echo esc_attr( $score_color ); ?>"><?php // Phase 5: escaped ?>
								<?php echo esc_html( $score_grade ); // Phase 5: escaped ?>
							</span>
							<span class="sg-score-val"><?php echo esc_html( (string) $score ); // Phase 5: escaped ?>/100</span>
						</div>
					</div>
				</div>
				<div class="sg-score-meta">
					<h4><?php _e( 'Security Score', 'spectrus-guard' ); ?></h4>
					<p><?php _e( 'Based on vulnerability severity', 'spectrus-guard' ); ?></p>
				</div>
			</div>
		</div>

		<!-- Breakdown Card (Same as before) -->
		<div class="sg-card sg-breakdown-card">
			<div class="sg-card-body">
				<?php if ( $critical_count > 0 ) : ?>
					<div class="sg-severity-row critical">
						<div class="sg-sev-label">CRITICAL <span class="sg-count"><?php echo esc_html( (string) $critical_count ); // Phase 5: escaped ?></span></div>
						<div class="sg-progress-track">
							<div class="sg-progress-bar bg-danger" style="width: <?php echo esc_attr( (string) min( 100, ( $critical_count * 5 ) ) ); ?>%"></div><?php // Phase 5: escaped ?>
						</div>
					</div>
				<?php endif; ?>

				<?php if ( $high_count > 0 ) : ?>
					<div class="sg-severity-row high">
						<div class="sg-sev-label">HIGH <span class="sg-count"><?php echo esc_html( (string) $high_count ); // Phase 5: escaped ?></span></div>
						<div class="sg-progress-track">
							<div class="sg-progress-bar bg-warning" style="width: <?php echo esc_attr( (string) min( 100, ( $high_count * 5 ) ) ); ?>%"></div><?php // Phase 5: escaped ?>
						</div>
					</div>
				<?php endif; ?>
				
				<?php if ( $medium_count > 0 ) : ?>
					<div class="sg-severity-row medium">
						<div class="sg-sev-label">MEDIUM <span class="sg-count"><?php echo esc_html( (string) $medium_count ); // Phase 5: escaped ?></span></div>
						<div class="sg-progress-track">
							<div class="sg-progress-bar bg-info" style="width: <?php echo esc_attr( (string) min( 100, ( $medium_count * 5 ) ) ); ?>%"></div><?php // Phase 5: escaped ?>
						</div>
					</div>
				<?php endif; ?>

				<?php if ( $total_issues === 0 ) : ?>
					<div class="sg-all-clean">
						<span class="dashicons dashicons-yes-alt text-success"></span>
						<span><?php _e( 'No issues detected', 'spectrus-guard' ); ?></span>
					</div>
				<?php endif; ?>
			</div>
		</div>

		<!-- Trend Card -->
		<div class="sg-card sg-trend-card">
			<div class="sg-card-body">
				<div class="sg-trend-graph">
					<!-- Sparkline Simulation (CSS) -->
					<svg width="120" height="40" stroke-width="2" fill="none" class="<?php echo esc_attr( $trend_stroke_class ); ?>"><?php // Phase 5: escaped ?>
						<path d="<?php echo esc_attr( $trend_path ); ?>" /><?php // Phase 5: escaped ?>
					</svg>
				</div>
				<div class="sg-trend-info">
					<h4><?php _e( 'Threat Trend', 'spectrus-guard' ); ?></h4>
					<span class="sg-trend-val">
						<?php echo wp_kses( $trend_markup, array( 'span' => array( 'class' => array() ) ) ); // Phase 5: escaped ?>
					</span>
					<small>vs Last 5 Scans</small>
				</div>
			</div>
		</div>
	</div>

	<!-- 3. FILTER BAR -->
	<div class="sg-filter-toolbar">
		<div class="sg-search-box">
			<span class="dashicons dashicons-search"></span>
			<input type="text" id="sg-search-input" placeholder="<?php _e( 'Search by vulnerability or file...', 'spectrus-guard' ); ?>">
		</div>
		<div class="sg-quick-filters">
			<button class="sg-filter-chip active" data-filter="all">All</button>
			<button class="sg-filter-chip" data-filter="critical">Critical Only</button>
			<button class="sg-filter-chip" data-filter="unpatched">Unpatched</button>
		</div>
	</div>

	<!-- 4. VULNERABILITY LIST (Data Grid) -->
	<div class="sg-vulnerability-grid">
		<div class="sg-grid-header">
			<div class="col-check"><input type="checkbox" id="sg-check-all"></div>
			<div class="col-sev">Severity</div>
			<div class="col-name">Vulnerability Group</div>
			<div class="col-assets">Affected Assets</div>
			<div class="col-status">Status</div>
			<div class="col-actions">Actions</div>
		</div>

		<?php if ( empty( $grouped_issues ) ) : ?>
			<!-- EMPTY STATE -->
			<div class="sg-empty-state">
				<span class="sg-empty-icon">🎉</span>
				<div class="sg-empty-title">System is Clean!</div>
				<div class="sg-empty-desc">No security threats were detected in the last scan. Your WordPress installation is secure.</div>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=spectrus-guard-scanner' ) ); ?>" class="sg-btn-primary-action"><?php // Phase 5: escaped ?>
					Run New Scan
				</a>
			</div>
		<?php else : ?>
			<?php foreach ( $grouped_issues as $group_key => $group ) : ?>
				<div class="sg-grid-row-group severity-<?php echo esc_attr( $group['severity'] ); ?>">
					<!-- Parent Row -->
					<div class="sg-grid-row parent" onclick="toggleGroup(this)">
						<div class="col-check"><input type="checkbox" class="sg-group-check" onclick="event.stopPropagation()"></div>
						<div class="col-sev">
							<span class="sg-badge-pill severity-<?php echo esc_attr( $group['severity'] ); ?>">
								<?php echo esc_html( strtoupper( (string) $group['severity'] ) ); // Phase 5: escaped ?>
							</span>
						</div>
						<div class="col-name">
							<strong><?php echo esc_html( $group['name'] ); ?></strong>
							<span class="sg-chevron">▼</span>
						</div>
						<div class="col-assets">
							<?php echo esc_html( (string) count( $group['items'] ) ); // Phase 5: escaped ?> assets
						</div>
						<div class="col-status">
							<?php $badge_color = in_array( $group['severity'], array( 'critical', 'high' ) ) ? 'red' : 'blue'; ?>
							<span class="status-badge bg-<?php echo esc_attr( $badge_color ); ?>"><?php // Phase 5: escaped ?>Open</span>
						</div>
						<div class="col-actions">
							<button class="sg-btn-icon" title="Fix All">⚡ Fix All</button>
						</div>
					</div>

					<!-- Children Rows (Accordion) -->
					<div class="sg-grid-children" style="display: none;">
						<div class="sg-bulk-actions-bar">
							<button class="sg-btn-nano bg-red delete-bulk">Delete Selected</button>
							<button class="sg-btn-nano bg-orange quarantine-bulk">Quarantine Selected</button>
							<button class="sg-btn-nano whitelist-bulk">Whitelist Selected</button>
						</div>
						<?php
						foreach ( $group['items'] as $item ) :
							$file = $item['file'] ?? 'Unknown';
							$desc = $item['message'] ?? $item['description'] ?? '';
							?>
							<div class="sg-child-row">
								<div class="col-check"><input type="checkbox" class="sg-item-check" data-file="<?php echo esc_attr( $file ); ?>"></div>
								<div class="child-loc">
									<code class="sg-mono"><?php echo esc_html( basename( $file ) ); ?></code>
									<small class="sg-path"><?php echo esc_html( $file ); ?></small>
								</div>
								<div class="child-actions" style="display: flex; gap: 4px;">
									
									<!-- View Details (Eye) -->
									<button class="sg-btn-icon-only" title="View Details" onclick="viewDetails('<?php echo esc_js( $file ); ?>')">
										<span class="dashicons dashicons-visibility"></span>
									</button>
									
									<!-- Quarantine (Shield/Orange) -->
									<button class="sg-btn-icon-only bg-orange" title="Quarantine File" onclick="quarantineFile('<?php echo esc_js( $file ); ?>', this)">
										<span class="dashicons dashicons-shield"></span>
									</button>
									
									<!-- Whitelist (Check/Green) -->
									<button class="sg-btn-icon-only bg-green" title="Whitelist File" onclick="whitelistFile('<?php echo esc_js( $file ); ?>', this)">
										<span class="dashicons dashicons-yes"></span>
									</button>

									<!-- Delete (Trash/Red) -->
									<button class="sg-btn-icon-only bg-red" title="Delete File" onclick="deleteFile('<?php echo esc_js( $file ); ?>', this)">
										<span class="dashicons dashicons-trash"></span>
									</button>

								</div>
							</div>
						<?php endforeach; ?>
					</div>
				</div>
			<?php endforeach; ?>
		<?php endif; ?>
	</div>
</div>

<script type="text/javascript">
jQuery(document).ready(function($) {
	
	// Toggle Accordion
	window.toggleGroup = function(element) {
		const children = element.nextElementSibling;
		const chevron = element.querySelector('.sg-chevron');
		
		if (children.style.display === 'none') {
			children.style.display = 'block';
			chevron.style.transform = 'rotate(180deg)';
			element.classList.add('expanded');
		} else {
			children.style.display = 'none';
			chevron.style.transform = 'rotate(0deg)';
			element.classList.remove('expanded');
		}
	};

	// SEARCH & FILTER Logic (Same as before)
	$('#sg-search-input').on('keyup', function searchFilter() {
		const term = $(this).val().toLowerCase();
		$('.sg-grid-row-group').each(function() {
			const text = $(this).text().toLowerCase();
			$(this).toggle(text.indexOf(term) > -1);
		});
	});

	$('.sg-filter-chip').on('click', function() {
		$('.sg-filter-chip').removeClass('active');
		$(this).addClass('active');
		const filter = $(this).data('filter');
		$('.sg-grid-row-group').each(function() {
			if (filter === 'all') $(this).show();
			else if (filter === 'critical') {
				$(this).toggle($(this).hasClass('severity-critical') || $(this).hasClass('severity-high'));
			} else if (filter === 'unpatched') $(this).show();
		});
	});

	// CHECKBOX Logic
	$('#sg-check-all').on('change', function() {
		$('input[type="checkbox"]').prop('checked', $(this).is(':checked'));
	});
	$('.sg-group-check').on('change', function() {
		$(this).closest('.sg-grid-row-group').find('.sg-item-check').prop('checked', $(this).is(':checked'));
	});

	// --- ACTIONS ---

	// 1. DELETE FILE
	window.deleteFile = function(file, btn) {
		if(!confirm('Are you sure you want to permanently delete ' + file + '?')) return;
		const $row = $(btn).closest('.sg-child-row');
		$row.css('opacity', '0.5');

		$.post(sg_ajax.ajaxurl, {
			action: 'sg_delete_file',
			file: file,
			nonce: sg_ajax.nonce
		}, function(response) {
			if(response.success) {
				$row.slideUp(function(){ $(this).remove(); });
				alert('File successfully deleted!');
			} else {
				alert('Error: ' + response.data);
				$row.css('opacity', '1');
			}
		});
	};

	// 2. QUARANTINE FILE (New)
	window.quarantineFile = function(file, btn) {
		if(!confirm('Move ' + file + ' to quarantine?')) return;
		const $row = $(btn).closest('.sg-child-row');
		$row.css('opacity', '0.5');
		
		$.post(sg_ajax.ajaxurl, {
			action: 'sg_quarantine_file',
			file: file,
			nonce: sg_ajax.nonce
		}, function(response) {
			if(response.success) {
				$row.slideUp();
				// Optional: Update count in header
				alert('File moved to quarantine.');
			} else {
				alert('Error: ' + (response.data || 'Unknown error'));
				$row.css('opacity', '1');
			}
		});
	};

	// 3. WHITELIST FILE
	window.whitelistFile = function(file, btn) {
		if(!confirm('Whitelist ' + file + '? It will be ignored in future scans.')) return;
		const $row = $(btn).closest('.sg-child-row');
		$.post(sg_ajax.ajaxurl, {
			action: 'sg_whitelist_file',
			file: file,
			nonce: sg_ajax.nonce
		}, function(response) {
			if(response.success) {
				$row.slideUp();
				alert('File whitelisted.');
			} else {
				alert('Error: ' + response.data);
			}
		});
	};

	// 4. BULK ACTIONS
	$('.delete-bulk').on('click', function() {
		const $group = $(this).closest('.sg-grid-children');
		const $checked = $group.find('.sg-item-check:checked');
		if($checked.length === 0) { alert('Select items first'); return; }
		if(!confirm('Delete ' + $checked.length + ' files?')) return;

		$checked.each(function() {
			const file = $(this).data('file');
			const $row = $(this).closest('.sg-child-row');
			$.post(sg_ajax.ajaxurl, { action: 'sg_delete_file', file: file, nonce: sg_ajax.nonce }, 
			function(res) { if(res.success) $row.remove(); });
		});
	});

	// 5. VIEW DETAILS
	window.viewDetails = function(file) {
		alert('View Details: \n' + file + '\n\n(Content viewer coming in v3.1)');
	};
});
</script>
