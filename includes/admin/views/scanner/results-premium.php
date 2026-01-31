<?php
if (!defined('ABSPATH')) {
    exit;
}
// Variables available from Controller: $report, $score_data, $grouped_issues, $trend
$summary = $report['summary'];
$last_scan = $report['scan_time'];
?>
<div class="wrap sg-dashboard sg-enterprise-view">
    <!-- 1. HEADER METRICS -->
    <div class="sg-metrics-row">
        <!-- Score Card -->
        <div class="sg-card sg-score-card">
            <div class="sg-card-body">
                <div class="sg-score-ring-container">
                    <div class="sg-score-ring" style="background: conic-gradient(var(--sg-<?php echo ($score_data['score'] >= 80 ? 'success' : ($score_data['score'] >= 60 ? 'warning' : 'danger')); ?>) <?php echo $score_data['score']; ?>%, transparent 0);">
                        <div class="sg-score-inner">
                            <span class="sg-score-grade <?php echo $score_data['color']; ?>">
                                <?php echo $score_data['grade']; ?>
                            </span>
                            <span class="sg-score-val"><?php echo $score_data['score']; ?>/100</span>
                        </div>
                    </div>
                </div>
                <div class="sg-score-meta">
                    <h4><?php _e('Security Score', 'spectrus-guard'); ?></h4>
                    <p><?php _e('Based on vulnerability severity', 'spectrus-guard'); ?></p>
                </div>
            </div>
        </div>

        <!-- Breakdown Card -->
        <div class="sg-card sg-breakdown-card">
            <div class="sg-card-body">
                <div class="sg-severity-row critical">
                    <div class="sg-sev-label">CRITICAL <span class="sg-count"><?php echo $summary['critical']; ?></span></div>
                    <div class="sg-progress-track">
                        <div class="sg-progress-bar bg-danger" style="width: <?php echo min(100, ($summary['critical'] * 5)); ?>%"></div>
                    </div>
                </div>
                <div class="sg-severity-row high">
                    <div class="sg-sev-label">HIGH <span class="sg-count"><?php echo $summary['high']; ?></span></div>
                    <div class="sg-progress-track">
                        <div class="sg-progress-bar bg-warning" style="width: <?php echo min(100, ($summary['high'] * 5)); ?>%"></div>
                    </div>
                </div>
                <div class="sg-severity-row medium">
                    <div class="sg-sev-label">MEDIUM <span class="sg-count"><?php echo $summary['medium']; ?></span></div>
                    <div class="sg-progress-track">
                        <div class="sg-progress-bar bg-info" style="width: <?php echo min(100, ($summary['medium'] * 5)); ?>%"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Trend Card -->
        <div class="sg-card sg-trend-card">
            <div class="sg-card-body">
                <div class="sg-trend-icon <?php echo $trend == 'up' ? 'text-red-500' : ($trend == 'down' ? 'text-green-500' : 'text-gray-500'); ?>">
                    <?php if ($trend == 'up'): ?>
                        📈
                    <?php elseif ($trend == 'down'): ?>
                        📉
                    <?php else: ?>
                        ➡️
                    <?php endif; ?>
                </div>
                <div class="sg-trend-info">
                    <h4><?php _e('Threat Trend', 'spectrus-guard'); ?></h4>
                    <span class="sg-trend-val">
                        <?php 
                        if ($trend == 'up') _e('Increasing', 'spectrus-guard');
                        elseif ($trend == 'down') _e('Decreasing', 'spectrus-guard');
                        else _e('Stable', 'spectrus-guard');
                        ?>
                    </span>
                    <small>vs Last 5 Scans</small>
                </div>
            </div>
        </div>
    </div>

    <!-- 2. FILTER BAR -->
    <div class="sg-filter-toolbar">
        <div class="sg-search-box">
            <span class="dashicons dashicons-search"></span>
            <input type="text" id="sg-search-input" placeholder="<?php _e('Search by vulnerability or file...', 'spectrus-guard'); ?>">
        </div>
        <div class="sg-quick-filters">
            <button class="sg-filter-chip active" data-filter="all">All</button>
            <button class="sg-filter-chip" data-filter="critical">Critical Only</button>
            <button class="sg-filter-chip" data-filter="unpatched">Unpatched</button>
        </div>
        <div class="sg-toolbar-actions">
            <button class="sg-btn sg-btn-outline" id="sg-export-pdf">
                <span class="dashicons dashicons-media-document"></span> Export PDF
            </button>
        </div>
    </div>

    <!-- 3. VULNERABILITY LIST (Data Grid) -->
    <div class="sg-vulnerability-grid">
        <div class="sg-grid-header">
            <div class="col-sev">Severity</div>
            <div class="col-name">Vulnerability Name</div>
            <div class="col-assets">Affected Assets</div>
            <div class="col-status">Status</div>
            <div class="col-actions">Actions</div>
        </div>

        <?php if (empty($grouped_issues)): ?>
            <div class="sg-empty-state-large">
                <div class="icon">🎉</div>
                <h3>No Vulnerabilities Found</h3>
                <p>Your system is clean and secure.</p>
            </div>
        <?php else: ?>
            <?php foreach ($grouped_issues as $group_key => $group): ?>
                <div class="sg-grid-row-group severity-<?php echo esc_attr($group['severity']); ?>">
                    <!-- Parent Row -->
                    <div class="sg-grid-row parent" onclick="toggleGroup(this)">
                        <div class="col-sev">
                            <span class="sg-badge-pill severity-<?php echo esc_attr($group['severity']); ?>">
                                <?php echo strtoupper($group['severity']); ?>
                            </span>
                        </div>
                        <div class="col-name">
                            <strong><?php echo esc_html($group['name']); ?></strong>
                            <span class="sg-chevron">▼</span>
                        </div>
                        <div class="col-assets">
                            <?php echo count($group['items']); ?> assets affected
                        </div>
                        <div class="col-status">
                            <span class="status-badge open">Open</span>
                        </div>
                        <div class="col-actions">
                            <button class="sg-btn-icon" title="Fix All">🔧</button>
                        </div>
                    </div>

                    <!-- Children Rows (Accordion) -->
                    <div class="sg-grid-children" style="display: none;">
                        <?php foreach ($group['items'] as $item): 
                            $file = $item['file'] ?? 'Unknown';
                            $desc = $item['message'] ?? $item['description'] ?? '';
                        ?>
                            <div class="sg-child-row">
                                <div class="child-loc">
                                    <code><?php echo esc_html(basename($file)); ?></code>
                                    <small><?php echo esc_html($file); ?></small>
                                </div>
                                <div class="child-actions">
                                    <button class="sg-btn-tiny" onclick="viewDetails('<?php echo esc_js($file); ?>')">View</button>
                                    <button class="sg-btn-tiny bg-red" onclick="deleteFile('<?php echo esc_js($file); ?>')">Delete</button>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>

<script>
function toggleGroup(element) {
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
}

// Search Logic
document.getElementById('sg-search-input').addEventListener('keyup', function(e) {
    const term = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.sg-grid-row-group');
    
    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        if (text.includes(term)) {
            row.style.display = 'block';
        } else {
            row.style.display = 'none';
        }
    });
});

// Quick Filters
document.querySelectorAll('.sg-filter-chip').forEach(btn => {
    btn.addEventListener('click', function() {
        // Toggle active class
        document.querySelectorAll('.sg-filter-chip').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        
        const filter = this.dataset.filter;
        const rows = document.querySelectorAll('.sg-grid-row-group');
        
        rows.forEach(row => {
            if (filter === 'all') {
                row.style.display = 'block';
            } else if (filter === 'critical') {
                if (row.classList.contains('severity-critical')) row.style.display = 'block';
                else row.style.display = 'none';
            } else {
                row.style.display = 'block'; // Placeholder for other logic
            }
        });
    });
});

// Mock Delete
function deleteFile(file) {
    if(confirm('Delete ' + file + '?')) {
        alert('Action simulated.');
    }
}

function viewDetails(file) {
    alert('Viewing ' + file);
}
</script>