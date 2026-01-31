<?php
/**
 * SpectrusGuard Results Page Controller
 *
 * Handles the display of the detailed scan results page (premium UI).
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Page_Results
 *
 * Controller for the Scanner Results page.
 */
class SG_Page_Results
{
    /**
     * Loader instance
     *
     * @var SG_Loader
     */
    private $loader;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct(SG_Loader $loader)
    {
        $this->loader = $loader;
    }

    /**
     * Render the page
     */
    public function render()
    {
        // DEBUG PROBE
        echo "DEBUG MODE: HELLO. IF YOU SEE THIS, CONTROLLER IS REACHABLE.";
        exit;

        // echo "Probe 1: Start Render<br>";

        // Fetch saved results
        $report = get_option('spectrus_guard_scan_report', array());
        echo "Probe 2: Report Fetched. Size: " . strlen(serialize($report)) . "<br>";

        // Fallback if empty
        if (empty($report)) {
            $report = array(
                'summary' => array(
                    'total_issues' => 0,
                    'critical' => 0,
                    'high' => 0,
                    'medium' => 0,
                    'low' => 0,
                ),
                'scan_time' => 'Never',
                'uploads_php' => array(),
                'suspicious' => array(),
                'core_integrity' => array(),
                'malware' => array(),
                'advanced_threats' => array(),
            );
        }

        // Calculate Score
        $score_data = $this->calculate_score($report['summary']);
        echo "Probe 3: Score Calculated<br>";

        // Group Issues
        $grouped_issues = $this->group_issues_by_type($report);
        echo "Probe 4: Issues Grouped<br>";

        // Get History for Trend
        $history = get_option('spectrus_guard_scan_history', array());
        $trend = $this->calculate_trend($history, $report['summary']);
        echo "Probe 5: Trend Calculated. Loading View...<br>";

        // Load the view
        require_once SG_PLUGIN_DIR . 'includes/admin/views/scanner/results-premium.php';
    }

    /**
     * Calculate Security Score (0-100)
     */
    private function calculate_score($summary)
    {
        $base_score = 100;

        // Penalties
        $deductions = (
            ($summary['critical'] * 25) +
            ($summary['high'] * 10) +
            ($summary['medium'] * 5) +
            ($summary['low'] * 1)
        );

        $final_score = max(0, $base_score - $deductions);

        // Grade
        if ($final_score >= 90)
            $grade = 'A';
        elseif ($final_score >= 80)
            $grade = 'B';
        elseif ($final_score >= 60)
            $grade = 'C';
        elseif ($final_score >= 40)
            $grade = 'D';
        else
            $grade = 'F';

        // Color
        if ($final_score >= 80)
            $color = 'text-green-500';
        elseif ($final_score >= 60)
            $color = 'text-yellow-500';
        else
            $color = 'text-red-500';

        return array(
            'score' => $final_score,
            'grade' => $grade,
            'color' => $color
        );
    }

    /**
     * Group issues by vulnerability type
     */
    private function group_issues_by_type($report)
    {
        $groups = array();

        // 1. Malware
        if (!empty($report['malware'])) {
            // Group malware slightly smarter if possible, otherwise generic bucket
            // $this->add_issue_to_group($groups, 'Malware Detected', 'critical', array('description' => count($report['malware']) . ' malware files detected'));
            // Actually, we want individual items in the group
            foreach ($report['malware'] as $item) {
                $this->add_issue_to_group($groups, 'Malware Detected', 'critical', $item);
            }
        }

        // 2. Uploads
        if (!empty($report['uploads_php'])) {
            foreach ($report['uploads_php'] as $item) {
                $this->add_issue_to_group($groups, 'PHP in Uploads Directory', 'critical', $item);
            }
        }

        // 3. Core Integrity
        if (!empty($report['core_integrity'])) {
            foreach ($report['core_integrity'] as $item) {
                $this->add_issue_to_group($groups, 'WordPress Core Modification', 'critical', $item);
            }
        }

        // 4. Suspicious
        if (!empty($report['suspicious'])) {
            foreach ($report['suspicious'] as $item) {
                $this->add_issue_to_group($groups, 'Suspicious File Attribute', 'high', $item);
            }
        }

        // 5. Advanced Threats - Normalized
        if (!empty($report['advanced_threats'])) {
            foreach ($report['advanced_threats'] as $item) {
                // Normalize names
                $desc = $item['description'] ?? $item['message'] ?? 'Unknown Vulnerability';

                if (stripos($desc, 'SQL Injection') !== false)
                    $name = 'SQL Injection';
                elseif (stripos($desc, 'XSS') !== false)
                    $name = 'Cross-Site Scripting (XSS)';
                elseif (stripos($desc, 'CSRF') !== false)
                    $name = 'CSRF Vulnerability';
                elseif (stripos($desc, 'Execution') !== false || stripos($desc, 'eval') !== false)
                    $name = 'Remote Code Execution (RCE)';
                elseif (stripos($desc, 'Upload') !== false)
                    $name = 'Unsafe File Upload';
                elseif (stripos($desc, 'User') !== false && stripos($desc, 'Creation') !== false)
                    $name = 'Unauthorized User Creation';
                else
                    $name = 'Code Vulnerability'; // Fallback

                $severity = $item['severity'] ?? 'medium';
                $this->add_issue_to_group($groups, $name, $severity, $item);
            }
        }

        // Sort groups by severity
        uasort($groups, function ($a, $b) {
            return $this->get_severity_weight($b['severity']) - $this->get_severity_weight($a['severity']);
        });

        return $groups;
    }

    /**
     * Add issue to specific group (passed by reference)
     */
    private function add_issue_to_group(&$groups, $type, $severity, $issue)
    {
        if (!isset($groups[$type])) {
            $groups[$type] = array(
                'name' => $type,
                'severity' => $severity,
                'count' => 0,
                'items' => array()
            );
        }
        // Update severity if this item is more critical
        if ($this->get_severity_weight($severity) > $this->get_severity_weight($groups[$type]['severity'])) {
            $groups[$type]['severity'] = $severity;
        }

        $groups[$type]['count']++;
        $groups[$type]['items'][] = $issue;
    }

    private function get_severity_weight($severity)
    {
        $map = array('critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1, 'info' => 0);
        return $map[strtolower($severity)] ?? 0;
    }

    private function calculate_trend($history, $current_summary)
    {
        if (empty($history))
            return 'neutral';

        $last_scan = end($history);
        $prev_issues = $last_scan['stats']['total_issues'] ?? 0;
        $curr_issues = $current_summary['total_issues'];

        if ($curr_issues > $prev_issues)
            return 'up'; // Bad
        if ($curr_issues < $prev_issues)
            return 'down'; // Good
        return 'neutral';
    }
}
