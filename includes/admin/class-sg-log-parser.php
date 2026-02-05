<?php
/**
 * SpectrusGuard Log Parser
 *
 * Memory-efficient log parser using PHP Generators.
 * Processes log files line-by-line without loading entire file into memory.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

declare(strict_types=1);

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Log_Parser
 *
 * Generator-based log parser for efficient processing of large log files.
 */
class SG_Log_Parser
{
    /**
     * Regex pattern for new PSR-3 format: [timestamp] [LEVEL]: message {json}
     */
    private const PATTERN_PSR3 = '/^\[([^\]]+)\] \[([^\]]+)\]: (.+?)(?: (\{.+\}))?$/';

    /**
     * Regex pattern for legacy format: [timestamp] [TYPE] IP: x | URI: y | ...
     */
    private const PATTERN_LEGACY = '/^\[([^\]]+)\] \[([^\]]+)\] IP: ([^\|]+) \| URI: ([^\|]+) \| Payload: ([^\|]+) \| UA: (.*)$/';

    /**
     * Get log entries using a Generator (memory efficient)
     *
     * Yields one parsed entry at a time, keeping memory usage minimal
     * even for multi-gigabyte log files.
     *
     * @param string $filePath Path to log file.
     * @return \Generator Yields parsed log entries.
     */
    public function getLogEntries(string $filePath): \Generator
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return;
        }

        $handle = @fopen($filePath, 'r');
        if (!$handle) {
            return;
        }

        try {
            while (($line = fgets($handle)) !== false) {
                $line = trim($line);
                if (empty($line)) {
                    continue;
                }

                $entry = $this->parseLine($line);
                if ($entry !== null) {
                    yield $entry;
                }
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Get log entries in reverse order (most recent first)
     *
     * @param string $filePath Path to log file.
     * @param int    $limit    Maximum entries to return.
     * @return array Array of parsed entries.
     */
    public function getRecentEntries(string $filePath, int $limit = 100): array
    {
        if (!file_exists($filePath)) {
            return [];
        }

        // For recent entries, we need to read from end
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (empty($lines)) {
            return [];
        }

        $lines = array_slice($lines, -$limit);
        $lines = array_reverse($lines);

        $entries = [];
        foreach ($lines as $line) {
            $entry = $this->parseLine($line);
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Parse a single log line
     *
     * Supports both PSR-3 and legacy formats.
     *
     * @param string $line Raw log line.
     * @return array|null Parsed entry or null if parsing failed.
     */
    public function parseLine(string $line): ?array
    {
        // Try PSR-3 format first
        if (preg_match(self::PATTERN_PSR3, $line, $matches)) {
            return [
                'timestamp' => $matches[1],
                'level' => strtolower($matches[2]),
                'message' => $matches[3],
                'context' => isset($matches[4]) ? json_decode($matches[4], true) ?? [] : [],
                'format' => 'psr3',
            ];
        }

        // Try legacy attack format
        if (preg_match(self::PATTERN_LEGACY, $line, $matches)) {
            return [
                'timestamp' => trim($matches[1]),
                'level' => 'critical',
                'message' => 'Attack: ' . trim($matches[2]),
                'context' => [
                    'type' => trim($matches[2]),
                    'ip' => trim($matches[3]),
                    'uri' => trim($matches[4]),
                    'payload' => trim($matches[5]),
                    'user_agent' => trim($matches[6]),
                ],
                'format' => 'legacy',
            ];
        }

        return null;
    }

    /**
     * Filter entries by level
     *
     * @param string $filePath Path to log file.
     * @param string $level    Level to filter by.
     * @return \Generator Yields matching entries.
     */
    public function filterByLevel(string $filePath, string $level): \Generator
    {
        $level = strtolower($level);

        foreach ($this->getLogEntries($filePath) as $entry) {
            if ($entry['level'] === $level) {
                yield $entry;
            }
        }
    }

    /**
     * Filter entries by date range
     *
     * @param string $filePath  Path to log file.
     * @param string $startDate Start date (Y-m-d format).
     * @param string $endDate   End date (Y-m-d format).
     * @return \Generator Yields matching entries.
     */
    public function filterByDateRange(string $filePath, string $startDate, string $endDate): \Generator
    {
        $startTimestamp = strtotime($startDate . ' 00:00:00');
        $endTimestamp = strtotime($endDate . ' 23:59:59');

        foreach ($this->getLogEntries($filePath) as $entry) {
            $entryTimestamp = strtotime($entry['timestamp']);
            if ($entryTimestamp >= $startTimestamp && $entryTimestamp <= $endTimestamp) {
                yield $entry;
            }
        }
    }

    /**
     * Get statistics for Chart.js
     *
     * Aggregates log entries by hour for time-series visualization.
     *
     * @param string $filePath Path to log file.
     * @param string $date     Date to analyze (Y-m-d format), defaults to today.
     * @return array Chart.js compatible data structure.
     */
    public function getStatsForChart(string $filePath, string $date = ''): array
    {
        if (empty($date)) {
            $date = date('Y-m-d');
        }

        $hourlyData = array_fill(0, 24, 0);
        $levelCounts = [
            'emergency' => 0,
            'alert' => 0,
            'critical' => 0,
            'error' => 0,
            'warning' => 0,
            'notice' => 0,
            'info' => 0,
            'debug' => 0,
        ];

        foreach ($this->getLogEntries($filePath) as $entry) {
            // Check if entry is from the target date
            $entryDate = substr($entry['timestamp'], 0, 10);
            if ($entryDate !== $date) {
                continue;
            }

            // Extract hour
            $hour = (int) substr($entry['timestamp'], 11, 2);
            $hourlyData[$hour]++;

            // Count by level
            $level = $entry['level'];
            if (isset($levelCounts[$level])) {
                $levelCounts[$level]++;
            }
        }

        // Prepare labels (00:00, 01:00, etc.)
        $labels = [];
        for ($i = 0; $i < 24; $i++) {
            $labels[] = sprintf('%02d:00', $i);
        }

        return [
            'labels' => $labels,
            'counts' => array_values($hourlyData),
            'total' => array_sum($hourlyData),
            'by_level' => $levelCounts,
            'date' => $date,
        ];
    }

    /**
     * Get threat summary across multiple days
     *
     * @param string $logDir   Log directory path.
     * @param int    $days     Number of days to analyze.
     * @return array Summary statistics.
     */
    public function getThreatSummary(string $logDir, int $days = 7): array
    {
        $summary = [
            'daily_counts' => [],
            'total' => 0,
            'by_level' => [
                'critical' => 0,
                'error' => 0,
                'warning' => 0,
            ],
            'top_ips' => [],
            'top_attacks' => [],
        ];

        $ipCounts = [];
        $attackCounts = [];

        for ($i = 0; $i < $days; $i++) {
            $date = date('Y-m-d', strtotime("-{$i} days"));
            $filePath = $logDir . '/security-' . $date . '.log';

            $dailyCount = 0;

            if (file_exists($filePath)) {
                foreach ($this->getLogEntries($filePath) as $entry) {
                    $dailyCount++;
                    $summary['total']++;

                    // Count by level
                    $level = $entry['level'];
                    if (isset($summary['by_level'][$level])) {
                        $summary['by_level'][$level]++;
                    }

                    // Count IPs
                    if (isset($entry['context']['ip'])) {
                        $ip = $entry['context']['ip'];
                        $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
                    }

                    // Count attack types
                    if (isset($entry['context']['type'])) {
                        $type = $entry['context']['type'];
                        $attackCounts[$type] = ($attackCounts[$type] ?? 0) + 1;
                    }
                }
            }

            $summary['daily_counts'][$date] = $dailyCount;
        }

        // Sort and get top IPs
        arsort($ipCounts);
        $summary['top_ips'] = array_slice($ipCounts, 0, 10, true);

        // Sort and get top attacks
        arsort($attackCounts);
        $summary['top_attacks'] = array_slice($attackCounts, 0, 10, true);

        return $summary;
    }

    /**
     * Search logs for specific pattern
     *
     * @param string $filePath Path to log file.
     * @param string $query    Search query (case-insensitive).
     * @param int    $limit    Maximum results.
     * @return array Matching entries.
     */
    public function search(string $filePath, string $query, int $limit = 50): array
    {
        $results = [];
        $query = strtolower($query);
        $count = 0;

        foreach ($this->getLogEntries($filePath) as $entry) {
            // Search in message
            if (stripos($entry['message'], $query) !== false) {
                $results[] = $entry;
                $count++;
            }
            // Search in context
            elseif (!empty($entry['context'])) {
                $contextStr = strtolower(json_encode($entry['context']));
                if (strpos($contextStr, $query) !== false) {
                    $results[] = $entry;
                    $count++;
                }
            }

            if ($count >= $limit) {
                break;
            }
        }

        return $results;
    }
}
