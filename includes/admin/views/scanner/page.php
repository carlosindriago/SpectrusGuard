<?php
/**
 * Scanner Page View
 *
 * Main template for the Security Scanner page.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/** @var array $scan */
/** @var array $threats */
/** @var array $suppressed_hashes */
?>
<?php
$timestamp = isset($scan['timestamp']) ? (int) $scan['timestamp'] : 0;
$total_files = isset($scan['total_files']) ? (int) $scan['total_files'] : 0;
$total_threats = isset($scan['total_threats']) ? (int) $scan['total_threats'] : 0;
$summary = isset($scan['summary']) && is_array($scan['summary']) ? $scan['summary'] : array();

$badge_counts = array(
    'critical' => isset($summary['critical']) ? (int) $summary['critical'] : 0,
    'high' => isset($summary['high']) ? (int) $summary['high'] : 0,
    'medium' => isset($summary['medium']) ? (int) $summary['medium'] : 0,
    'low' => isset($summary['low']) ? (int) $summary['low'] : 0,
    'info' => isset($summary['info']) ? (int) $summary['info'] : 0,
);
?>
<div class="wrap">
    <h1><?php esc_html_e('Security Scanner', 'spectrus-guard'); ?></h1>

    <div class="sg-scanner-header">
        <div class="sg-scanner-meta">
            <?php if ($timestamp): ?>
                <div class="sg-scanner-meta-item">
                    <strong><?php esc_html_e('Último scan:', 'spectrus-guard'); ?></strong>
                    <span id="sg-last-scan"><?php echo esc_html(wp_date('d/m/Y H:i', $timestamp)); ?></span>
                </div>
                <div class="sg-scanner-meta-item">
                    <strong><?php esc_html_e('Total archivos:', 'spectrus-guard'); ?></strong>
                    <span id="sg-total-files"><?php echo esc_html((string) $total_files); ?></span>
                </div>
                <div class="sg-scanner-meta-item">
                    <strong><?php esc_html_e('Total amenazas:', 'spectrus-guard'); ?></strong>
                    <span id="sg-total-threats"><?php echo esc_html((string) $total_threats); ?></span>
                </div>
            <?php else: ?>
                <div class="sg-scanner-meta-item">
                    <?php esc_html_e('Aún no se ha ejecutado un scan.', 'spectrus-guard'); ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="sg-scanner-actions">
            <button type="button" class="button button-primary" id="sg-scan-btn">
                <?php esc_html_e('Escanear ahora', 'spectrus-guard'); ?>
            </button>
            <span class="sg-scan-spinner" id="sg-scan-spinner"><?php esc_html_e('Escaneando...', 'spectrus-guard'); ?></span>
        </div>
    </div>

    <div class="sg-scanner-summary">
        <span class="sg-badge sg-badge-critical"><?php echo esc_html('CRITICAL: ' . (string) $badge_counts['critical']); ?></span>
        <span class="sg-badge sg-badge-high"><?php echo esc_html('HIGH: ' . (string) $badge_counts['high']); ?></span>
        <span class="sg-badge sg-badge-medium"><?php echo esc_html('MEDIUM: ' . (string) $badge_counts['medium']); ?></span>
        <span class="sg-badge sg-badge-low"><?php echo esc_html('LOW: ' . (string) $badge_counts['low']); ?></span>
        <span class="sg-badge sg-badge-info"><?php echo esc_html('INFO: ' . (string) $badge_counts['info']); ?></span>
    </div>

    <div class="sg-scanner-filters">
        <div class="sg-filter-group">
            <strong><?php esc_html_e('Severidad:', 'spectrus-guard'); ?></strong>
            <label><input type="checkbox" class="sg-filter-sev" value="critical" checked> <?php esc_html_e('CRITICAL', 'spectrus-guard'); ?></label>
            <label><input type="checkbox" class="sg-filter-sev" value="high" checked> <?php esc_html_e('HIGH', 'spectrus-guard'); ?></label>
            <label><input type="checkbox" class="sg-filter-sev" value="medium" checked> <?php esc_html_e('MEDIUM', 'spectrus-guard'); ?></label>
            <label><input type="checkbox" class="sg-filter-sev" value="low" checked> <?php esc_html_e('LOW', 'spectrus-guard'); ?></label>
            <label><input type="checkbox" class="sg-filter-sev" value="info" checked> <?php esc_html_e('INFO', 'spectrus-guard'); ?></label>
        </div>

        <div class="sg-filter-group">
            <label>
                <input type="checkbox" id="sg-toggle-suppressed">
                <?php esc_html_e('Mostrar suprimidas', 'spectrus-guard'); ?>
            </label>
        </div>
    </div>

    <?php if (empty($threats)): ?>
        <div class="sg-scanner-empty">
            <span class="dashicons dashicons-yes-alt" aria-hidden="true"></span>
            <strong><?php esc_html_e('No se encontraron amenazas.', 'spectrus-guard'); ?></strong>
        </div>
    <?php else: ?>
        <div class="sg-table-wrapper">
            <table class="widefat fixed striped" id="sg-threat-table">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Severidad', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Archivo', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Tipo', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Descripción', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Línea', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Contexto', 'spectrus-guard'); ?></th>
                        <th><?php esc_html_e('Acciones', 'spectrus-guard'); ?></th>
                    </tr>
                </thead>
                <tbody id="sg-threat-tbody">
                    <?php foreach ($threats as $threat): ?>
                        <?php
                        $file = isset($threat['file']) ? (string) $threat['file'] : '';
                        $type = isset($threat['type']) ? (string) $threat['type'] : '';
                        $type_label = isset($threat['type_label']) ? (string) $threat['type_label'] : $type;
                        $description = isset($threat['description']) ? (string) $threat['description'] : '';
                        $severity = isset($threat['severity']) ? strtolower((string) $threat['severity']) : '';
                        $line = isset($threat['line']) ? (int) $threat['line'] : 0;
                        $context = isset($threat['context']) ? (string) $threat['context'] : '';
                        $score = isset($threat['score']) ? (int) $threat['score'] : 0;
                        $hash = isset($threat['hash']) ? (string) $threat['hash'] : '';
                        $is_suppressed = !empty($threat['suppressed']);
                        $row_class = $is_suppressed ? 'sg-threat-suppressed' : '';
                        ?>
                        <tr class="<?php echo esc_attr($row_class); ?>" data-severity="<?php echo esc_attr($severity); ?>" data-suppressed="<?php echo esc_attr($is_suppressed ? '1' : '0'); ?>" data-score="<?php echo esc_attr((string) $score); ?>">
                            <td><span class="<?php echo esc_attr('sg-badge sg-badge-' . $severity); ?>"><?php echo esc_html(strtoupper($severity)); ?></span></td>
                            <td><?php echo esc_html($file); ?></td>
                            <td><?php echo esc_html($type_label); ?></td>
                            <td><?php echo esc_html($description); ?></td>
                            <td><?php echo esc_html((string) $line); ?></td>
                            <td>
                                <?php if ($context !== ''): ?>
                                    <code><?php echo esc_html($context); ?></code>
                                <?php endif; ?>
                            </td>
                            <td>
                                <button type="button" class="button button-small sg-suppress-btn"
                                    data-file="<?php echo esc_attr($file); ?>"
                                    data-type="<?php echo esc_attr($type); ?>"
                                    data-line="<?php echo esc_attr((string) $line); ?>"
                                    data-hash="<?php echo esc_attr($hash); ?>"
                                    data-suppressed="<?php echo esc_attr($is_suppressed ? '1' : '0'); ?>">
                                    <?php echo esc_html($is_suppressed ? __('Restaurar', 'spectrus-guard') : __('Suprimir', 'spectrus-guard')); ?>
                                </button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="sg-pagination">
            <button type="button" class="button" id="sg-prev-page"><?php esc_html_e('Anterior', 'spectrus-guard'); ?></button>
            <span id="sg-page-info"></span>
            <button type="button" class="button" id="sg-next-page"><?php esc_html_e('Siguiente', 'spectrus-guard'); ?></button>
        </div>
    <?php endif; ?>
</div>
