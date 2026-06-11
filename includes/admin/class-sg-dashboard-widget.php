<?php
/**
 * SpectrusGuard Dashboard Widget
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

defined('ABSPATH') || exit;

class SG_Dashboard_Widget
{
    /**
     * Loader instance.
     *
     * @var SG_Loader
     */
    private $loader;

    /**
     * Constructor.
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct(SG_Loader $loader)
    {
        $this->loader = $loader;
        add_action('wp_dashboard_setup', array($this, 'register_widget'));
    }

    /**
     * Register the dashboard widget.
     *
     * @return void
     */
    public function register_widget(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            'sg_security_summary',
            esc_html__('SpectrusGuard Security Summary', 'spectrus-guard'),
            array($this, 'render')
        );
    }

    /**
     * Render widget HTML.
     *
     * @return void
     */
    public function render(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $scanner = $this->loader->get_scanner();
        $saved = $scanner && method_exists($scanner, 'get_scan_results') ? $scanner->get_scan_results() : array();

        if (empty($saved) || empty($saved['timestamp'])) {
            $this->render_empty_state();
            return;
        }

        $this->render_summary($saved);
    }

    /**
     * Render empty state widget.
     *
     * @return void
     */
    private function render_empty_state(): void
    {
        $url = admin_url('admin.php?page=spectrus-guard-scanner');

        $html = sprintf(
            '<p>%s</p><p><a href="%s" class="button button-primary">%s</a></p>',
            esc_html__('Aún no se ha ejecutado un scan.', 'spectrus-guard'),
            esc_url($url),
            esc_html__('Ir al Scanner →', 'spectrus-guard')
        );

        echo wp_kses($html, $this->get_widget_allowlist());
    }

    /**
     * Render summary widget.
     *
     * @param array $saved Saved scan data.
     * @return void
     */
    private function render_summary(array $saved): void
    {
        $timestamp = isset($saved['timestamp']) ? (int) $saved['timestamp'] : 0;
        $summary = isset($saved['summary']) && is_array($saved['summary']) ? $saved['summary'] : array();

        $badges = array(
            'critical' => array('label' => 'CRITICAL', 'color' => '#dc3545'),
            'high' => array('label' => 'HIGH', 'color' => '#fd7e14'),
            'medium' => array('label' => 'MEDIUM', 'color' => '#ffc107'),
            'low' => array('label' => 'LOW', 'color' => '#0d6efd'),
            'info' => array('label' => 'INFO', 'color' => '#6c757d'),
        );

        $items = '';
        foreach ($badges as $key => $badge) {
            $count = isset($summary[$key]) ? (int) $summary[$key] : 0;
            $items .= sprintf(
                '<span class="sg-badge" style="display:inline-block;margin:2px 6px 2px 0;padding:2px 8px;border-radius:999px;background:%s;color:#fff;font-weight:600;">%s: %d</span>',
                esc_attr($badge['color']),
                esc_html($badge['label']),
                $count
            );
        }

        $url = admin_url('admin.php?page=spectrus-guard-scanner');
        $html = sprintf(
            '<p><strong>%s</strong> %s</p><p>%s</p><p><a href="%s">%s</a></p>',
            esc_html__('Último scan:', 'spectrus-guard'),
            esc_html(wp_date('d/m/Y H:i', $timestamp)),
            $items,
            esc_url($url),
            esc_html__('Ver detalles →', 'spectrus-guard')
        );

        echo wp_kses($html, $this->get_widget_allowlist());
    }

    /**
     * Return a strict allowlist for widget output.
     *
     * @return array Allowlist.
     */
    private function get_widget_allowlist(): array
    {
        return array(
            'span' => array(
                'class' => true,
                'style' => true,
            ),
            'a' => array(
                'class' => true,
                'href' => true,
                'style' => true,
            ),
            'strong' => array(),
            'p' => array(),
        );
    }
}

