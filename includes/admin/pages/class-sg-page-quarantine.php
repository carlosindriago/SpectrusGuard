<?php
/**
 * Page Controller: Quarantine Vault
 *
 * Handles the quarantine page functionality including listing,
 * restoring, and permanently deleting quarantined files.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Quarantine
{
    /**
     * @var SG_Loader Plugin loader instance
     */
    private $loader;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Plugin loader instance
     */
    public function __construct($loader)
    {
        $this->loader = $loader;
    }

    /**
     * Render the quarantine page
     */
    public function render()
    {
        // Load view template
        $this->render_view('scanner/quarantine.php');
    }

    /**
     * Render a view template with data
     *
     * @param string $template Template file name relative to views directory
     * @param array  $data     Data to pass to the template
     */
    private function render_view($template, $data = array())
    {
        $view_file = SG_PLUGIN_DIR . 'includes/admin/views/' . $template;

        if (!file_exists($view_file)) {
            wp_die(__('View file not found: ', 'spectrus-guard') . esc_html($template));
        }

        // Extract data variables for use in template
        extract($data, EXTR_SKIP);

        // Load template
        include $view_file;
    }
}
