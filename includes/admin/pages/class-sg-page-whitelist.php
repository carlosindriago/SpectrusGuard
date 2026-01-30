<?php
/**
 * Page Controller: Whitelist Management
 *
 * Handles the whitelist page functionality including listing,
 * and removing whitelisted files.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class SG_Page_Whitelist
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
        $this->register_ajax_handlers();
    }

    /**
     * Register AJAX handlers
     */
    private function register_ajax_handlers()
    {
        // Handlers are already registered in SG_Page_Scanner
        // This is just for reference
    }

    /**
     * Render the whitelist page
     */
    public function render()
    {
        // Load view template
        $this->render_view('scanner/whitelist.php');
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
