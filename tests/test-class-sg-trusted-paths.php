<?php
use PHPUnit\Framework\TestCase;

class Test_SG_Trusted_Paths extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!defined('ABSPATH')) {
            define('ABSPATH', sys_get_temp_dir() . '/');
        }
        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-trusted-paths.php';
    }

    public function test_is_vendor_path()
    {
        $this->assertTrue(SG_Trusted_Paths::is_vendor_path('/var/www/wp-content/plugins/myplugin/vendor/autoload.php'));
        $this->assertTrue(SG_Trusted_Paths::is_vendor_path('/var/www/wp-content/plugins/myplugin/node_modules/package/index.js'));
        $this->assertTrue(SG_Trusted_Paths::is_vendor_path('/var/www/wp-includes/class-wp-query.php'));
        $this->assertFalse(SG_Trusted_Paths::is_vendor_path('/var/www/wp-content/plugins/myplugin/includes/class-myplugin.php'));
    }

    public function test_is_known_plugin()
    {
        $this->assertTrue(SG_Trusted_Paths::is_known_plugin('/var/www/wp-content/plugins/woocommerce/woocommerce.php'));
        $this->assertTrue(SG_Trusted_Paths::is_known_plugin('/var/www/wp-content/plugins/elementor/elementor.php'));
        $this->assertFalse(SG_Trusted_Paths::is_known_plugin('/var/www/wp-content/plugins/unknown-plugin/plugin.php'));
    }
}
