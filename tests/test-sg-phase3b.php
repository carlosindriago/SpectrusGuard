<?php
use PHPUnit\Framework\TestCase;

if (!function_exists('__')) {
    function __($text, $domain = null)
    {
        return $text;
    }
}

if (!function_exists('esc_html__')) {
    function esc_html__($text, $domain = null)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_html_e')) {
    function esc_html_e($text, $domain = null)
    {
        echo esc_html__($text, $domain);
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_attr')) {
    function esc_attr($text)
    {
        return htmlspecialchars((string) $text, ENT_QUOTES, 'UTF-8');
    }
}

if (!function_exists('esc_url')) {
    function esc_url($text)
    {
        return (string) $text;
    }
}

if (!function_exists('wp_kses')) {
    function wp_kses($html, $allowed_html = array())
    {
        return (string) $html;
    }
}

if (!function_exists('admin_url')) {
    function admin_url($path = '')
    {
        return 'admin.php' . ($path ? '?' . ltrim($path, '?') : '');
    }
}

if (!function_exists('wp_date')) {
    function wp_date($format, $timestamp = null)
    {
        $ts = $timestamp ? (int) $timestamp : time();
        return date($format, $ts);
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability)
    {
        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action($hook, $callback)
    {
        return true;
    }
}

if (!class_exists('SG_Loader')) {
    class SG_Loader
    {
        private $scanner;

        public function __construct($scanner)
        {
            $this->scanner = $scanner;
        }

        public function get_scanner()
        {
            return $this->scanner;
        }
    }
}

class Test_SG_Phase3B extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!defined('ABSPATH')) {
            define('ABSPATH', sys_get_temp_dir() . '/');
        }

        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }

        if (!defined('SG_PLUGIN_URL')) {
            define('SG_PLUGIN_URL', 'http://example.test/wp-content/plugins/spectrusguard/');
        }

        if (!defined('SG_VERSION')) {
            define('SG_VERSION', '0.0.0-test');
        }
    }

    public function test_threat_type_to_label_mapping(): void
    {
        require_once dirname(__DIR__) . '/includes/admin/pages/class-sg-page-scanner.php';

        $ref = new ReflectionClass('SG_Page_Scanner');
        $instance = $ref->newInstanceWithoutConstructor();

        $method = $ref->getMethod('threat_type_to_label');
        $method->setAccessible(true);

        $this->assertSame('SQL Injection', $method->invoke($instance, 'sql_injection'));
        $this->assertSame('CSRF', $method->invoke($instance, 'csrf'));
        $this->assertSame('LFI', $method->invoke($instance, 'lfi'));
        $this->assertSame('Ofuscación', $method->invoke($instance, 'obfuscation'));
        $this->assertSame('Custom Type', $method->invoke($instance, 'custom_type'));
    }

    public function test_widget_renders_without_scan_data(): void
    {
        require_once dirname(__DIR__) . '/includes/admin/class-sg-dashboard-widget.php';

        $scanner = new class {
            public function get_scan_results(): array
            {
                return array();
            }
        };

        $widget = new SG_Dashboard_Widget(new SG_Loader($scanner));

        ob_start();
        $widget->render();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString('Aún no se ha ejecutado un scan.', $html);
        $this->assertStringContainsString('Ir al Scanner →', $html);
    }

    public function test_widget_renders_with_scan_data(): void
    {
        require_once dirname(__DIR__) . '/includes/admin/class-sg-dashboard-widget.php';

        $scanner = new class {
            public function get_scan_results(): array
            {
                return array(
                    'timestamp' => 1710000000,
                    'summary' => array(
                        'critical' => 2,
                        'high' => 3,
                        'medium' => 2,
                        'low' => 0,
                        'info' => 1,
                    ),
                );
            }
        };

        $widget = new SG_Dashboard_Widget(new SG_Loader($scanner));

        ob_start();
        $widget->render();
        $html = (string) ob_get_clean();

        $this->assertStringContainsString('CRITICAL: 2', $html);
        $this->assertStringContainsString('HIGH: 3', $html);
        $this->assertStringContainsString('MEDIUM: 2', $html);
        $this->assertStringContainsString('LOW: 0', $html);
        $this->assertStringContainsString('INFO: 1', $html);
    }

    public function test_scanner_page_escapes_file_paths(): void
    {
        $scan = array(
            'timestamp' => 1710000000,
            'total_files' => 10,
            'total_threats' => 1,
            'summary' => array(
                'critical' => 1,
                'high' => 0,
                'medium' => 0,
                'low' => 0,
                'info' => 0,
            ),
        );

        $threats = array(
            array(
                'file' => 'wp-content/plugins/<script>alert(1)</script>.php',
                'type' => 'csrf',
                'type_label' => 'CSRF',
                'severity' => 'high',
                'description' => 'x',
                'line' => 7,
                'score' => 50,
                'hash' => md5('x'),
                'suppressed' => false,
                'context' => 'do_action("init");',
            ),
        );

        $suppressed_hashes = array();

        ob_start();
        require dirname(__DIR__) . '/includes/admin/views/scanner/page.php';
        $html = (string) ob_get_clean();

        $this->assertStringNotContainsString('<script>alert(1)</script>', $html);
        $this->assertStringContainsString('&lt;script&gt;alert(1)&lt;/script&gt;', $html);
    }
}

