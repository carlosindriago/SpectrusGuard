<?php
use PHPUnit\Framework\TestCase;

if (!function_exists('__')) {
    function __($text, $domain = null)
    {
        return $text;
    }
}

if (!function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field($text)
    {
        $text = (string) $text;
        $text = preg_replace('/<[^>]*>/', '', $text);
        $text = preg_replace('/\s+/', ' ', trim($text));
        return $text;
    }
}

if (!function_exists('sanitize_text_field')) {
    function sanitize_text_field($text)
    {
        $text = (string) $text;
        $text = preg_replace('/<[^>]*>/', '', $text);
        return trim($text);
    }
}

if (!function_exists('wp_unslash')) {
    function wp_unslash($text)
    {
        return $text;
    }
}

if (!function_exists('absint')) {
    function absint($value)
    {
        return abs((int) $value);
    }
}

if (!function_exists('update_option')) {
    function update_option($option, $value, $autoload = null)
    {
        $GLOBALS['sg_test_options'][$option] = $value;
        return true;
    }
}

if (!function_exists('get_option')) {
    function get_option($option, $default = false)
    {
        return isset($GLOBALS['sg_test_options'][$option]) ? $GLOBALS['sg_test_options'][$option] : $default;
    }
}

class Test_SG_Phase3A extends TestCase
{
    private $scanner;

    public static function setUpBeforeClass(): void
    {
        if (!defined('ABSPATH')) {
            define('ABSPATH', sys_get_temp_dir() . '/');
        }

        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }

        if (!defined('DAY_IN_SECONDS')) {
            define('DAY_IN_SECONDS', 86400);
        }

        if (!defined('SG_SEV_CRITICAL')) {
            define('SG_SEV_CRITICAL', 'critical');
            define('SG_SEV_HIGH', 'high');
            define('SG_SEV_MEDIUM', 'medium');
            define('SG_SEV_LOW', 'low');
            define('SG_SEV_INFO', 'info');
        }
    }

    protected function setUp(): void
    {
        $GLOBALS['sg_test_options'] = array();
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-scanner.php';

        $reflection = new ReflectionClass('SG_Scanner');
        $this->scanner = $reflection->newInstanceWithoutConstructor();
    }

    public function test_save_results_truncates_at_500(): void
    {
        $threats = array();
        for ($i = 1; $i <= 600; $i++) {
            $threats[] = array(
                'file' => 'wp-content/plugins/p' . $i . '.php',
                'type' => 'sql_injection',
                'severity' => SG_SEV_HIGH,
                'description' => 'x',
                'line' => 1,
                'score' => $i,
            );
        }

        $this->scanner->save_scan_results(array('advanced_total_files' => 999, 'advanced_threats' => $threats), 123);
        $saved = $this->scanner->get_scan_results();

        $this->assertSame(500, $saved['total_threats']);
        $this->assertSame(999, $saved['total_files']);
        $this->assertSame(600, $saved['threats'][0]['score']);
        $this->assertSame(101, $saved['threats'][499]['score']);
    }

    public function test_save_results_sanitizes_context(): void
    {
        $threats = array(
            array(
                'file' => 'wp-content/plugins/test.php',
                'type' => 'csrf',
                'severity' => SG_SEV_HIGH,
                'description' => 'x',
                'line' => 2,
                'score' => 55,
                'context' => "<b>hello</b>\nworld",
            ),
        );

        $this->scanner->save_scan_results(array('advanced_threats' => $threats), 123);
        $saved = $this->scanner->get_scan_results();

        $this->assertSame('hello world', $saved['threats'][0]['context']);
    }

    public function test_get_results_returns_empty_array_when_missing(): void
    {
        $saved = $this->scanner->get_scan_results();
        $this->assertSame(array(), $saved);
    }

    public function test_summary_counts_are_correct(): void
    {
        $threats = array(
            array('file' => 'a.php', 'type' => 'x', 'severity' => SG_SEV_CRITICAL, 'description' => 'x', 'line' => 1, 'score' => 50),
            array('file' => 'b.php', 'type' => 'x', 'severity' => SG_SEV_HIGH, 'description' => 'x', 'line' => 1, 'score' => 50),
            array('file' => 'c.php', 'type' => 'x', 'severity' => SG_SEV_MEDIUM, 'description' => 'x', 'line' => 1, 'score' => 50),
            array('file' => 'd.php', 'type' => 'x', 'severity' => SG_SEV_LOW, 'description' => 'x', 'line' => 1, 'score' => 50),
            array('file' => 'e.php', 'type' => 'x', 'severity' => SG_SEV_INFO, 'description' => 'x', 'line' => 1, 'score' => 50),
            array('file' => 'f.php', 'type' => 'x', 'severity' => SG_SEV_INFO, 'description' => 'x', 'line' => 1, 'score' => 50),
        );

        $this->scanner->save_scan_results(array('advanced_threats' => $threats), 123);
        $saved = $this->scanner->get_scan_results();

        $this->assertSame(1, $saved['summary']['critical']);
        $this->assertSame(1, $saved['summary']['high']);
        $this->assertSame(1, $saved['summary']['medium']);
        $this->assertSame(1, $saved['summary']['low']);
        $this->assertSame(2, $saved['summary']['info']);
    }

    public function test_suppress_hash_is_deterministic(): void
    {
        $threat = array('file' => 'wp-content/plugins/x.php', 'type' => 'csrf', 'line' => 7);

        $reflection = new ReflectionClass('SG_Scanner');
        $method = $reflection->getMethod('compute_threat_hash');
        $method->setAccessible(true);

        $hash_a = $method->invoke($this->scanner, $threat);
        $hash_b = $method->invoke($this->scanner, $threat);

        $this->assertSame($hash_a, $hash_b);
        $this->assertSame(md5('wp-content/plugins/x.php|csrf|7'), $hash_a);
    }

    public function test_suppressed_list_max_200_fifo(): void
    {
        $reflection = new ReflectionClass('SG_Scanner');
        $add_method = $reflection->getMethod('add_suppressed_hash');
        $add_method->setAccessible(true);

        $hashes = array();
        for ($i = 1; $i <= 205; $i++) {
            $hashes[] = md5('f' . $i);
            $add_method->invoke($this->scanner, md5('f' . $i));
        }

        $saved = $this->scanner->get_suppressed_hashes();

        $this->assertSame(200, count($saved));
        $this->assertSame($hashes[5], $saved[0]);
        $this->assertSame($hashes[204], $saved[199]);
    }
}

