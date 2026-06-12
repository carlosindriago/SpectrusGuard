<?php
use PHPUnit\Framework\TestCase;

class SG_Phase5_Test_Json_Response extends Exception
{
    public $success;
    public $data;
    public $status;

    public function __construct(bool $success, array $data, int $status)
    {
        parent::__construct('json_response');
        $this->success = $success;
        $this->data = $data;
        $this->status = $status;
    }
}

if (!function_exists('__')) {
    function __($text, $domain = null)
    {
        return $text;
    }
}

if (!function_exists('check_ajax_referer')) {
    function check_ajax_referer($action, $query_arg = false, $die = true)
    {
        return true;
    }
}

if (!function_exists('current_user_can')) {
    function current_user_can($capability)
    {
        return true;
    }
}

if (!function_exists('get_current_user_id')) {
    function get_current_user_id()
    {
        return isset($GLOBALS['sg_phase5_current_user_id']) ? (int) $GLOBALS['sg_phase5_current_user_id'] : 123;
    }
}

if (!function_exists('wp_send_json_error')) {
    function wp_send_json_error($data = null, $status_code = null)
    {
        $payload = is_array($data) ? $data : array();
        $status = is_int($status_code) ? $status_code : 400;
        throw new SG_Phase5_Test_Json_Response(false, $payload, $status);
    }
}

if (!function_exists('wp_send_json_success')) {
    function wp_send_json_success($data = null, $status_code = null)
    {
        $payload = is_array($data) ? $data : array();
        $status = is_int($status_code) ? $status_code : 200;
        throw new SG_Phase5_Test_Json_Response(true, $payload, $status);
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

if (!function_exists('sanitize_textarea_field')) {
    function sanitize_textarea_field($text)
    {
        $text = (string) $text;
        $text = preg_replace('/<[^>]*>/', '', $text);
        $text = preg_replace('/\s+/', ' ', trim($text));
        return $text;
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

if (!function_exists('normalize_file_path')) {
    function normalize_file_path($path)
    {
        return str_replace('\\', '/', (string) $path);
    }
}

if (!function_exists('trailingslashit')) {
    function trailingslashit($path)
    {
        return rtrim((string) $path, '/\\') . '/';
    }
}

if (!function_exists('get_transient')) {
    function get_transient($key)
    {
        return isset($GLOBALS['sg_test_transients'][$key]) ? $GLOBALS['sg_test_transients'][$key] : false;
    }
}

if (!function_exists('set_transient')) {
    function set_transient($key, $value, $expiration = 0)
    {
        $GLOBALS['sg_test_transients'][$key] = $value;
        return true;
    }
}

if (!function_exists('delete_transient')) {
    function delete_transient($key)
    {
        unset($GLOBALS['sg_test_transients'][$key]);
        return true;
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
        return array_key_exists($option, $GLOBALS['sg_test_options']) ? $GLOBALS['sg_test_options'][$option] : $default;
    }
}

if (!function_exists('delete_option')) {
    function delete_option($option)
    {
        unset($GLOBALS['sg_test_options'][$option]);
        return true;
    }
}

if (!function_exists('current_time')) {
    function current_time($type)
    {
        if ($type === 'timestamp') {
            return time();
        }

        if ($type === 'mysql') {
            return gmdate('Y-m-d H:i:s');
        }

        return '';
    }
}

if (!function_exists('sg_get_malware_signatures')) {
    function sg_get_malware_signatures()
    {
        return array();
    }
}

if (!function_exists('wp_next_scheduled')) {
    function wp_next_scheduled($hook)
    {
        return false;
    }
}

if (!function_exists('wp_schedule_event')) {
    function wp_schedule_event($timestamp, $recurrence, $hook)
    {
        return true;
    }
}

if (!class_exists('SG_Trusted_Paths')) {
    class SG_Trusted_Paths
    {
        public static function get_php_files_in_directory($dir, $limit = 5000)
        {
            if (!is_dir($dir)) {
                return array();
            }

            $files = array();
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
            foreach ($iterator as $item) {
                if ($item->isFile() && strtolower($item->getExtension()) === 'php') {
                    $files[] = $item->getPathname();
                }

                if (count($files) >= $limit) {
                    break;
                }
            }

            return $files;
        }

        public static function is_vendor_path($file_path)
        {
            return strpos((string) $file_path, '/vendor/') !== false;
        }
    }
}

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class SG_Phase5_SecurityTest extends TestCase
{
    private static $test_abspath;
    private static $test_wp_content_dir;

    public static function setUpBeforeClass(): void
    {
        self::$test_abspath = sys_get_temp_dir() . '/spectrusguard-phase5/';
        self::$test_wp_content_dir = self::$test_abspath . 'wp-content';

        if (!defined('ABSPATH')) {
            define('ABSPATH', self::$test_abspath);
        }

        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }

        if (!defined('DAY_IN_SECONDS')) {
            define('DAY_IN_SECONDS', 86400);
        }

        if (!defined('WP_CONTENT_DIR')) {
            define('WP_CONTENT_DIR', self::$test_wp_content_dir);
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
        $GLOBALS['sg_test_transients'] = array();
        $GLOBALS['sg_phase5_current_user_id'] = 123;

        $_POST = array(
            'nonce' => 'x',
        );

        $this->reset_test_filesystem();
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-scanner.php';
    }

    public function test_suppress_rejects_path_traversal(): void
    {
        $scanner = $this->new_scanner_without_constructor();

        $_POST['file'] = '../../../../etc/passwd';
        $_POST['type'] = 'csrf';
        $_POST['line'] = 10;

        try {
            $scanner->handle_ajax_suppress_threat();
            $this->fail('Expected JSON error response');
        } catch (SG_Phase5_Test_Json_Response $response) {
            $this->assertFalse($response->success);
            $this->assertSame(400, $response->status);
            $this->assertSame('Invalid file path.', $response->data['message']);
        }
    }

    public function test_suppress_rejects_path_outside_abspath(): void
    {
        $scanner = $this->new_scanner_without_constructor();

        $_POST['file'] = '../../etc/hosts';
        $_POST['type'] = 'sql_injection';
        $_POST['line'] = 20;

        try {
            $scanner->handle_ajax_suppress_threat();
            $this->fail('Expected JSON error response');
        } catch (SG_Phase5_Test_Json_Response $response) {
            $this->assertFalse($response->success);
            $this->assertSame(400, $response->status);
            $this->assertSame('Invalid file path.', $response->data['message']);
        }
    }

    public function test_is_path_within_dir_returns_false_for_nonexistent(): void
    {
        $scanner = $this->new_scanner_without_constructor();
        $method = new ReflectionMethod('SG_Scanner', 'is_path_within_dir');
        $method->setAccessible(true);

        $result = $method->invoke($scanner, WP_CONTENT_DIR . '/plugins/missing.php', WP_CONTENT_DIR . '/plugins');

        $this->assertFalse($result);
    }

    public function test_is_path_within_dir_returns_true_for_valid_path(): void
    {
        $scanner = $this->new_scanner_without_constructor();
        $method = new ReflectionMethod('SG_Scanner', 'is_path_within_dir');
        $method->setAccessible(true);

        $base_dir = WP_CONTENT_DIR . '/plugins/phase5-plugin';
        $file_path = $base_dir . '/safe.php';
        $this->write_file($file_path, "<?php\nreturn true;\n");

        $result = $method->invoke($scanner, $file_path, $base_dir);

        $this->assertTrue($result);
    }

    public function test_transient_results_have_sanitized_context(): void
    {
        $scanner = $this->new_scanner_without_constructor();
        $fixture_path = WP_CONTENT_DIR . '/plugins/phase5-plugin/sample.php';
        $this->write_file($fixture_path, "<?php\nreturn true;\n");

        $this->set_scanner_property($scanner, 'checksum', new class {
            public function verify_core_files()
            {
                return array();
            }
        });

        $this->set_scanner_property($scanner, 'heuristics', new class {
            public function scan_uploads_for_php()
            {
                return array();
            }
            public function scan_hidden_files()
            {
                return array();
            }
            public function scan_dangerous_permissions()
            {
                return array();
            }
            public function scan_for_signatures($dir, $signatures)
            {
                return array();
            }
        });

        $this->set_scanner_property($scanner, 'advanced_detector', new class {
            public function scan_file($file)
            {
                return array(
                    array(
                        'file' => 'wp-content/plugins/phase5-plugin/sample.php',
                        'type' => 'csrf',
                        'severity' => 'high',
                        'description' => 'Potential CSRF',
                        'line' => 12,
                        'score' => 40,
                        'context' => "<strong>alert(1)</strong>\n next",
                    ),
                );
            }
        });

        $this->set_scanner_property($scanner, 'whitelist', null);

        $scanner->run_full_scan(true);

        $transient = get_transient(SG_Scanner::RESULTS_TRANSIENT);
        $this->assertIsArray($transient);
        $this->assertSame('alert(1) next', $transient['advanced_threats'][0]['context']);
        $this->assertStringNotContainsString('<strong>', $transient['advanced_threats'][0]['context']);
    }

    public function test_ajax_run_scan_rejects_user_id_zero(): void
    {
        $GLOBALS['sg_phase5_current_user_id'] = 0;

        $scanner = new class extends SG_Scanner {
            public $run_called = false;

            public function __construct()
            {
            }

            public function run_full_scan($force_fresh = false)
            {
                $this->run_called = true;
                return array();
            }
        };

        try {
            $scanner->handle_ajax_run_scan();
            $this->fail('Expected JSON error response');
        } catch (SG_Phase5_Test_Json_Response $response) {
            $this->assertFalse($response->success);
            $this->assertSame(403, $response->status);
            $this->assertSame('Unauthorized', $response->data['message']);
        }

        $this->assertFalse($scanner->run_called);
    }

    private function new_scanner_without_constructor(): SG_Scanner
    {
        $reflection = new ReflectionClass('SG_Scanner');
        return $reflection->newInstanceWithoutConstructor();
    }

    private function set_scanner_property(SG_Scanner $scanner, string $property, $value): void
    {
        $reflection = new ReflectionObject($scanner);
        $ref_property = $reflection->getProperty($property);
        $ref_property->setAccessible(true);
        $ref_property->setValue($scanner, $value);
    }

    private function reset_test_filesystem(): void
    {
        $this->remove_dir(self::$test_abspath);

        $directories = array(
            self::$test_abspath,
            WP_CONTENT_DIR,
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads',
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
        }
    }

    private function write_file(string $file_path, string $contents): void
    {
        $directory = dirname($file_path);
        if (!is_dir($directory)) {
            mkdir($directory, 0777, true);
        }

        file_put_contents($file_path, $contents);
    }

    private function remove_dir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        if ($items === false) {
            return;
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }

            $path = $dir . $item;
            if (is_dir($path)) {
                $this->remove_dir(trailingslashit($path));
                continue;
            }

            unlink($path);
        }

        rmdir(rtrim($dir, '/\\'));
    }
}
