<?php
use PHPUnit\Framework\TestCase;

class SG_Test_Json_Response extends Exception
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
        return 123;
    }
}

if (!function_exists('wp_send_json_error')) {
    function wp_send_json_error($data = null, $status_code = null)
    {
        $payload = is_array($data) ? $data : array();
        $status = is_int($status_code) ? $status_code : 400;
        throw new SG_Test_Json_Response(false, $payload, $status);
    }
}

if (!function_exists('wp_send_json_success')) {
    function wp_send_json_success($data = null, $status_code = null)
    {
        $payload = is_array($data) ? $data : array();
        $status = is_int($status_code) ? $status_code : 200;
        throw new SG_Test_Json_Response(true, $payload, $status);
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
        if (!isset($GLOBALS['sg_test_update_option_calls'][$option])) {
            $GLOBALS['sg_test_update_option_calls'][$option] = 0;
        }
        $GLOBALS['sg_test_update_option_calls'][$option]++;

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

if (!function_exists('wp_clear_scheduled_hook')) {
    function wp_clear_scheduled_hook($hook)
    {
        return true;
    }
}

if (!function_exists('flush_rewrite_rules')) {
    function flush_rewrite_rules()
    {
        return true;
    }
}

if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file)
    {
        return dirname($file) . '/';
    }
}

if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file)
    {
        return 'http://example.test/wp-content/plugins/spectrus-guard/';
    }
}

if (!function_exists('plugin_basename')) {
    function plugin_basename($file)
    {
        return basename($file);
    }
}

if (!function_exists('register_activation_hook')) {
    function register_activation_hook($file, $callback)
    {
        return true;
    }
}

if (!function_exists('register_deactivation_hook')) {
    function register_deactivation_hook($file, $callback)
    {
        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action($hook, $callback, $priority = 10, $accepted_args = 1)
    {
        return true;
    }
}

if (!function_exists('add_filter')) {
    function add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
    {
        return true;
    }
}

class Test_SG_Phase4 extends TestCase
{
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

        if (!defined('WP_CONTENT_DIR')) {
            define('WP_CONTENT_DIR', sys_get_temp_dir() . '/sg_wp_content_missing');
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
        $GLOBALS['sg_test_update_option_calls'] = array();

        $_POST = array(
            'nonce' => 'x',
        );
    }

    public function test_ajax_run_scan_respects_cooldown(): void
    {
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-scanner.php';

        $scanner = new class extends SG_Scanner {
            public $run_calls = 0;

            public function run_full_scan($force_fresh = false)
            {
                $this->run_calls++;
                update_option('sg_last_scan_results', array(
                    'timestamp' => time(),
                    'total_files' => 0,
                    'total_threats' => 0,
                    'threats' => array(),
                    'summary' => array(
                        'critical' => 0,
                        'high' => 0,
                        'medium' => 0,
                        'low' => 0,
                        'info' => 0,
                    ),
                ), false);
                return array();
            }
        };

        try {
            $scanner->handle_ajax_run_scan();
            $this->fail('Expected JSON response');
        } catch (SG_Test_Json_Response $res) {
            $this->assertTrue($res->success);
            $this->assertSame(200, $res->status);
        }

        try {
            $scanner->handle_ajax_run_scan();
            $this->fail('Expected JSON response');
        } catch (SG_Test_Json_Response $res) {
            $this->assertFalse($res->success);
            $this->assertSame(429, $res->status);
            $this->assertSame(60, $res->data['retry_after']);
        }

        $this->assertSame(1, $scanner->run_calls);
    }

    public function test_suppress_threat_rejects_invalid_type(): void
    {
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-scanner.php';

        $reflection = new ReflectionClass('SG_Scanner');
        $scanner = $reflection->newInstanceWithoutConstructor();

        $_POST['file'] = 'wp-content/plugins/test.php';
        $_POST['type'] = 'not_allowed';
        $_POST['line'] = 12;

        try {
            $scanner->handle_ajax_suppress_threat();
            $this->fail('Expected JSON response');
        } catch (SG_Test_Json_Response $res) {
            $this->assertFalse($res->success);
            $this->assertSame(400, $res->status);
            $this->assertSame('Invalid threat type.', $res->data['message']);
        }
    }

    public function test_deactivation_cleans_phase3_options(): void
    {
        require_once dirname(__DIR__) . '/spectrus-guard.php';

        update_option('sg_last_scan_results', array('x' => 1), false);
        update_option('sg_suppressed_threats', array('y'), false);

        sg_deactivate();

        $this->assertFalse(get_option('sg_last_scan_results', false));
        $this->assertFalse(get_option('sg_suppressed_threats', false));
    }

    public function test_double_save_does_not_occur(): void
    {
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-scanner.php';

        $reflection = new ReflectionClass('SG_Scanner');
        $scanner = $reflection->newInstanceWithoutConstructor();

        $scanner_ref = new ReflectionObject($scanner);

        $checksum_prop = $scanner_ref->getProperty('checksum');
        $checksum_prop->setAccessible(true);
        $checksum_prop->setValue($scanner, new class {
            public function verify_core_files()
            {
                return array();
            }
        });

        $heuristics_prop = $scanner_ref->getProperty('heuristics');
        $heuristics_prop->setAccessible(true);
        $heuristics_prop->setValue($scanner, new class {
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

        $adv_prop = $scanner_ref->getProperty('advanced_detector');
        $adv_prop->setAccessible(true);
        $adv_prop->setValue($scanner, new class {
            public function scan_file($file)
            {
                return array();
            }
        });

        $whitelist_prop = $scanner_ref->getProperty('whitelist');
        $whitelist_prop->setAccessible(true);
        $whitelist_prop->setValue($scanner, null);

        $scanner->run_full_scan(true);

        $calls = isset($GLOBALS['sg_test_update_option_calls']['sg_last_scan_results']) ? (int) $GLOBALS['sg_test_update_option_calls']['sg_last_scan_results'] : 0;
        $this->assertSame(1, $calls);
    }
}

