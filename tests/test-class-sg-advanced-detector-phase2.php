<?php
use PHPUnit\Framework\TestCase;

class Test_SG_Advanced_Detector_Phase2 extends TestCase
{
    private $detector;

    public static function setUpBeforeClass(): void
    {
        if (!defined('ABSPATH')) {
            define('ABSPATH', sys_get_temp_dir() . '/spectrusguard-tests/');
        }

        if (!defined('WP_CONTENT_DIR')) {
            define('WP_CONTENT_DIR', ABSPATH . 'wp-content');
        }

        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }

        if (!defined('SG_SEV_CRITICAL')) {
            define('SG_SEV_CRITICAL', 'critical');
            define('SG_SEV_HIGH', 'high');
            define('SG_SEV_MEDIUM', 'medium');
            define('SG_SEV_LOW', 'low');
            define('SG_SEV_INFO', 'info');
        }

        if (!is_dir(ABSPATH . 'wp-content/plugins/spectrus-guard-tests')) {
            mkdir(ABSPATH . 'wp-content/plugins/spectrus-guard-tests', 0777, true);
        }
    }

    protected function setUp(): void
    {
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-advanced-detector.php';
        $this->detector = new SG_Advanced_Detector();
    }

    public function test_phase2_scoring_below_threshold_filters_file(): void
    {
        $file_path = $this->create_test_file(
            'phase2-low-score.php',
            '<?php
            $callback = "safe_function";
            $callback();
            '
        );

        $threats = $this->detector->scan_file($file_path);

        $this->assertEmpty($threats);
        @unlink($file_path);
    }

    public function test_phase2_scoring_accumulates_and_attaches_score(): void
    {
        $score = $this->invoke_private_method(
            'calculate_threat_score',
            array(
                array(
                    array('type' => 'sql_injection', 'severity' => SG_SEV_CRITICAL),
                    array('type' => 'csrf', 'severity' => SG_SEV_HIGH),
                    array('type' => 'variable_function', 'severity' => SG_SEV_HIGH),
                ),
            )
        );

        $file_path = $this->create_test_file(
            'phase2-high-score.php',
            '<?php
            global $wpdb;
            $sql = "SELECT * FROM users WHERE id = " . $_GET["id"];
            $wpdb->query($sql);

            if (isset($_POST["submit"])) {
                update_option("my_option", $_POST["value"]);
            }
            '
        );

        $threats = $this->detector->scan_file($file_path);

        $this->assertSame(70, $score);
        $this->assertNotEmpty($threats);
        $this->assertSame(55, $threats[0]['score']);
        $this->assertArrayHasKey('context', $threats[0]);
        $this->assertLessThanOrEqual(120, strlen($threats[0]['context']));
        @unlink($file_path);
    }

    public function test_phase2_variable_method_calls_do_not_report(): void
    {
        $content = '<?php
        class PhaseTwoSample {
            public function dispatch() {
                $this->run();
            }
        }
        ';

        $threats = $this->invoke_private_method('analyze_tokens', array('phase2-oop.php', $content));

        $this->assertEmpty($threats);
    }

    public function test_phase2_ignore_annotation_skips_variable_function_report(): void
    {
        $content = '<?php
        // @spectrusguard-ignore
        $callback();
        ';

        $threats = $this->invoke_private_method('analyze_tokens', array('phase2-ignore.php', $content));

        $this->assertEmpty($threats);
    }

    public function test_phase2_callback_array_downgrades_variable_function_to_info(): void
    {
        $content = '<?php
        $callback = array($this, "handle_event");
        add_action("init", $callback);
        $callback();
        ';

        $threats = $this->invoke_private_method('analyze_tokens', array('phase2-callback.php', $content));

        $this->assertNotEmpty($threats);
        $this->assertSame(SG_SEV_INFO, $threats[0]['severity']);
    }

    public function test_phase2_path_normalization_always_uses_abspath_relative_paths(): void
    {
        $content = '<?php eval("echo 1;");';
        $file_path = ABSPATH . 'wp-content/plugins/spectrus-guard-tests/path-normalization.php';
        $threats = $this->invoke_private_method('analyze_tokens', array($file_path, $content));

        $this->assertNotEmpty($threats);
        $this->assertSame('wp-content/plugins/spectrus-guard-tests/path-normalization.php', $threats[0]['file']);
    }

    public function test_phase2_detects_csrf_when_rest_api_init_is_not_in_proximity(): void
    {
        $content = '<?php
        if (isset($_POST["submit"])) {
            update_option("my_option", $_POST["value"]);
        }
        ' . str_repeat("\n", 120) . '
        add_action("rest_api_init", "register_route");
        ';

        $threats = $this->invoke_private_method('detect_csrf', array('phase2-csrf.php', $content));

        $this->assertNotEmpty($threats);
        $this->assertSame('csrf', $threats[0]['type']);
    }

    public function test_phase2_context_redacts_sensitive_tokens(): void
    {
        $file_path = $this->create_test_file(
            'phase2-context-redaction.php',
            '<?php
            echo DB_PASSWORD;

            if (isset($_POST["submit"])) {
                update_option("my_option", $_POST["value"]);
            }
            '
        );

        $threats = $this->detector->scan_file($file_path);
        $info_threat = $this->find_threat_by_type($threats, 'information_disclosure');

        $this->assertNotNull($info_threat);
        $this->assertSame('[REDACTED]', $info_threat['context']);
        @unlink($file_path);
    }

    /**
     * Invoke a private detector method using reflection.
     *
     * @param string $method_name Method name.
     * @param array  $arguments Method arguments.
     * @return mixed
     */
    private function invoke_private_method(string $method_name, array $arguments = array())
    {
        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod($method_name);
        $method->setAccessible(true);

        return $method->invokeArgs($this->detector, $arguments);
    }

    /**
     * Create a test PHP file under the fake ABSPATH tree.
     *
     * @param string $file_name File name.
     * @param string $content File content.
     * @return string Absolute file path.
     */
    private function create_test_file(string $file_name, string $content): string
    {
        $file_path = ABSPATH . 'wp-content/plugins/spectrus-guard-tests/' . $file_name;
        file_put_contents($file_path, $content);

        return $file_path;
    }

    /**
     * Find the first threat matching a given type.
     *
     * @param array  $threats Threat list.
     * @param string $type Threat type.
     * @return array|null Matching threat or null.
     */
    private function find_threat_by_type(array $threats, string $type): ?array
    {
        foreach ($threats as $threat) {
            if (isset($threat['type']) && $type === $threat['type']) {
                return $threat;
            }
        }

        return null;
    }
}
