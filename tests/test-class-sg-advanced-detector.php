<?php
use PHPUnit\Framework\TestCase;

class Test_SG_Advanced_Detector extends TestCase
{
    private $detector;

    public static function setUpBeforeClass(): void
    {
        if (!defined('ABSPATH')) {
            define('ABSPATH', sys_get_temp_dir() . '/');
        }
        if (!defined('SG_PLUGIN_DIR')) {
            define('SG_PLUGIN_DIR', dirname(__DIR__) . '/');
        }
        // Define severity constants if not defined
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
        require_once dirname(__DIR__) . '/includes/scanner/class-sg-advanced-detector.php';
        $this->detector = new SG_Advanced_Detector();
    }

    public function test_analyze_tokens_ignores_method_and_definition()
    {
        $safe_content = '<?php
        class MyClass {
            public function eval($code) {
                return $code;
            }
        }
        $obj = new MyClass();
        $obj->eval("echo 1;");
        MyClass::eval("echo 2;");
        ';

        // Reflection to call private method analyze_tokens
        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('analyze_tokens');
        $method->setAccessible(true);

        $threats = $method->invoke($this->detector, 'safe_file.php', $safe_content);
        $this->assertEmpty($threats, 'Should not detect safe method definitions or calls as dangerous function calls.');
    }

    public function test_detect_sql_injection_skips_static_queries()
    {
        $safe_content = '<?php
        global $wpdb;
        $sql = "SELECT * FROM wp_users WHERE id = 1";
        $wpdb->query($sql);
        ';

        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('detect_sql_injection');
        $method->setAccessible(true);

        $threats = $method->invoke($this->detector, 'safe_sql.php', $safe_content);
        $this->assertEmpty($threats, 'Should skip static SQL queries without variable concat or interpolation.');
    }

    public function test_detect_csrf_nonces()
    {
        $safe_content = '<?php
        if (isset($_POST["submit"])) {
            if (wc_verify_nonce($_POST["nonce"], "action")) {
                wp_insert_post($data);
            }
        }
        ';

        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('detect_csrf');
        $method->setAccessible(true);

        $threats = $method->invoke($this->detector, 'safe_csrf.php', $safe_content);
        $this->assertEmpty($threats, 'Should accept wc_verify_nonce as valid CSRF verification.');
    }

    public function test_detect_lfi_constants()
    {
        $safe_content = '<?php
        include SG_PLUGIN_DIR . "includes/file.php";
        ';

        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('detect_lfi');
        $method->setAccessible(true);

        $threats = $method->invoke($this->detector, 'safe_lfi.php', $safe_content);
        $this->assertEmpty($threats, 'Should permit constant-only file inclusion paths without variables.');
    }

    public function test_analyze_tokens_dangerous_functions_with_and_without_user_input()
    {
        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('analyze_tokens');
        $method->setAccessible(true);

        // 1. Dangerous function with user input -> CRITICAL
        $unsafe_content = '<?php eval($_POST["code"]);';
        $threats = $method->invoke($this->detector, 'unsafe_eval.php', $unsafe_content);
        $this->assertNotEmpty($threats);
        $this->assertEquals(SG_SEV_CRITICAL, $threats[0]['severity'], 'eval with user input should be critical.');

        // 2. Dangerous function without user input -> MEDIUM
        $safe_content = '<?php eval("echo 1;");';
        $threats = $method->invoke($this->detector, 'safe_eval.php', $safe_content);
        $this->assertNotEmpty($threats);
        $this->assertEquals(SG_SEV_MEDIUM, $threats[0]['severity'], 'eval without user input should be medium.');
    }

    public function test_detect_csrf_with_nonce_or_hooks_anywhere_in_file()
    {
        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('detect_csrf');
        $method->setAccessible(true);

        // CSRF with protective hook rest_api_init anywhere in the file
        $content = '<?php
        // Trigger action
        if (isset($_POST["submit"])) {
            update_option("my_option", $_POST["val"]);
        }
        
        // Somewhere else in the file, we have a protective hook or nonce
        add_action("rest_api_init", "my_register_route");
        ';

        $threats = $method->invoke($this->detector, 'csrf_hook.php', $content);
        $this->assertEmpty($threats, 'Should not flag CSRF if rest_api_init is present in the file.');
    }

    public function test_detect_sql_injection_prepare_large_window_and_safe_variables()
    {
        $reflection = new ReflectionClass('SG_Advanced_Detector');
        $method = $reflection->getMethod('detect_sql_injection');
        $method->setAccessible(true);

        // Scenario A: prepare() located far away but within ±3000 chars (e.g. 2500 chars before)
        $padding = str_repeat("// padding comment line \n", 100); // ~2500 chars of comments
        $prepare_content = '<?php
        global $wpdb;
        $sql = $wpdb->prepare("SELECT * FROM table WHERE id = %d", $_GET["id"]);
        ' . $padding . '
        $wpdb->get_results($sql);
        ';
        $threats = $method->invoke($this->detector, 'sql_large_window.php', $prepare_content);
        $this->assertEmpty($threats, 'Should find prepare() in large window and not flag.');

        // Scenario B: Variable is not tainted (no user input in the context)
        $no_taint_content = '<?php
        global $wpdb;
        $my_id = 42;
        $sql = "SELECT * FROM table WHERE id = " . $my_id;
        $wpdb->get_col($sql);
        ';
        $threats = $method->invoke($this->detector, 'sql_no_taint.php', $no_taint_content);
        $this->assertEmpty($threats, 'Should not flag if variables are not tainted.');

        // Scenario C: Variable is tainted (user input in the context and assigned)
        $tainted_content = '<?php
        global $wpdb;
        $my_id = $_GET["id"];
        $sql = "SELECT * FROM table WHERE id = " . $my_id;
        $wpdb->get_row($sql);
        ';
        $threats = $method->invoke($this->detector, 'sql_tainted.php', $tainted_content);
        $this->assertNotEmpty($threats, 'Should flag if the variable is tainted.');
    }
}
