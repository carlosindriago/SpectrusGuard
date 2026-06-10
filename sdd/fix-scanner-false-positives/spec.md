content: # Delta for malware-scanner
         
         ## ADDED Requirements
         
         ### Requirement: Directory Exclusion during Traversal
         
         The malware scanner MUST support excluding specific directory names from scans.
         The traversal logic SHALL skip any directory matching: `vendor`, `node_modules`, `bower_components`, `tests`, `test`, `docs`, `.git`, `.github`.
         Directory skip checks MUST apply to both heuristic signature scans and advanced tokenizer scans.
         
         #### Scenario: Traversal skips excluded folder
         
         - GIVEN a directory traversal starts for scanning plugins or themes
         - WHEN the traversal encounters a directory named `vendor` or `node_modules`
         - THEN the scanner MUST NOT recurse into that directory or scan any files within it
         
         #### Scenario: Traversal scans non-excluded folders with similar names
         
         - GIVEN a directory traversal starts for scanning
         - WHEN the traversal encounters a directory named `vendor-integration` or `mytests`
         - THEN the scanner MUST recurse and scan the files inside it
         
         ## MODIFIED Requirements
         
         ### Requirement: Refined Tokenizer Function Context
         
         The token scanner MUST ignore T_STRING match for dangerous functions when the match is part of an object/class method call or definition.
         (Previously: The tokenizer flagged any T_STRING matching dangerous functions like `exec` or `eval` regardless of context.)
         
         #### Scenario: Class method or static calls matching dangerous function names
         
         - GIVEN a file containing PHP code with class method calls like `$obj->exec()` or definitions like `public function eval()`
         - WHEN the token scanner analyzes the file
         - THEN the scanner SHALL NOT flag the code as a dangerous function threat
         
         #### Scenario: Direct call of dangerous function
         
         - GIVEN a file containing PHP code with direct execution like `exec($cmd)`
         - WHEN the token scanner analyzes the file
         - THEN the scanner MUST flag it as a CRITICAL severity threat
         
         ### Requirement: Refined LFI Path Concatenation
         
         The LFI detector MUST NOT flag dynamic file inclusions using safe WordPress/PHP constants or path functions.
         (Previously: The LFI detector flagged any dynamic file inclusion using concatenation.)
         
         #### Scenario: Inclusion with safe WP path constants
         
         - GIVEN a file with code: `include plugin_dir_path(__FILE__) . 'view.php';` or `require ABSPATH . 'wp-settings.php';`
         - WHEN the advanced detector scans the file
         - THEN the detector SHALL NOT flag it as an LFI threat
         
         #### Scenario: Concatenation with user input or dynamic variables
         
         - GIVEN a file with code: `include $dynamic_path . $_GET['page'] . '.php';`
         - WHEN the advanced detector scans the file
         - THEN the detector MUST flag it as a CRITICAL severity LFI threat
         
         ### Requirement: Refined SQLi Variable Checks
         
         The SQLi detector MUST NOT flag queries stored in variables if the query does not contain dynamic string concatenation or user inputs.
         (Previously: The SQLi detector flagged any query utilizing a variable where wpdb->prepare was not within 800 characters.)
         
         #### Scenario: Safe static query in variable
         
         - GIVEN a file with code: `$sql = "SELECT * FROM wp_posts"; $wpdb->query($sql);`
         - WHEN the advanced detector scans the file
         - THEN the detector SHALL NOT flag it as an SQL Injection threat
         
         #### Scenario: Concatenation with user inputs in query variable
         
         - GIVEN a file with code: `$sql = "SELECT * FROM wp_users WHERE ID = " . $_GET['id']; $wpdb->query($sql);`
         - WHEN the advanced detector scans the file
         - THEN the detector MUST flag it as a CRITICAL severity SQL Injection threat
         
         ### Requirement: Refined CSRF Nonce Verification
         
         The CSRF detector MUST recognize additional nonce verification functions `wc_verify_nonce` and `check_admin_referer`.
         (Previously: The CSRF detector only recognized `wp_verify_nonce` and `check_ajax_referer`.)
         
         #### Scenario: Nonce verification using wc_verify_nonce or check_admin_referer
         
         - GIVEN a file processing `$_POST` containing `wc_verify_nonce` or `check_admin_referer` within 800 characters
         - WHEN the advanced detector scans the file
         - THEN the detector SHALL NOT flag it as a CSRF threat
         
         #### Scenario: POST processing without nonce verification
         
         - GIVEN a file processing `$_POST` with no nonce verification functions in the proximity window
         - WHEN the advanced detector scans the file
         - THEN the detector MUST flag it as a HIGH severity CSRF threat
