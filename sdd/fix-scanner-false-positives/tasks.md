# Tasks: Fix Scanner False Positives

## Review Workload Forecast

Decision needed before apply: No
Chained PRs recommended: No
Chain strategy: size-exception
400-line budget risk: Low

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Centralize exclusions and refactor scanner | None | Direct commit to main. |

## Phase 1: Foundation

- [x] 1.1 Define global severity constants `SG_SEV_CRITICAL`, `SG_SEV_HIGH`, `SG_SEV_MEDIUM`, `SG_SEV_LOW`, and `SG_SEV_INFO` in `spectrus-guard.php`.
- [x] 1.2 Create `includes/scanner/class-sg-trusted-paths.php` implementing `SG_Trusted_Paths` class.
- [x] 1.3 Implement `SG_Trusted_Paths::is_path_excluded()` to check if a path contains any of the excluded directory names (`vendor`, `node_modules`, etc.).
- [x] 1.4 Implement `SG_Trusted_Paths::get_php_files_in_directory()` to recursively scan a directory and skip excluded folders using path exclusion checks.
- [x] 1.5 Implement `SG_Trusted_Paths::is_php_file()`, `is_plugin_file()`, and `is_plugin_or_theme_file()` helpers.

## Phase 2: Core Implementation

- [x] 2.1 Modify `includes/scanner/class-sg-scanner.php` to require `class-sg-trusted-paths.php` and use `SG_Trusted_Paths` methods for PHP file discovery.
- [x] 2.2 Update `includes/scanner/class-sg-heuristics.php` to use `SG_Trusted_Paths::get_php_files_in_directory()` in `scan_for_signatures()` and directory traversals.
- [x] 2.3 Refactor `SG_Advanced_Detector::analyze_tokens()` in `class-sg-advanced-detector.php` to ignore `T_STRING` match for dangerous functions when prefixed by object operator (`->`, `?->`), static operator (`::`), or preceded by `T_FUNCTION`.
- [x] 2.4 Refactor `SG_Advanced_Detector::detect_csrf()` to check for `wc_verify_nonce` and `check_admin_referer` in addition to `wp_verify_nonce` and `check_ajax_referer`.
- [x] 2.5 Refactor `SG_Advanced_Detector::detect_sql_injection()` to parse and inspect the definition of variable queries, skipping static queries with no concatenation or user input.
- [x] 2.6 Refactor `SG_Advanced_Detector::detect_lfi()` to permit LFI inclusions containing safe constants and path functions without variables.

## Phase 3: Testing and Verification

- [x] 3.1 Create unit tests in `tests/test-class-sg-trusted-paths.php` to verify `is_path_excluded()` matches exact names and recursively skips excluded directories.
- [x] 3.2 Create unit tests in `tests/test-class-sg-advanced-detector.php` to verify token analyzer context ignores method/static calls and function definitions.
- [x] 3.3 Create unit/integration tests for SQLi, CSRF, and LFI detectors with safe patterns vs threat patterns.
- [x] 3.4 Run phpcs (`composer run lint`) to verify WordPress coding standards compliance.
- [x] 3.5 Run phpstan (`composer run analyze`) to ensure static analysis checks pass.
