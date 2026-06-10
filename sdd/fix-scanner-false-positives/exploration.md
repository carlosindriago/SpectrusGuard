## Exploration: fix-scanner-false-positives

### Current State
The SpectrusGuard scanner scans recursive files under `wp-content/plugins` and `wp-content/themes` using signature analysis (heuristics) and token-based code flow analysis (advanced detector). Currently:
1. There is no directory-level exclusion logic. The scanner recurses into and analyzes all dependency paths (like `vendor/`, `node_modules/`, `bower_components/`, `tests/`, etc.).
2. The advanced detector relies on naive regex and token patterns that flag standard, secure coding patterns as threats:
   - **LFI**: Flags any file inclusion using standard path concatenation with `.php` at the end (e.g. `include plugin_dir_path(__FILE__) . 'views/file.php'`).
   - **SQL Injection**: Flags any query using variables (like `$wpdb->query($sql)`) where `$wpdb->prepare` is not within 800 characters, even if it is a completely safe static query or was prepared elsewhere.
   - **CSRF**: Flags any file accessing `$_POST` without `wp_verify_nonce` or `check_ajax_referer` in a tiny 800-character window, ignoring global filters, other security functions, or WooCommerce native wrappers (`wc_verify_nonce`).
   - **Dangerous Functions**: Flags standard PHP functions (`exec`, `shell_exec`, etc.) as critical malware threats even when used in trusted library dependencies.
3. The whitelist system is strictly database-driven, checking individual files by their full path and SHA-256 hash. It lacks support for folder-level exclusions, wildcards, or trusted namespaces.

### Affected Areas
- `includes/scanner/class-sg-scanner.php` — Coordinates directory scans and needs to support path exclusion checks.
- `includes/scanner/class-sg-heuristics.php` — Runs signature scans and needs to respect path exclusion settings.
- `includes/scanner/class-sg-advanced-detector.php` — Implements tokenizer and regex threat detectors which require logic improvements to reduce false positives.
- `includes/whitelist/class-sg-whitelist.php` — Holds the whitelisting implementation and can be extended to support wildcard or path-prefix whitelisting.

### Approaches

1. **Approach A: Basic Exclusions + Rules Refactoring (Recommended)**
   - **Description**: Add directory-level exclusions for dependency paths (`vendor`, `node_modules`, `tests`, etc.) to skip them entirely during scanning. In `class-sg-advanced-detector.php`, refine threat detection logic (e.g., exclude constant-based path concatenation from LFI checks, recognize more nonce wrappers like `wc_verify_nonce` or `check_admin_referer`, and ignore simple variable query checks if there is no string concatenation with user inputs).
   - **Pros**: 
     - Drastically cuts scan execution time and memory usage.
     - Eliminates the majority of false positives on standard codebases.
     - Keeps files neat without introducing heavy database tables.
   - **Cons**: 
     - Might miss malicious files if an attacker manages to hide them inside a `vendor/` folder (though WAF/integrity checks would still protect core and runtime).
   - **Effort**: Medium

2. **Approach B: Advanced Wildcard Whitelisting & Configurable Exclusions**
   - **Description**: Build an options-based configuration interface in settings for ignored directories, and update `SG_Whitelist` to support path wildcard rules (`/path/to/folder/*`).
   - **Pros**:
     - Highly flexible and puts full control in user hands.
     - Allows developers to explicitly ignore customized directories.
   - **Cons**:
     - Higher complexity to build setting UI and database/regex parsing logic.
     - Might be overwhelming for normal users who just want the scanner to work out-of-the-box.
   - **Effort**: High

### Recommendation
Combine **Approach A** with a configurable filter/setting. Introduce a default list of excluded directories (`vendor`, `node_modules`, `bower_components`, `tests`, `test`, `docs`, `.git`, `.github`) that is skipped during the recursive scan. Refactor detector rules to exclude constant-based concatenations in LFI, add common WP/WooCommerce nonce verification functions, and ignore safe query variable patterns.

### Risks
- **Evasion**: Attackers could intentionally place webshells/backdoors inside directories matching `vendor/` or `tests/` names to avoid detection. Mitigation: Check WAF logs and monitor file modifications via core integrity checks or separate audit logs.
- **Rule Relaxation**: Making regex checks more specific might lead to missing edge-case actual injections. Mitigation: Focus rule relaxations only on known safe coding standards (e.g., plugin path constants).

### Ready for Proposal
Yes — The orchestrator should propose:
1. Adding a default directory exclusion list for dependency/test folders.
2. Refactoring regex patterns in `class-sg-advanced-detector.php` (for LFI, SQLi, and CSRF) to prevent flagging standard WordPress/WooCommerce patterns.
3. Adding support for common WooCommerce/WP core functions.
