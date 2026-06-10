# Design: Fix Scanner False Positives

## Technical Approach

To reduce false positives in `SpectrusGuard` scans and optimize scan execution times, we will centralize directory exclusions and refine threat analysis in the advanced tokenizer detector. We will introduce a new class, `SG_Trusted_Paths`, that handles path filtering. Both the heuristics scanner and the advanced detector will use it to bypass dependency and testing directories (`vendor`, `node_modules`, etc.). The advanced detector's parsing rules for SQL Injection (SQLi), CSRF, Local File Inclusion (LFI), and Token/Method identification will be updated to respect safety constants and token call contexts.

## Architecture Decisions

| Decision | Option | Tradeoff | Decision |
|---|---|---|---|
| Centralized Exclusions | `SG_Trusted_Paths` helper | Slight initial setup overhead, but avoids duplicating exclusion logic across scanner classes | **Chosen**: Centralized `SG_Trusted_Paths` class. |
| Directory Traversal | Recursive directory loop | `RecursiveFilterIterator` might be slow or prone to PHP iterator overhead | **Chosen**: Custom recursive scanner directory walker in `SG_Trusted_Paths`. |
| Severity Constants | Main plugin file constants | Class constants in `SG_Advanced_Detector` are not globally visible | **Chosen**: Defined globally in `spectrus-guard.php`. |

## Data Flow

```
  SG_Scanner / SG_Heuristics
              │
              ▼
    SG_Trusted_Paths::get_php_files_in_directory()
              │
              ├─► Skip: vendor, node_modules, etc.
              ▼
       PHP Files List
              │
              ▼
   SG_Advanced_Detector::scan_file()
              │
              ├─► analyze_tokens()  (checks token context & arguments)
              ├─► detect_csrf()     (checks WooCommerce hooks & nonces in entire file)
              ├─► detect_sql_injection() (checks contaminated variables & prepare safety)
              └─► detect_lfi()       (checks user-input inclusions)
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `includes/scanner/class-sg-trusted-paths.php` | Create | Contains the `SG_Trusted_Paths` class with static exclusion and file collection logic. |
| `spectrus-guard.php` | Modify | Define global severity constants `SG_SEV_CRITICAL`, `SG_SEV_HIGH`, `SG_SEV_MEDIUM`, `SG_SEV_LOW`, `SG_SEV_INFO`. |
| `includes/scanner/class-sg-scanner.php` | Modify | Include `class-sg-trusted-paths.php` and use it to discover PHP files. Map severity constants. |
| `includes/scanner/class-sg-heuristics.php` | Modify | Use `SG_Trusted_Paths` to fetch scanned PHP files and filter exclusions. |
| `includes/scanner/class-sg-advanced-detector.php` | Modify | Update token method resolution, CSRF file checks, SQLi variable tracking, and user-input-only LFI checks. |

## Interfaces / Contracts

```php
class SG_Trusted_Paths {
    private static $excluded_directories = array(
        'vendor', 'node_modules', 'bower_components', 'tests', 'test', 'docs', '.git', '.github'
    );
    public static function get_php_files_in_directory(string $directory, int $max_files = 5000): array;
    public static function is_php_file(string $filename): bool;
    public static function is_path_excluded(string $path): bool;
    public static function is_plugin_file(string $path): bool;
}
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Path exclusions | Verify `SG_Trusted_Paths::is_path_excluded()` skips `vendor` but not `vendor-integration`. |
| Unit | Token Prefixes | Ensure class methods or definitions matching dangerous functions (e.g. `$obj->exec()`) are ignored. |
| Integration | SQLi, CSRF, LFI | Verify dynamic variables/inputs are flagged, while safe path constants and WooCommerce hooks are skipped. |

## Migration / Rollout

No migration required. Scanner updates take effect immediately on the next scheduled or manual scan.

## Open Questions

None.
