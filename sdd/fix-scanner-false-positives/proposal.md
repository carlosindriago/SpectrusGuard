# Proposal: Fix Scanner False Positives

## Intent
Reduce false positives in the SpectrusGuard scanner (WooCommerce and WP core files flagged as malware) and improve scan execution time.

## Scope

### In Scope
- Exclude dependency and testing paths (`vendor`, `node_modules`, `bower_components`, `tests`, `test`, `docs`, `.git`, `.github`) from advanced scanner and heuristics scans.
- Refactor logic in `class-sg-advanced-detector.php`:
  - `analyze_tokens`: Prevent false positives on class/object method calls and definitions of dangerous functions (ignore `T_STRING` prefixed by `->`, `::`, or `function`).
  - `detect_csrf`: Recognize additional common nonce verification functions (`wc_verify_nonce`, `check_admin_referer`).
  - `detect_sql_injection`: Exclude queries with no user-controlled string concatenation or prepared variables.
  - `detect_lfi`: Allow standard path concatenation using constants/functions (`plugin_dir_path`, `dirname`, `__DIR__`, `ABSPATH`).

### Out of Scope
- Configurable settings UI for modifying path exclusions.
- Core integrity scanner exclusions (core files must always be checked).

## Capabilities

### New Capabilities
- None

### Modified Capabilities
- `malware-scanner`: Refine detection rules and skip dependency/testing folders to prevent false positives and reduce execution time.

## Approach
- Update directory traversal in `SG_Scanner` and `SG_Heuristics` to skip files located in the excluded directory segments.
- Refactor token scanner in `SG_Advanced_Detector::analyze_tokens` to check token sequence context and avoid flagging class methods/properties that match dangerous function names.
- Update `detect_lfi` regex to permit concatenations containing safe constants and path functions.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `includes/scanner/class-sg-scanner.php` | Modified | Add `is_path_excluded` check in `scan_directory_for_php`. |
| `includes/scanner/class-sg-heuristics.php` | Modified | Add `is_path_excluded` check in `scan_for_signatures`. |
| `includes/scanner/class-sg-advanced-detector.php` | Modified | Refactor tokenizer and regex threat detectors (SQLi, CSRF, LFI). |
| `includes/class-sg-loader.php` | Modified | Define default `scanner_excluded_paths` setting. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Evasion via vendor folder | Low | Core file integrity checker and WAF protect the system. |
| Relaxed rules miss real injections | Low | Restrict relaxation strictly to safe WP constants/methods; continue flagging dynamic user inputs. |

## Rollback Plan
- Revert file changes to the scanner components from git history.

## Dependencies
- None

## Success Criteria
- [ ] WooCommerce files and standard WordPress core structures do not trigger malware alerts.
- [ ] Scan execution time is reduced by bypassing the `vendor` and `node_modules` paths.
- [ ] Signature and heuristic checks remain fully functional for non-excluded files.
