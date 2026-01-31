## 2025-01-29 - JSON vs PHP Array Performance in MU Plugins
**Learning:** Loading and parsing a 6KB JSON file on every request (via MU-Plugin) adds significant overhead (~0.05ms) which can be reduced by ~20x (~0.002ms) by converting it to a PHP array file. PHP OPcache caches the compiled array, eliminating parsing overhead.
**Action:** When working with static configuration in hot paths (like WAFs or autoloaders), prefer `return array(...)` in a PHP file over `json_decode()`.

## 2025-01-29 - String Processing Fast-Fail Optimization
**Learning:** Pre-checking strings with `strpos()` before running expensive operations like `urldecode`, `html_entity_decode`, or regex matching can improve performance by 30x+ on large strings, as most clean data doesn't require processing.
**Action:** Always add "fast fail" `strpos` guards before expensive string transformations or regexes when the target character/pattern is rare.
