## 2025-01-29 - JSON vs PHP Array Performance in MU Plugins
**Learning:** Loading and parsing a 6KB JSON file on every request (via MU-Plugin) adds significant overhead (~0.05ms) which can be reduced by ~20x (~0.002ms) by converting it to a PHP array file. PHP OPcache caches the compiled array, eliminating parsing overhead.
**Action:** When working with static configuration in hot paths (like WAFs or autoloaders), prefer `return array(...)` in a PHP file over `json_decode()`.

## 2025-01-30 - Guard Clauses for Expensive String Operations
**Learning:** Using `strpos` as a guard clause before expensive string operations like `urldecode` loops, `html_entity_decode`, or complex `preg_replace` significantly improves performance (~10x for `urldecode` loop, ~3x overall for mixed operations) on strings that don't need decoding.
**Action:** Always check if the string contains the relevant characters (e.g., `%` or `+` for `urldecode`, `&` for `html_entity_decode`) before calling expensive decoding functions, especially in hot paths like request analysis.
