## 2025-01-29 - JSON vs PHP Array Performance in MU Plugins
**Learning:** Loading and parsing a 6KB JSON file on every request (via MU-Plugin) adds significant overhead (~0.05ms) which can be reduced by ~20x (~0.002ms) by converting it to a PHP array file. PHP OPcache caches the compiled array, eliminating parsing overhead.
**Action:** When working with static configuration in hot paths (like WAFs or autoloaders), prefer `return array(...)` in a PHP file over `json_decode()`.
