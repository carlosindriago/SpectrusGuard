## 2025-01-29 - JSON vs PHP Array Performance in MU Plugins
**Learning:** Loading and parsing a 6KB JSON file on every request (via MU-Plugin) adds significant overhead (~0.05ms) which can be reduced by ~20x (~0.002ms) by converting it to a PHP array file. PHP OPcache caches the compiled array, eliminating parsing overhead.
**Action:** When working with static configuration in hot paths (like WAFs or autoloaders), prefer `return array(...)` in a PHP file over `json_decode()`.

## 2026-01-29 - Security vs Performance in Cache Files
**Learning:** While generating PHP files for caching is fast (OPcache), writing them to `wp-content/uploads` (writable directory) creates a Critical RCE vulnerability if an attacker can overwrite them.
**Action:** For dynamic cache data in writable directories, prefer Transients API (DB/Object Cache) or JSON files over executable PHP files. Correctness and Security > Speed.
