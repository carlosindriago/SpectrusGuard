## 2025-01-29 - JSON vs PHP Array Performance in MU Plugins
**Learning:** Loading and parsing a 6KB JSON file on every request (via MU-Plugin) adds significant overhead (~0.05ms) which can be reduced by ~20x (~0.002ms) by converting it to a PHP array file. PHP OPcache caches the compiled array, eliminating parsing overhead.
**Action:** When working with static configuration in hot paths (like WAFs or autoloaders), prefer `return array(...)` in a PHP file over `json_decode()`.

## 2025-01-29 - strpos vs preg_replace for "Fast Fail"
**Learning:** Using `strpos` to "fast fail" before a regex can be counter-productive. In this PHP environment, `strpos($large_string, 'needle')` was ~5x slower than `preg_replace` (PCRE) when the needle was missing. PCRE likely uses optimized internal searching (JIT/SIMD) that outperforms standard `strpos` for this case.
**Action:** Don't assume `strpos` is always faster than regex for simple checks. Benchmark it. If the regex is simple (e.g., literal prefix), let the regex engine handle the optimization.
