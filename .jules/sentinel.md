## 2024-05-23 - [Critical SQL Injection Pattern]
**Vulnerability:** Unsanitized variables used in SQL `LIMIT` and `OFFSET` clauses via string interpolation in `SG_Whitelist::get_all`.
**Learning:** Even internal helper methods can be vulnerable if they don't validate inputs, creating "ticking time bombs" if future code exposes them to user input.
**Prevention:** Always cast numeric SQL parameters (like LIMIT/OFFSET) to `(int)` before using them in query strings, or use `$wpdb->prepare` with `%d`.
