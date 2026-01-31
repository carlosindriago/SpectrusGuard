## 2024-05-23 - WAF IP Spoofing via Header Manipulation
**Vulnerability:** The WAF's `get_client_ip()` method blindly trusted forwarded headers like `X-Forwarded-For` from any source, allowing attackers to bypass IP-based blocks by spoofing these headers.
**Learning:** Defaulting to trust forwarded headers without validating the source (checking if `REMOTE_ADDR` is a trusted proxy) destroys the integrity of IP-based security.
**Prevention:** Only process forwarded headers if the request originates from a private IP (local proxy) or a known trusted load balancer (e.g., Cloudflare ranges).
