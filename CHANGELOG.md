# Changelog

All notable changes to SpectrusGuard Enterprise will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-01-29

### Added
- **AI-Powered Threat Analytics (UEBA)**: Complete User and Entity Behavior Analytics system
  - Real-time behavioral profiling for all users
  - Statistical anomaly detection (Z-Score, IQR, Sequential Pattern Analysis)
  - Comprehensive risk scoring system (0-100)
  - Automated incident response based on risk level
  - Threat Analytics dashboard with real-time visualizations
  - REST API endpoints for external integrations
  - 6 anomaly detection types:
    - Login frequency anomalies
    - Time-based anomalies
    - Geographic anomalies
    - Device fingerprint anomalies
    - Request rate anomalies
    - IP reputation anomalies (Tor, VPN)
- **New Database Table**: `wp_spectrus_ueba_metrics` for storing behavioral data
- **Metrics Collection System**:
  - Login metrics (frequency, geo, time, device)
  - Request metrics (rate, patterns, errors)
  - User metrics (actions, role behavior)
  - IP metrics (history, reputation)
- **Risk Scoring Engine**:
  - Configurable risk weights per anomaly type
  - Severity multipliers (LOW: 0.3, MEDIUM: 0.6, HIGH: 0.9, CRITICAL: 1.0)
  - Trend analysis (improving, stable, worsening)
- **Automated Response System**:
  - LOW: Log only
  - MEDIUM: Warning banner to user
  - HIGH: Require 2FA + Notify admin
  - CRITICAL: Block IP + Logout + Urgent email
- **Threat Analytics Dashboard**:
  - Real-time risk score overview (LOW/MEDIUM/HIGH/CRITICAL)
  - Activity timeline with Chart.js visualization
  - Top risky users with detailed metrics
  - Top risky IPs with blocking capability
  - Recent anomalies feed
- **REST API Endpoints**:
  - `GET /wp-json/spectrus-guard/v1/ueba/risk-score/{user_id}`
  - `GET /wp-json/spectrus-guard/v1/ueba/baseline/{user_id}`
  - `GET /wp-json/spectrus-guard/v1/ueba/anomalies/{user_id}`
- **Advanced IP Validation**:
  - Trusted proxy configuration
  - IP spoofing protection
  - IPv6 support
- **Cron Jobs**:
  - Daily metric cleanup (90-day retention)
  - Baseline recalculations
- **Comprehensive Documentation**:
  - UEBA technical documentation
  - Architecture diagrams
  - API documentation
  - Use cases and examples

### Changed
- **PHP Version Requirement**: Minimum PHP version increased from 7.4 to 8.1
- **WordPress Version Requirement**: Minimum WP version increased from 5.8 to 6.4
- **Plugin Version**: Updated to 3.0.0 (major version increment)
- **Database Schema**: Added `wp_spectrus_ueba_metrics` table
- **Loader**: Updated to initialize UEBA Engine when enabled
- **Admin Interface**: Added Threat Analytics menu item
- **Logging**: Enhanced to support UEBA events with structured data

### Security
- **IP Spoofing Protection**: Implemented trusted proxy validation
- **Zero-Trust Input Validation**: All inputs validated before use
- **Secure Random Number Generation**: Eliminated insecure `rand()` fallback in TOTP
- **Timing Attack Protection**: Use `hash_equals()` for comparisons
- **Fail-Open Design**: UEBA allows access if baseline insufficient
- **Data Privacy**: No PII stored, hashed device fingerprints
- **Immutable Audit Trail**: Logs cannot be modified without detection

### Performance
- **Caching**: Baselines cached for 1 hour
- **Lazy Loading**: UEBA components loaded on-demand
- **Database Optimization**: Composite indexes for common queries
- **Query Limits**: Pagination to prevent large result sets
- **Memory Management**: Exponential decay for old data

### Deprecated
- None in this release

### Removed
- None in this release

### Fixed
- None in this release (new features only)

### Security Advisory
- This release introduces major security enhancements including IP spoofing protection and secure random number generation.
- All users are encouraged to upgrade to this version.
- The plugin now requires PHP 8.1+ for modern cryptographic functions.

---

## [2.1.0] - 2026-01-28

### Added
- **Geo-Blocking Module**: Country-based access restriction
  - MaxMind GeoLite2 database integration
  - Tor exit node detection
  - VPN/datacenter IP detection
  - Automated database updates via cron
  - Configurable blocking actions (403, CAPTCHA, redirect)

### Changed
- **MU-Plugin Path**: Updated to `/wp-content/mu-plugins/spectrus-waf.php`
- **WAF Rules**: Added 50+ new patterns for emerging threats

### Security
- **Geo-IP Fail-Open**: Allows access if database unavailable

---

## [2.0.0] - 2025-12-15

### Added
- **WAF Drop-In**: Must-Use plugin executes before WordPress loads
- **Deep Packet Inspection**: SQL Injection, XSS, RCE, LFI/RFI, Path Traversal
- **URL Cloaking**: Hide WordPress paths (`/wp-content`, `/wp-includes`)
- **Login Page Protection**: Move login to custom slug
- **Zero-Trust 2FA**: TOTP authentication with Google Authenticator
- **Brute Force Protection**: Intelligent lockout with exponential backoff
- **Header Hardening**: Remove WordPress version, X-Powered-By
- **Immersive Admin UI**: Custom dark-mode dashboard
- **Malware Scanner**: Heuristic-based file analysis

### Security
- **Pattern Decoding**: Multi-pass URL decoding to catch evasion
- **HTML Entity Decoding**: Prevent XSS via encoded payloads
- **Unicode Escape Detection**: Block Unicode-based attacks

---

## [1.0.0] - 2024-11-01

### Added
- Initial release
- Basic WAF with regex patterns
- Login protection
- File integrity scanning
- Admin dashboard
- Logging system

---

## Upgrade Guide

### From 2.x to 3.0.0

**Prerequisites**:
- PHP 8.1 or higher
- WordPress 6.4 or higher
- MySQL 5.7+ or MariaDB 10.2+

**Steps**:

1. **Backup Your Site**
   ```bash
   # Full backup of files and database
   wp db export
   tar -czf backup.tar.gz wp-content/
   ```

2. **Update PHP**
   - Ensure your server is running PHP 8.1 or higher
   - Check with: `php -v`

3. **Update WordPress**
   - Update to WordPress 6.4+ via Dashboard or WP-CLI

4. **Install the Update**
   ```bash
   # Via WP-CLI
   wp plugin update spectrus-guard

   # Or manually upload
   rm -rf wp-content/plugins/spectrus-guard
   wp plugin install https://github.com/carlosindriago/SpectrusGuard/archive/refs/tags/3.0.0.zip --activate
   ```

5. **Run Database Migration**
   - The plugin automatically creates the `wp_spectrus_ueba_metrics` table
   - No manual action required

6. **Configure UEBA Settings**
   - Navigate to **SpectrusGuard → Settings**
   - Enable UEBA: Set `ueba_enabled` to `true`
   - Configure learning period (default: 7 days)
   - Set risk thresholds (HIGH: 50, CRITICAL: 80)

7. **Verify Installation**
   ```bash
   # Check database table
   wp db query "SHOW TABLES LIKE 'wp_spectrus_ueba_metrics'"

   # Check MU-Plugin
   ls -la wp-content/mu-plugins/spectrus-waf.php
   ```

8. **Test the System**
   - Log in to verify UEBA metrics collection
   - Check Threat Analytics dashboard
   - Review risk scores for users

**Post-Upgrade**:
- Monitor logs for any anomalies
- Check that baselines are being created
- Verify threat detection is working

**Rollback** (if needed):
```bash
# Revert to previous version
wp plugin install https://github.com/carlosindriago/SpectrusGuard/archive/refs/tags/2.1.0.zip --activate

# Remove UEBA table (optional)
wp db query "DROP TABLE IF EXISTS wp_spectrus_ueba_metrics"
```

---

## Release Notes

### Version Numbering

SpectrusGuard follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR**: Incompatible API changes, major features
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

Example: `3.0.0` → `MAJOR 3`, `MINOR 0`, `PATCH 0`

### Supported Versions

| Version | Security Updates | Bug Fixes | Status |
|---------|------------------|-----------|--------|
| 3.0.x | ✅ Yes | ✅ Yes | Current |
| 2.1.x | ✅ Yes | ✅ Yes | Supported |
| 2.0.x | ❌ No | ❌ No | Deprecated |
| 1.0.x | ❌ No | ❌ No | Unsupported |

**End of Life**:
- Version 1.x: December 31, 2025
- Version 2.0.x: June 30, 2026

### Branching Strategy

- **`main`**: Production-ready, stable releases
- **`develop`**: Development branch, integration testing
- **`release/x.y.z`**: Release preparation branches
- **`feature/xxx`**: Feature branches
- **`bugfix/xxx`**: Bug fix branches

### Deployment Pipeline

1. Development in `develop` branch
2. Code review and testing
3. Create `release/x.y.z` branch
4. Final testing and documentation
5. Merge to `main` branch
6. Tag release
7. Deploy to production

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Reporting Bugs

Use [GitHub Issues](https://github.com/carlosindriago/SpectrusGuard/issues) with:
- WordPress version
- PHP version
- Plugin version
- Steps to reproduce
- Expected vs actual behavior

### Security Vulnerabilities

**Do NOT** use GitHub Issues for security vulnerabilities.

Email: **security@spectrusguard.com**

---

## License

SpectrusGuard is licensed under the **GPL v2 or later**.

See [LICENSE](LICENSE) for full details.

---

**Last Updated**: January 29, 2026
