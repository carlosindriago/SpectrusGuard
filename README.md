# SpectrusGuard: Advanced WAF & Stealth Security Suite

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.8%2B-green.svg)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-orange.svg)

**A comprehensive security system** designed to intercept attacks before they reach your site and camouflage your WordPress instance, making it invisible to automated scanners and hackers.

## 🛡️ Key Features

### Web Application Firewall (WAF)
- ⚡ **MU-Plugin DROP-IN**: Executes BEFORE WordPress loads for maximum efficiency.
- 🔒 **Defense Vector**: Proactive protection against **SQL Injection**, **XSS**, **RCE**, **Path Traversal**, and **LFI**.
- 📋 **Extensible Ruleset**: Regex-based rules defined in `rules.json`.
- 🔄 **Multi-Layer Decoding**: Handles encoded payloads to prevent filter evasion.
- 📊 **Detailed Logging**: Comprehensive attack logging with automatic rotation.

### Ghost Cloak™ (Advanced Stealth Obfuscation)
- 🕵️ **URL Path Rewriting**: Dynamically obfuscates `wp-content`, `wp-includes`, and plugin directories.
- 🎭 **Plugin Masking Studio**: Custom fake names for installed plugins to confuse scanners.
- 🔄 **Dynamic Mapping**: Database-driven configuration for plugin obfuscation.
- 🧹 **CSS Class Cleaning**: Removes revealing WordPress body classes.
- 🌐 **Server Rule Generation**: Automatic `.htaccess`/Nginx rules creation.
- 🆘 **Ghost Rescue Mode**: Emergency access key to bypass cloaking if locked out.

### Login Guard (Access Control)
- 🔐 **Custom Login Slug**: Replace `wp-login.php` with a secret URL (e.g., `/ghost-access`).
- 🚫 **Admin Panel Protection**: Block `/wp-admin` access for non-authenticated users (returns 404).
- 🔄 **URL Filtering**: Automatically rewrites all WordPress-generated login URLs.
- ✅ **Logout Protection**: Allows logout actions while blocking unauthorized access.
- 🛡️ **Scope Fix**: Proper global declarations for seamless `wp-login.php` integration.

### Two-Factor Authentication (2FA)
- 🔑 **TOTP Engine**: Time-based one-time passwords compatible with Google Authenticator, Authy.
- 📱 **QR Code Setup**: Easy enrollment with automatic QR code generation.
- 🔒 **Mandatory Verification**: Force 2FA for admin/editor roles.
- 📋 **Backup Codes**: Recovery codes for emergency access.
- 🎨 **Integrated UI**: Seamless setup and verification interfaces.

### Legacy Stealth Features
- 🕵️ **Metadata Scrubbing**: Removes revealing meta tags (e.g., `<meta name="generator">`).
- 🔇 **Header Sanitization**: Strips HTTP headers like `X-Powered-By` and `Server`.
- 🎭 **Asset Obfuscation**: Hides version strings in CSS/JS files (`?ver=X.X`).
- 🚫 **Protocol Hardening**: Blocks XML-RPC and pingbacks to reduce attack surface.

### API Guard
- 🛑 **Enumeration Blocking**: Prevents user enumeration via REST API endpoints.
- 🍯 **Honeypot Mechanism**: Trap for bots in the login form.
- ⏱️ **Rate Limiting**: Mitigates brute-force attempts on sensitive endpoints.
- 📝 **Intrusion Detection**: Logs suspicious bot activity.

### Enterprise Dashboard
- 🖥️ **Unified Hero Section**: Central command center displaying real-time security status and scan results.
- 📊 **Threat Intel Grid**: Visual metrics for attack vectors with sparklines and semantic status indicators.
- 🌙 **Professional Dark Mode**: Modern, high-contrast dark theme (Slate/Blue palette) optimized for readability.
- 🖱️ **Smart Sidebar**: Quick access to critical actions and a compact Rescue Mode panel.
- 📈 **Interactive Analytics**: Dynamic activity chart visualizing attack trends over the last 30 days.

## 📦 Installation

1. Upload the `SpectrusGuard` directory to `/wp-content/plugins/`.
2. Activate the plugin via **Plugins > Installed Plugins**.
3. The MU-Plugin (Must-Use) component automatically installs to `wp-content/mu-plugins/`.
4. Configure settings via **SpectrusGuard > Settings**.

## ⚙️ Configuration

### Rescue Mode (Fail-Safe)
If you accidentally lock yourself out, use the designated rescue URL:
```
https://yoursite.com/?spectrus_rescue=YOUR_SECRET_KEY
```

The secret key is automatically generated and can be found in **SpectrusGuard > Dashboard**.

### IP Whitelist
add trusted IP addresses that should never be blocked in **Settings > IP Whitelist**.

### Ghost Cloak Configuration
1. Navigate to **SpectrusGuard > Settings > Ghost Cloak**.
2. Enable the "URL Cloaking" toggle.
3. Configure **Login Hider**:
   - Set custom login slug (e.g., `secret-door`).
   - Access admin via: `https://yoursite.com/secret-door`
4. Configure **Plugin Masking Studio**:
   - Add real plugin names (e.g., `woocommerce`).
   - Assign fake names (e.g., `shop-core`).
   - Click "Randomize" 🎲 for auto-generated names.
5. **Write Server Rules** to apply `.htaccess`/Nginx rewrite rules.
6. Save your **Ghost Rescue Key** for emergency access:
   ```
   https://yoursite.com/?ghost_rescue=YOUR_GHOST_KEY
   ```

### Two-Factor Authentication (2FA)
1. Go to **SpectrusGuard > Settings > 2FA**.
2. Enable 2FA and scan the QR code with your authenticator app.
3. Enter the verification code to complete setup.
4. Save backup codes in a secure location.

## 📂 Project Structure

```
spectrus-guard/
├── spectrus-guard.php            # Main Bootstrapper
├── uninstall.php               # Cleanup Routine
├── assets/
│   ├── css/admin.css           # Dashboard Styles (Enterprise Dark Theme)
│   └── js/admin.js             # Admin Interactions
├── includes/
│   ├── class-sg-loader.php     # Singleton Orchestrator
│   ├── class-sg-logger.php     # Logging System
│   ├── waf/
│   │   ├── class-sg-firewall.php  # WAF Engine
│   │   └── rules.json          # Regex Ruleset
│   ├── hardening/
│   │   ├── class-sg-stealth.php      # Legacy Anti-fingerprinting
│   │   ├── class-sg-cloak-engine.php # Ghost Cloak URL Rewriting Engine
│   │   ├── class-sg-login-guard.php  # Login & Admin Access Control
│   │   ├── class-sg-ghost-rescue.php # Emergency Access System
│   │   ├── class-sg-api-guard.php    # REST API Protection
│   │   └── views/
│   │       └── settings-cloak.php    # Ghost Cloak Configuration UI
│   ├── auth/
│   │   ├── class-sg-2fa-handler.php  # 2FA Authentication Logic
│   │   ├── class-sg-totp-engine.php  # TOTP Generator
│   │   └── views/
│   │       ├── setup-2fa.php         # 2FA Setup Interface
│   │       └── verify-2fa.php        # 2FA Verification Screen
│   ├── scanner/
│   │   └── class-sg-scanner.php   # Integrity Scanner Engine
│   └── admin/
│       └── class-sg-admin.php  # Enterprise Dashboard Controller
├── mu-loader/
│   └── ghost-waf.php           # MU-Plugin DROP-IN
└── languages/                  # Localization Files
```

## 🔧 Design Patterns

- **Singleton**: `SG_Loader` - Ensures a single instance of the main orchestrator.
- **Factory**: `SG_Firewall` - Instantiates specific matchers based on attack vectors.
- **Observer**: Hooks into WordPress actions for alerts and notifications.

## 🔐 Security Best Practices

The codebase adheres to strict WordPress security standards:

- ✅ `esc_html()`, `esc_attr()` for output escaping.
- ✅ `sanitize_text_field()` for input sanitization.
- ✅ `wp_verify_nonce()` for CSRF protection on all AJAX calls.
- ✅ `current_user_can('manage_options')` for capability checks.
- ✅ Prepared statements for all database queries.

## 📋 Roadmap

- [x] **Sprint 1**: WAF Core & MU-Plugin Implementation
- [x] **Sprint 2**: Hardening & Stealth Module
- [x] **Sprint 3**: Integrity & Malware Scanner
- [x] **Sprint 4**: URL Cloaking & Advanced Features
- [x] **Sprint 5**: Enterprise UI/UX Overhaul (Dashboard Redesign)
- [x] **Sprint 6**: Ghost Cloak Engine (Dynamic URL Obfuscation)
- [x] **Sprint 7**: Login Guard & Plugin Masking Studio
- [x] **Sprint 8**: Two-Factor Authentication (TOTP)
- [ ] **Sprint 9**: Geo-Blocking & IP Intelligence
- [ ] **Sprint 10**: Advanced Threat Analytics & ML Detection

## 📄 License

GPL v2 or later. See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

Developed by Carlos Developer

---

**⚠️ Note**: This plugin is designed for production environments. Always maintain a backup and test in a staging environment before deployment.
