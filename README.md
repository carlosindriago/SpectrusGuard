# GhostShield: Advanced WAF & Stealth Security Suite

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

### Ghost Stealth (Anti-Fingerprinting)
- 🕵️ **Metadata Scrubbing**: Removes revealing meta tags (e.g., `<meta name="generator">`).
- 🔇 **Header Sanitization**: Strips HTTP headers like `X-Powered-By` and `Server`.
- 🎭 **Asset Obfuscation**: Hides version strings in CSS/JS files (`?ver=X.X`).
- 🚫 **Protocol Hardening**: Blocks XML-RPC and pingbacks to reduce attack surface.
- 🔐 **Login Cloaking**: Conceals `/wp-login.php` with a custom slug.

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

1. Upload the `GhostShield` directory to `/wp-content/plugins/`.
2. Activate the plugin via **Plugins > Installed Plugins**.
3. The MU-Plugin (Must-Use) component automatically installs to `wp-content/mu-plugins/`.
4. Configure settings via **GhostShield > Settings**.

## ⚙️ Configuration

### Rescue Mode (Fail-Safe)
If you accidentally lock yourself out, use the designated rescue URL:
```
https://yoursite.com/?ghost_rescue=YOUR_SECRET_KEY
```

The secret key is automatically generated and can be found in **GhostShield > Dashboard**.

### IP Whitelist
add trusted IP addresses that should never be blocked in **Settings > IP Whitelist**.

### Login Cloaking
1. Enable "Hide Login Page" in Settings.
2. Define your custom slug (e.g., `my-secret-access`).
3. Access your administration panel via `https://yoursite.com/my-secret-access`.

## 📂 Project Structure

```
ghost-shield/
├── ghost-shield.php            # Main Bootstrapper
├── uninstall.php               # Cleanup Routine
├── assets/
│   ├── css/admin.css           # Dashboard Styles (Enterprise Dark Theme)
│   └── js/admin.js             # Admin Interactions
├── includes/
│   ├── class-gs-loader.php     # Singleton Orchestrator
│   ├── class-gs-logger.php     # Logging System
│   ├── waf/
│   │   ├── class-gs-firewall.php  # WAF Engine
│   │   └── rules.json          # Regex Ruleset
│   ├── hardening/
│   │   ├── class-gs-stealth.php   # Anti-fingerprinting Module
│   │   └── class-gs-api-guard.php # REST API Protection
│   ├── scanner/
│   │   └── class-gs-scanner.php   # Integrity Scanner Engine
│   └── admin/
│       └── class-gs-admin.php  # Enterprise Dashboard Controller
├── mu-loader/
│   └── ghost-waf.php           # MU-Plugin DROP-IN
└── languages/                  # Localization Files
```

## 🔧 Design Patterns

- **Singleton**: `GS_Loader` - Ensures a single instance of the main orchestrator.
- **Factory**: `GS_Firewall` - Instantiates specific matchers based on attack vectors.
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

## 📄 License

GPL v2 or later. See [LICENSE](LICENSE) for details.

## 👨‍💻 Author

Developed by Carlos Developer

---

**⚠️ Note**: This plugin is designed for production environments. Always maintain a backup and test in a staging environment before deployment.
