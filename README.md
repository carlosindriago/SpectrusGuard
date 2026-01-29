# SpectrusGuard: Advanced WAF & Stealth Security Suite

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-green.svg)
![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-orange.svg)

**SpectrusGuard** is an enterprise-grade security plugin for WordPress that combines a high-performance WAF, advanced stealth capabilities, and a modern "Immersive Mode" administration interface. It is designed to intercept attacks at the application layer, mask the CMS footprint, and provide granular access control.

## 🚀 Key Features

### 🛡️ Web Application Firewall (WAF)
- **Zero-Latency Drop-In**: Operates as an MU-Plugin to intercept threats *before* WordPress loads.
- **Deep Packet Inspection**: Proactively blocks **SQL Injection**, **XSS**, **RCE**, **LFI/RFI**, and **Path Traversal**.
- **Geo-Defense Strategy**:
  - 🌍 **Country Blocking**: Restrict access by nation using a local MaxMind GeoLite2 database.
  - 🧅 **Tor Node Detection**: Automatically identify and block traffic from the Tor anonymity network.
- **Intelligent Ruleset**: Regex-based pattern matching with sophisticated decoding to prevent evasion.

### 👻 Stealth & Hardening
- **Ghost Cloak**: Completely hides standard WordPress paths (`/wp-content`, `/wp-includes`) via rewrite rules.
- **Login Defense**:
  - 🚫 **Hide Login Page**: Move `/wp-login.php` to a custom secret slug.
  - 🔐 **Zero-Trust 2FA**: Enforce Two-Factor Authentication (TOTP) for administrators and privileged roles.
  - 🛑 **Brute Force Protection**: Intelligent lockout mechanism with configurable attempts and duration.
- **Fingerprint Erasure**: Removes `X-Powered-By` headers, WP version generators, and blocks XML-RPC/REST API enumeration.

### 🖥️ Immersive Admin Interface
- **SPA-Like Experience**: A fully custom "Immersive Mode" UI that overrides standard WordPress styling.
- **Dark Mode**: High-contrast Slate/Indigo theme optimized for security operations centers (SOC).
- **Page Controller Architecture**: Modular backend design ensuring speed and code maintainability.
- **Unified Dashboard**:
  - **Threat Intelligence**: Real-time visual metrics of attack vectors.
  - **Activity Logs**: Integrated traffic inspection with severity tagging.
  - **Quick Actions**: Rapid response tools for emergency hardening.

## 📦 Installation

1. Upload the `SpectrusGuard` directory to `/wp-content/plugins/`.
2. Activate the plugin via WordPress Admin.
3. The WAF Drop-In (`ghost-waf.php`) will automatically install to `/wp-content/mu-plugins/`.
4. Navigate to the **SpectrusGuard** menu to configure your policy.

## ⚙️ Configuration Hints

### 🆘 Rescue Mode
Locked out? Use the emergency bypass URL defined in your dashboard:
```
https://yoursite.com/?spectrus_rescue=YOUR_GENERATED_KEY
```

### 🌍 Geo-IP Setup
1. Go to **Firewall > Geo-Defense**.
2. Click **Update Database** to download the latest MaxMind GeoLite2 City DB.
3. Select countries to block from the interactive list.

## 🏗️ Architecture

SpectrusGuard 2.0 adopts a **Page Controller Pattern** for robust scalability and separation of concerns.

```tree
spectrus-guard/
├── spectrus-guard.php            # Bootshrapper
├── includes/
│   ├── class-sg-loader.php       # Dependency Injection Container
│   ├── admin/
│   │   ├── class-sg-admin.php    # Main Router
│   │   └── pages/                # Page Controllers
│   │       ├── class-sg-page-dashboard.php
│   │       ├── class-sg-page-firewall.php
│   │       ├── class-sg-page-scanner.php
│   │       ├── class-sg-page-hardening.php
│   │       └── class-sg-page-settings.php
│   ├── geo/                      # Geo-Defense Engine
│   │   ├── class-sg-geo-engine.php
│   │   └── class-sg-maxmind-reader.php
│   ├── waf/                      # Firewall Core
│   └── hardening/                # Security Modules
├── assets/
│   └── css/
│       └── admin.css             # Immersive Mode Styles
└── mu-loader/
    └── ghost-waf.php             # Early Execution WAF
```

## 🔐 Security Standards

- **Context-Aware Sanitization**: Strict input validation using `sanitize_text_field`, `absint`, and custom regex.
- **Nonce Verification**: All AJAX actions and form submissions are protected against CSRF.
- **Capability Checks**: Administrative functions strictly require `manage_options`.

## 📄 License

GPL v2 or later.

---
**Developed with ❤️ by SpectrusGuard Team**
