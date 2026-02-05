<?php
/**
 * Page Controller: Help & Documentation
 *
 * Comprehensive in-plugin documentation for end users.
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Page_Help
 *
 * Renders the Help & Documentation page.
 */
class SG_Page_Help
{
    /**
     * Loader instance
     *
     * @var SG_Loader
     */
    private $loader;

    /**
     * Constructor
     *
     * @param SG_Loader $loader Loader instance.
     */
    public function __construct($loader)
    {
        $this->loader = $loader;
    }

    /**
     * Get help sections
     *
     * @return array
     */
    private function get_sections(): array
    {
        return [
            'getting-started' => [
                'title' => __('Getting Started', 'spectrus-guard'),
                'icon' => '🚀',
            ],
            'dashboard' => [
                'title' => __('Dashboard', 'spectrus-guard'),
                'icon' => '📊',
            ],
            'firewall' => [
                'title' => __('Firewall (WAF)', 'spectrus-guard'),
                'icon' => '🔥',
            ],
            'scanner' => [
                'title' => __('Malware Scanner', 'spectrus-guard'),
                'icon' => '🔍',
            ],
            'hardening' => [
                'title' => __('Hardening', 'spectrus-guard'),
                'icon' => '🛡️',
            ],
            'login-security' => [
                'title' => __('Login Security', 'spectrus-guard'),
                'icon' => '🔐',
            ],
            'geo-blocking' => [
                'title' => __('Geo-Blocking', 'spectrus-guard'),
                'icon' => '🌍',
            ],
            'api-hardening' => [
                'title' => __('API Protection', 'spectrus-guard'),
                'icon' => '🔌',
            ],
            'troubleshooting' => [
                'title' => __('Troubleshooting', 'spectrus-guard'),
                'icon' => '🔧',
            ],
            'faq' => [
                'title' => __('FAQ', 'spectrus-guard'),
                'icon' => '❓',
            ],
        ];
    }

    /**
     * Render the help page
     */
    public function render(): void
    {
        $sections = $this->get_sections();
        $active_section = isset($_GET['section']) ? sanitize_key($_GET['section']) : 'getting-started';

        if (!isset($sections[$active_section])) {
            $active_section = 'getting-started';
        }
        ?>
        <div class="wrap sg-dashboard">
            <div class="sg-dashboard-header">
                <h1>
                    <span class="sg-logo">📚</span>
                    <?php esc_html_e('Help & Documentation', 'spectrus-guard'); ?>
                </h1>
                <div class="sg-version-badge">v
                    <?php echo esc_html(SG_VERSION); ?>
                </div>
            </div>

            <div class="sg-help-container" style="display: flex; gap: 24px; margin-top: 24px;">
                <!-- Sidebar Navigation -->
                <nav class="sg-help-sidebar" style="width: 240px; flex-shrink: 0;">
                    <div class="sg-card" style="padding: 0; overflow: hidden;">
                        <?php foreach ($sections as $key => $section): ?>
                            <a href="<?php echo esc_url(admin_url('admin.php?page=spectrus-guard-help&section=' . $key)); ?>"
                                class="sg-help-nav-item <?php echo $active_section === $key ? 'active' : ''; ?>"
                                style="display: flex; align-items: center; gap: 12px; padding: 14px 18px; 
                                      text-decoration: none; color: var(--sg-text-secondary);
                                      border-bottom: 1px solid var(--sg-border);
                                      transition: all 0.2s ease;
                                      <?php echo $active_section === $key ? 'background: var(--sg-primary); color: white;' : ''; ?>">
                                <span style="font-size: 18px;">
                                    <?php echo $section['icon']; ?>
                                </span>
                                <span style="font-weight: 500;">
                                    <?php echo esc_html($section['title']); ?>
                                </span>
                            </a>
                        <?php endforeach; ?>
                    </div>

                    <!-- Quick Links -->
                    <div class="sg-card" style="margin-top: 16px; padding: 16px;">
                        <h4
                            style="margin: 0 0 12px 0; color: var(--sg-text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px;">
                            <?php esc_html_e('Resources', 'spectrus-guard'); ?>
                        </h4>
                        <a href="https://github.com/carlosindriago/SpectrusGuard" target="_blank"
                            style="display: block; padding: 8px 0; color: var(--sg-primary); text-decoration: none; font-size: 14px;">
                            📂
                            <?php esc_html_e('GitHub Repository', 'spectrus-guard'); ?>
                        </a>
                        <a href="https://github.com/carlosindriago/SpectrusGuard/issues" target="_blank"
                            style="display: block; padding: 8px 0; color: var(--sg-primary); text-decoration: none; font-size: 14px;">
                            🐛
                            <?php esc_html_e('Report an Issue', 'spectrus-guard'); ?>
                        </a>
                        <a href="https://github.com/carlosindriago/SpectrusGuard/releases" target="_blank"
                            style="display: block; padding: 8px 0; color: var(--sg-primary); text-decoration: none; font-size: 14px;">
                            📦
                            <?php esc_html_e('Changelog', 'spectrus-guard'); ?>
                        </a>
                    </div>
                </nav>

                <!-- Main Content -->
                <main class="sg-help-content" style="flex: 1; min-width: 0;">
                    <div class="sg-card">
                        <div class="sg-card-header">
                            <h2 style="display: flex; align-items: center; gap: 12px;">
                                <span style="font-size: 24px;">
                                    <?php echo $sections[$active_section]['icon']; ?>
                                </span>
                                <?php echo esc_html($sections[$active_section]['title']); ?>
                            </h2>
                        </div>
                        <div class="sg-card-body sg-help-article" style="line-height: 1.8; color: var(--sg-text-secondary);">
                            <?php $this->render_section($active_section); ?>
                        </div>
                    </div>
                </main>
            </div>

            <style>
                /* Full dark mode background */
                #wpcontent,
                #wpfooter {
                    background: var(--sg-bg-primary, #0f172a) !important;
                }

                #wpbody-content {
                    padding-bottom: 0 !important;
                }

                #wpfooter {
                    color: var(--sg-text-muted, #64748b);
                    border-top: 1px solid var(--sg-border, #334155);
                    margin-left: 0;
                    padding: 20px;
                }

                #wpfooter a {
                    color: var(--sg-primary, #6366f1);
                }

                .sg-help-nav-item:hover {
                    background: var(--sg-bg-tertiary) !important;
                    color: var(--sg-text-primary) !important;
                }

                .sg-help-nav-item.active:hover {
                    background: var(--sg-primary) !important;
                    color: white !important;
                }

                .sg-help-article h3 {
                    color: var(--sg-text-primary);
                    margin: 32px 0 16px 0;
                    padding-bottom: 8px;
                    border-bottom: 1px solid var(--sg-border);
                }

                .sg-help-article h3:first-child {
                    margin-top: 0;
                }

                .sg-help-article p {
                    margin: 12px 0;
                }

                .sg-help-article ul,
                .sg-help-article ol {
                    margin: 12px 0;
                    padding-left: 24px;
                }

                .sg-help-article li {
                    margin: 8px 0;
                }

                .sg-help-article code {
                    background: var(--sg-bg-tertiary);
                    padding: 2px 8px;
                    border-radius: 4px;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 13px;
                    color: var(--sg-primary);
                }

                .sg-help-article pre {
                    background: var(--sg-bg-tertiary);
                    padding: 16px;
                    border-radius: 8px;
                    overflow-x: auto;
                    margin: 16px 0;
                }

                .sg-help-article pre code {
                    background: none;
                    padding: 0;
                    color: var(--sg-text-secondary);
                }

                .sg-help-tip {
                    background: linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(5, 150, 105, 0.1) 100%);
                    border-left: 4px solid #10b981;
                    padding: 16px 20px;
                    border-radius: 0 8px 8px 0;
                    margin: 20px 0;
                }

                .sg-help-tip strong {
                    color: #10b981;
                }

                .sg-help-warning {
                    background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(217, 119, 6, 0.1) 100%);
                    border-left: 4px solid #f59e0b;
                    padding: 16px 20px;
                    border-radius: 0 8px 8px 0;
                    margin: 20px 0;
                }

                .sg-help-warning strong {
                    color: #f59e0b;
                }

                .sg-help-danger {
                    background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%);
                    border-left: 4px solid #ef4444;
                    padding: 16px 20px;
                    border-radius: 0 8px 8px 0;
                    margin: 20px 0;
                }

                .sg-help-danger strong {
                    color: #ef4444;
                }

                .sg-help-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }

                .sg-help-table th,
                .sg-help-table td {
                    padding: 12px 16px;
                    text-align: left;
                    border-bottom: 1px solid var(--sg-border);
                }

                .sg-help-table th {
                    background: var(--sg-bg-tertiary);
                    color: var(--sg-text-primary);
                    font-weight: 600;
                }

                .sg-help-table tr:hover {
                    background: var(--sg-bg-tertiary);
                }
            </style>
        </div>
        <?php
    }

    /**
     * Render section content
     *
     * @param string $section Section key.
     */
    private function render_section(string $section): void
    {
        switch ($section) {
            case 'getting-started':
                $this->render_getting_started();
                break;
            case 'dashboard':
                $this->render_dashboard();
                break;
            case 'firewall':
                $this->render_firewall();
                break;
            case 'scanner':
                $this->render_scanner();
                break;
            case 'hardening':
                $this->render_hardening();
                break;
            case 'login-security':
                $this->render_login_security();
                break;
            case 'geo-blocking':
                $this->render_geo_blocking();
                break;
            case 'api-hardening':
                $this->render_api_hardening();
                break;
            case 'troubleshooting':
                $this->render_troubleshooting();
                break;
            case 'faq':
                $this->render_faq();
                break;
        }
    }

    /**
     * Getting Started section
     */
    private function render_getting_started(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Welcome to SpectrusGuard', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('SpectrusGuard is a comprehensive WordPress security suite that provides multi-layered protection for your website. This guide will help you get started quickly.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('First Steps After Installation', 'spectrus-guard'); ?>
        </h3>
        <ol>
            <li>
                <strong>
                    <?php esc_html_e('Complete the Setup Wizard', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('If you haven\'t done so, the wizard will guide you through essential configuration.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Verify MU-Plugin Installation', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Check that the WAF is active. Look for the green "WAF Active" indicator on the Dashboard.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Run Your First Scan', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Go to Scanner and run a full scan to establish a baseline of your site\'s security.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Configure Login Protection', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Enable brute force protection and consider setting up 2FA for admin accounts.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Save Your Rescue Key', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Copy and securely store your Ghost Rescue URL in case you get locked out.', 'spectrus-guard'); ?>
            </li>
        </ol>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Pro Tip:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Start with the "Balanced" security level. You can increase strictness later as you become familiar with the plugin.', 'spectrus-guard'); ?>
        </div>

        <h3>
            <?php esc_html_e('Security Level Recommendations', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Site Type', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Recommended Level', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Notes', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>
                        <?php esc_html_e('Personal Blog', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Balanced', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Good protection without complexity', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>
                        <?php esc_html_e('Business Website', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Balanced + 2FA', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Enable 2FA for all admin users', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>
                        <?php esc_html_e('E-Commerce (WooCommerce)', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Strict', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Add API whitelist for payment gateways', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>
                        <?php esc_html_e('High-Traffic / Enterprise', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Custom', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Configure trusted proxies for CDN', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>
        <?php
    }

    /**
     * Dashboard section
     */
    private function render_dashboard(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Understanding the Dashboard', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The SpectrusGuard Dashboard provides a real-time overview of your site\'s security status.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('Security Alerts', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Colored banners at the top indicate potential security issues:', 'spectrus-guard'); ?>
        </p>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Color', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Meaning', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Action', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>🔴
                        <?php esc_html_e('Red', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Critical security issue', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Address immediately', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>🟠
                        <?php esc_html_e('Orange', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Warning - potential vulnerability', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Review and fix when possible', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>🔵
                        <?php esc_html_e('Blue', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Informational notice', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Optional improvements', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Threat Intelligence Cards', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The main cards show attack statistics:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li><strong>💉 SQL Injection</strong> -
                <?php esc_html_e('Attempts to manipulate database queries', 'spectrus-guard'); ?>
            </li>
            <li><strong>⚡ XSS</strong> -
                <?php esc_html_e('Cross-Site Scripting attempts to inject malicious scripts', 'spectrus-guard'); ?>
            </li>
            <li><strong>🔓 RCE</strong> -
                <?php esc_html_e('Remote Code Execution attempts to run commands on your server', 'spectrus-guard'); ?>
            </li>
            <li><strong>📁 Path Traversal</strong> -
                <?php esc_html_e('Attempts to access files outside allowed directories', 'spectrus-guard'); ?>
            </li>
        </ul>

        <h3>
            <?php esc_html_e('Activity Chart', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The 30-day chart visualizes attack trends. Use this to:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li>
                <?php esc_html_e('Identify attack patterns (e.g., attacks on weekends)', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Detect sudden spikes that may indicate targeted attacks', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Verify that protections are working (blocked count should increase)', 'spectrus-guard'); ?>
            </li>
        </ul>
        <?php
    }

    /**
     * Firewall section
     */
    private function render_firewall(): void
    {
        ?>
        <h3>
            <?php esc_html_e('How the WAF Works', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The Web Application Firewall (WAF) inspects every incoming request before WordPress loads. This provides zero-latency protection against common attacks.', 'spectrus-guard'); ?>
        </p>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Why MU-Plugin?', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('The WAF runs as a Must-Use Plugin (MU-Plugin) to ensure it executes before any other code, providing maximum protection.', 'spectrus-guard'); ?>
        </div>

        <h3>
            <?php esc_html_e('Attack Types Detected', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Attack', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Description', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Example', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>SQL Injection</strong></td>
                    <td>
                        <?php esc_html_e('Malicious SQL in form inputs', 'spectrus-guard'); ?>
                    </td>
                    <td><code>' OR 1=1 --</code></td>
                </tr>
                <tr>
                    <td><strong>XSS</strong></td>
                    <td>
                        <?php esc_html_e('JavaScript injection', 'spectrus-guard'); ?>
                    </td>
                    <td><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></td>
                </tr>
                <tr>
                    <td><strong>RCE</strong></td>
                    <td>
                        <?php esc_html_e('Command execution attempts', 'spectrus-guard'); ?>
                    </td>
                    <td><code>system('ls')</code></td>
                </tr>
                <tr>
                    <td><strong>LFI/RFI</strong></td>
                    <td>
                        <?php esc_html_e('File inclusion attacks', 'spectrus-guard'); ?>
                    </td>
                    <td><code>../../etc/passwd</code></td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Firewall Settings', 'spectrus-guard'); ?>
        </h3>
        <ul>
            <li>
                <strong>
                    <?php esc_html_e('Enable WAF', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Master switch for the firewall. When disabled, no requests are blocked.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Log Attacks', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Records blocked requests. Essential for monitoring and debugging.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Rate Limiting', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Limits requests per IP to prevent DDoS. Default: 60 requests/minute.', 'spectrus-guard'); ?>
            </li>
        </ul>

        <div class="sg-help-warning">
            <strong>⚠️
                <?php esc_html_e('False Positives', 'spectrus-guard'); ?>
            </strong><br>
            <?php esc_html_e('If legitimate requests are being blocked, check the logs and add exceptions to the whitelist.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * Scanner section
     */
    private function render_scanner(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Malware Scanner Overview', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The scanner inspects your WordPress files for malware, backdoors, and suspicious code patterns.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('Scan Types', 'spectrus-guard'); ?>
        </h3>
        <ul>
            <li>
                <strong>
                    <?php esc_html_e('Quick Scan', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Checks only high-risk directories (uploads, plugins). Fast, ~1-2 minutes.', 'spectrus-guard'); ?>
            </li>
            <li>
                <strong>
                    <?php esc_html_e('Full Scan', 'spectrus-guard'); ?>
                </strong><br>
                <?php esc_html_e('Scans entire wp-content folder. More thorough, ~5-15 minutes depending on site size.', 'spectrus-guard'); ?>
            </li>
        </ul>

        <h3>
            <?php esc_html_e('Severity Levels', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Level', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Description', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Recommended Action', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>🔴
                        <?php esc_html_e('Critical', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Confirmed malware or backdoor', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Quarantine immediately', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>🟠
                        <?php esc_html_e('High', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Highly suspicious code', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Investigate and likely quarantine', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>🟡
                        <?php esc_html_e('Medium', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Potentially harmful patterns', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Review code before action', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td>🔵
                        <?php esc_html_e('Low', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Unusual but likely benign', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Monitor, usually safe to ignore', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Quarantine', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('When you quarantine a file:', 'spectrus-guard'); ?>
        </p>
        <ol>
            <li>
                <?php esc_html_e('The file is moved to a secure vault directory', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('The original path and permissions are recorded', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('You can restore it if it was a false positive', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('After 30 days, quarantined files can be permanently deleted', 'spectrus-guard'); ?>
            </li>
        </ol>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Best Practice:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Run a scan after every plugin/theme update and at least weekly for active sites.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * Hardening section
     */
    private function render_hardening(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Security Hardening Features', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Hardening reduces your attack surface by hiding or disabling WordPress features that attackers commonly exploit.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('Stealth Mode', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Feature', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('What It Does', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('When to Use', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Hide WordPress Version', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Removes version numbers from HTML and feeds', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Always recommended', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Disable XML-RPC', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Blocks xmlrpc.php used in brute force attacks', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Enable unless you use Jetpack or WP mobile app', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Disable Author Archives', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Prevents username enumeration via ?author=1', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Recommended for most sites', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Remove Generator Meta', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Removes WordPress generator tag from &lt;head&gt;', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('Always recommended', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Ghost Cloak (URL Masking)', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Hides common WordPress directories:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li><code>/wp-content/</code> →
                <?php esc_html_e('Custom path (e.g., /assets/)', 'spectrus-guard'); ?>
            </li>
            <li><code>/wp-includes/</code> →
                <?php esc_html_e('Custom path (e.g., /core/)', 'spectrus-guard'); ?>
            </li>
        </ul>

        <div class="sg-help-warning">
            <strong>⚠️
                <?php esc_html_e('Caution:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Ghost Cloak may break some plugins that generate hardcoded URLs. Test in staging first.', 'spectrus-guard'); ?>
        </div>

        <h3>
            <?php esc_html_e('Custom Login URL', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Changes your login page from the default /wp-login.php to a custom slug:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li>
                <?php esc_html_e('Default:', 'spectrus-guard'); ?> <code>/wp-login.php</code>
            </li>
            <li>
                <?php esc_html_e('Custom:', 'spectrus-guard'); ?> <code>/my-secret-login</code>
            </li>
        </ul>
        <p>
            <?php esc_html_e('Attackers trying /wp-login.php will see a 404 error.', 'spectrus-guard'); ?>
        </p>

        <div class="sg-help-danger">
            <strong>🚨
                <?php esc_html_e('Important:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Save your custom login URL and Ghost Rescue key! If you forget it, use the rescue URL to regain access.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * Login Security section
     */
    private function render_login_security(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Brute Force Protection', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Limits failed login attempts to prevent password guessing attacks.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('Settings Explained', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Setting', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Description', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Recommended', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Max Attempts', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Failed logins before lockout', 'spectrus-guard'); ?>
                    </td>
                    <td>5</td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Lockout Duration', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('How long to block after max attempts', 'spectrus-guard'); ?>
                    </td>
                    <td>
                        <?php esc_html_e('60 minutes', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Lockout Multiplier', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Increases duration for repeat offenders', 'spectrus-guard'); ?>
                    </td>
                    <td>2x</td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Two-Factor Authentication (2FA)', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Adds a second verification step using an authenticator app (Google Authenticator, Authy, etc.).', 'spectrus-guard'); ?>
        </p>

        <h4>
            <?php esc_html_e('Setting Up 2FA:', 'spectrus-guard'); ?>
        </h4>
        <ol>
            <li>
                <?php esc_html_e('Go to Users → Your Profile', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Find the "SpectrusGuard 2FA" section', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Scan the QR code with your authenticator app', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Enter the 6-digit code to verify', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Save backup codes in a secure location', 'spectrus-guard'); ?>
            </li>
        </ol>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Recommendation:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Enable 2FA for all administrator accounts. It\'s the single most effective protection against account takeover.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * Geo-Blocking section
     */
    private function render_geo_blocking(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Geographic Access Control', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Block or limit access from specific countries or regions based on IP geolocation.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('When to Use Geo-Blocking', 'spectrus-guard'); ?>
        </h3>
        <ul>
            <li>
                <?php esc_html_e('Your business only serves specific regions', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('You\'re experiencing attacks from specific countries', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Regulatory compliance requires regional restrictions', 'spectrus-guard'); ?>
            </li>
        </ul>

        <h3>
            <?php esc_html_e('Block Actions', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Action', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Description', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>403 Block</strong></td>
                    <td>
                        <?php esc_html_e('Shows access denied page (most common)', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>CAPTCHA</strong></td>
                    <td>
                        <?php esc_html_e('Allows access after solving challenge (coming soon)', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>Redirect</strong></td>
                    <td>
                        <?php esc_html_e('Redirects to a custom URL', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('Tor Blocking', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The Tor network anonymizes users, which can be used for legitimate privacy or for malicious attacks. Consider:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li>
                <?php esc_html_e('Block Tor for admin pages (recommended)', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Allow Tor for public content if privacy is important to your users', 'spectrus-guard'); ?>
            </li>
        </ul>

        <div class="sg-help-warning">
            <strong>⚠️
                <?php esc_html_e('Note:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('Geo-blocking is not 100% accurate. VPNs can bypass country restrictions. Use as one layer of defense, not the only protection.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * API Hardening section
     */
    private function render_api_hardening(): void
    {
        ?>
        <h3>
            <?php esc_html_e('REST API Protection', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('The WordPress REST API exposes data endpoints. While useful for modern development, it can leak information.', 'spectrus-guard'); ?>
        </p>

        <h3>
            <?php esc_html_e('Available Protections', 'spectrus-guard'); ?>
        </h3>
        <table class="sg-help-table">
            <thead>
                <tr>
                    <th>
                        <?php esc_html_e('Feature', 'spectrus-guard'); ?>
                    </th>
                    <th>
                        <?php esc_html_e('Protection', 'spectrus-guard'); ?>
                    </th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Block User Enumeration', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Prevents /wp-json/wp/v2/users from revealing usernames', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Hide REST Index', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Hides available endpoints from non-admins', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Custom REST Prefix', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Changes /wp-json/ to custom path', 'spectrus-guard'); ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>
                            <?php esc_html_e('Require Authentication', 'spectrus-guard'); ?>
                        </strong></td>
                    <td>
                        <?php esc_html_e('Forces login for all API requests', 'spectrus-guard'); ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <h3>
            <?php esc_html_e('API Whitelist', 'spectrus-guard'); ?>
        </h3>
        <p>
            <?php esc_html_e('Some plugins require public API access. SpectrusGuard automatically whitelists:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li><strong>WooCommerce</strong> -
                <?php esc_html_e('Checkout and store endpoints', 'spectrus-guard'); ?>
            </li>
            <li><strong>Contact Form 7</strong> -
                <?php esc_html_e('Form submission endpoints', 'spectrus-guard'); ?>
            </li>
            <li><strong>Jetpack</strong> -
                <?php esc_html_e('WordPress.com connection', 'spectrus-guard'); ?>
            </li>
            <li><strong>oEmbed</strong> -
                <?php esc_html_e('Content embedding (YouTube, Twitter)', 'spectrus-guard'); ?>
            </li>
        </ul>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Custom Whitelist:', 'spectrus-guard'); ?>
            </strong>
            <?php esc_html_e('If a plugin stops working after enabling API protection, add its namespace to the whitelist in Settings → API Hardening.', 'spectrus-guard'); ?>
        </div>
        <?php
    }

    /**
     * Troubleshooting section
     */
    private function render_troubleshooting(): void
    {
        ?>
        <h3>
            <?php esc_html_e('Common Issues & Solutions', 'spectrus-guard'); ?>
        </h3>

        <h4>🔒
            <?php esc_html_e('I\'m locked out of my site', 'spectrus-guard'); ?>
        </h4>
        <p>
            <?php esc_html_e('Use the Ghost Rescue URL:', 'spectrus-guard'); ?>
        </p>
        <pre><code>https://yoursite.com/?spectrus_rescue=YOUR_RESCUE_KEY</code></pre>
        <p>
            <?php esc_html_e('This temporarily disables security features so you can fix configuration issues.', 'spectrus-guard'); ?>
        </p>

        <h4>🔥
            <?php esc_html_e('WAF is blocking legitimate requests', 'spectrus-guard'); ?>
        </h4>
        <ol>
            <li>
                <?php esc_html_e('Check the Firewall Logs to identify the blocked request', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Go to Whitelist and add the pattern or path', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Test the functionality again', 'spectrus-guard'); ?>
            </li>
        </ol>

        <h4>🌍
            <?php esc_html_e('Geo-blocking isn\'t working', 'spectrus-guard'); ?>
        </h4>
        <p>
            <?php esc_html_e('Possible causes:', 'spectrus-guard'); ?>
        </p>
        <ul>
            <li>
                <?php esc_html_e('GeoLite2 database not installed (check Firewall → Geo tab)', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Your IP might be whitelisted', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('CDN/proxy not configured in Trusted Proxies', 'spectrus-guard'); ?>
            </li>
        </ul>

        <h4>⚙️
            <?php esc_html_e('Plugin conflicts', 'spectrus-guard'); ?>
        </h4>
        <p>
            <?php esc_html_e('If you experience issues after activating SpectrusGuard:', 'spectrus-guard'); ?>
        </p>
        <ol>
            <li>
                <?php esc_html_e('Enter Rescue Mode', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Disable one feature at a time to identify the conflict', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Common conflicts: caching plugins, other security plugins', 'spectrus-guard'); ?>
            </li>
        </ol>

        <h4>📊
            <?php esc_html_e('Dashboard shows no data', 'spectrus-guard'); ?>
        </h4>
        <ul>
            <li>
                <?php esc_html_e('Ensure "Log Attacks" is enabled', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Wait for traffic - data appears after blocked attacks', 'spectrus-guard'); ?>
            </li>
            <li>
                <?php esc_html_e('Check that wp-content/spectrus-guard-logs/ is writable', 'spectrus-guard'); ?>
            </li>
        </ul>

        <div class="sg-help-tip">
            <strong>💡
                <?php esc_html_e('Still having issues?', 'spectrus-guard'); ?>
            </strong>
            <?php
            printf(
                esc_html__('Open an issue on %sGitHub%s with your WordPress version, PHP version, and detailed error description.', 'spectrus-guard'),
                '<a href="https://github.com/carlosindriago/SpectrusGuard/issues" target="_blank">',
                '</a>'
            );
            ?>
        </div>
        <?php
    }

    /**
     * FAQ section
     */
    private function render_faq(): void
    {
        $faqs = [
            [
                'q' => __('Is SpectrusGuard compatible with Cloudflare?', 'spectrus-guard'),
                'a' => __('Yes! Enable "Cloudflare IP Integration" in Settings → Advanced to ensure correct IP detection behind Cloudflare\'s proxy.', 'spectrus-guard'),
            ],
            [
                'q' => __('Can I use SpectrusGuard with other security plugins?', 'spectrus-guard'),
                'a' => __('Generally not recommended. Running multiple WAFs can cause conflicts and performance issues. Choose one comprehensive solution.', 'spectrus-guard'),
            ],
            [
                'q' => __('Will SpectrusGuard slow down my site?', 'spectrus-guard'),
                'a' => __('No. The WAF adds less than 2ms per request. The dashboard uses AJAX loading to avoid impacting frontend performance.', 'spectrus-guard'),
            ],
            [
                'q' => __('How do I completely disable the plugin temporarily?', 'spectrus-guard'),
                'a' => __('Use the Ghost Rescue URL, or rename/delete wp-content/mu-plugins/spectrus-waf.php via FTP.', 'spectrus-guard'),
            ],
            [
                'q' => __('Does SpectrusGuard work on multisite?', 'spectrus-guard'),
                'a' => __('Partially. The WAF protects all sites, but admin settings are per-site. Network-wide settings coming in a future version.', 'spectrus-guard'),
            ],
            [
                'q' => __('How often should I run malware scans?', 'spectrus-guard'),
                'a' => __('At least weekly for active sites. After every plugin/theme update. Immediately if you notice suspicious activity.', 'spectrus-guard'),
            ],
            [
                'q' => __('What happens if I forget my custom login URL?', 'spectrus-guard'),
                'a' => __('Use the Ghost Rescue URL (saved during setup) or access via FTP and edit the database option "spectrus_shield_settings".', 'spectrus-guard'),
            ],
            [
                'q' => __('Is my data sent to external servers?', 'spectrus-guard'),
                'a' => __('No. All processing is local. The only external connections are optional: Cloudflare IP list updates and integrity verification against GitHub.', 'spectrus-guard'),
            ],
        ];
        ?>
        <h3>
            <?php esc_html_e('Frequently Asked Questions', 'spectrus-guard'); ?>
        </h3>

        <?php foreach ($faqs as $index => $faq): ?>
            <div style="margin-bottom: 20px; border-bottom: 1px solid var(--sg-border); padding-bottom: 20px;">
                <h4 style="margin: 0 0 8px 0; color: var(--sg-text-primary);">
                    <?php echo ($index + 1) . '. ' . esc_html($faq['q']); ?>
                </h4>
                <p style="margin: 0; color: var(--sg-text-secondary);">
                    <?php echo esc_html($faq['a']); ?>
                </p>
            </div>
        <?php endforeach; ?>

        <div class="sg-help-tip">
            <strong>❓
                <?php esc_html_e('Have a question not listed here?', 'spectrus-guard'); ?>
            </strong><br>
            <?php
            printf(
                esc_html__('Check the %sGitHub Discussions%s or open an issue.', 'spectrus-guard'),
                '<a href="https://github.com/carlosindriago/SpectrusGuard/discussions" target="_blank">',
                '</a>'
            );
            ?>
        </div>
        <?php
    }
}
