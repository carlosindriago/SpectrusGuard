<?php
/**
 * SpectrusGuard CloudFlare IP Ranges Manager
 *
 * Automatically fetches and caches CloudFlare IP ranges for trusted proxy detection.
 * This is an opt-in feature configured via the onboarding wizard.
 *
 * @package SpectrusGuard
 * @since   3.0.7
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Cloudflare_IPs
 *
 * Manages CloudFlare IP ranges with automatic weekly updates via wp_cron.
 */
class SG_Cloudflare_IPs
{
    /**
     * CloudFlare IPv4 ranges endpoint
     */
    private const CLOUDFLARE_IPV4_URL = 'https://www.cloudflare.com/ips-v4';

    /**
     * CloudFlare IPv6 ranges endpoint
     */
    private const CLOUDFLARE_IPV6_URL = 'https://www.cloudflare.com/ips-v6';

    /**
     * Transient key for cached IP ranges
     */
    private const TRANSIENT_KEY = 'sg_cloudflare_ip_ranges';

    /**
     * Cache duration (1 week)
     */
    private const CACHE_DURATION = WEEK_IN_SECONDS;

    /**
     * Cron hook name
     */
    private const CRON_HOOK = 'sg_cloudflare_weekly_update';

    /**
     * Constructor - Register cron handler
     */
    public function __construct()
    {
        add_action(self::CRON_HOOK, [$this, 'refreshIpRanges']);
    }

    /**
     * Get cached CloudFlare IP ranges
     *
     * @return array List of CIDR ranges
     */
    public function getIpRanges(): array
    {
        $cached = get_transient(self::TRANSIENT_KEY);

        if ($cached !== false && is_array($cached)) {
            return $cached;
        }

        return $this->refreshIpRanges();
    }

    /**
     * Refresh IP ranges from CloudFlare API
     *
     * @return array List of CIDR ranges
     */
    public function refreshIpRanges(): array
    {
        $ipv4 = $this->fetchIpList(self::CLOUDFLARE_IPV4_URL);
        $ipv6 = $this->fetchIpList(self::CLOUDFLARE_IPV6_URL);

        $ranges = array_merge($ipv4, $ipv6);

        if (!empty($ranges)) {
            set_transient(self::TRANSIENT_KEY, $ranges, self::CACHE_DURATION);
            update_option('sg_cloudflare_last_update', time());
        }

        return $ranges;
    }

    /**
     * Fetch IP list from CloudFlare endpoint
     *
     * @param string $url CloudFlare API endpoint
     * @return array List of CIDR ranges
     */
    private function fetchIpList(string $url): array
    {
        $response = wp_remote_get($url, [
            'timeout' => 10,
            'sslverify' => true,
        ]);

        if (is_wp_error($response)) {
            return [];
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            return [];
        }

        $body = wp_remote_retrieve_body($response);
        $lines = explode("\n", $body);

        return array_filter(array_map('trim', $lines));
    }

    /**
     * Check if an IP belongs to CloudFlare
     *
     * @param string $ip IP address to check
     * @return bool True if IP is from CloudFlare
     */
    public function isCloudflareIp(string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        $ranges = $this->getIpRanges();

        foreach ($ranges as $range) {
            if ($this->ipInCidr($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is within a CIDR range
     *
     * @param string $ip   IP address
     * @param string $cidr CIDR notation range
     * @return bool True if IP is in range
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        // Handle IPv6
        if (strpos($cidr, ':') !== false) {
            return $this->ipv6InCidr($ip, $cidr);
        }

        // Handle single IP (no CIDR)
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Check if IPv6 is within a CIDR range
     *
     * @param string $ip   IPv6 address
     * @param string $cidr CIDR notation range
     * @return bool True if IP is in range
     */
    private function ipv6InCidr(string $ip, string $cidr): bool
    {
        // Skip if IP is IPv4
        if (strpos($ip, ':') === false) {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int) $bits;

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // Compare bit by bit
        $fullBytes = (int) floor($bits / 8);
        $remainingBits = $bits % 8;

        // Compare full bytes
        if (substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
            return false;
        }

        // Compare remaining bits
        if ($remainingBits > 0 && $fullBytes < 16) {
            $mask = 0xFF << (8 - $remainingBits);
            $ipByte = ord($ipBin[$fullBytes]);
            $subnetByte = ord($subnetBin[$fullBytes]);

            if (($ipByte & $mask) !== ($subnetByte & $mask)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Schedule weekly automatic updates
     */
    public function scheduleUpdates(): void
    {
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time(), 'weekly', self::CRON_HOOK);
        }
    }

    /**
     * Unschedule automatic updates
     */
    public function unscheduleUpdates(): void
    {
        wp_clear_scheduled_hook(self::CRON_HOOK);
    }

    /**
     * Get update status info
     *
     * @return array Status information
     */
    public function getStatus(): array
    {
        $ranges = get_transient(self::TRANSIENT_KEY);

        return [
            'enabled' => $this->isEnabled(),
            'ranges_count' => is_array($ranges) ? count($ranges) : 0,
            'last_update' => get_option('sg_cloudflare_last_update', null),
            'next_scheduled' => wp_next_scheduled(self::CRON_HOOK),
        ];
    }

    /**
     * Check if CloudFlare detection is enabled
     *
     * @return bool True if enabled
     */
    public function isEnabled(): bool
    {
        $settings = get_option('spectrus_shield_settings', []);

        return !empty($settings['cloudflare_enabled']);
    }

    /**
     * Enable CloudFlare detection
     */
    public function enable(): void
    {
        $settings = get_option('spectrus_shield_settings', []);
        $settings['cloudflare_enabled'] = true;
        update_option('spectrus_shield_settings', $settings);

        $this->scheduleUpdates();
        $this->refreshIpRanges();
    }

    /**
     * Disable CloudFlare detection
     */
    public function disable(): void
    {
        $settings = get_option('spectrus_shield_settings', []);
        $settings['cloudflare_enabled'] = false;
        update_option('spectrus_shield_settings', $settings);

        $this->unscheduleUpdates();
        delete_transient(self::TRANSIENT_KEY);
    }
}
