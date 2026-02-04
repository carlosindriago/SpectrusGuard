<?php
/**
 * SpectrusGuard IP Detection Trait
 *
 * Provides secure client IP detection with trusted proxy validation.
 * This trait should be used by all classes that need to determine client IP.
 *
 * @package SpectrusGuard
 * @since   3.0.7
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Trait IpDetectionTrait
 *
 * Secure IP detection with trusted proxy support.
 */
trait IpDetectionTrait
{
    /**
     * Get the real client IP address securely
     *
     * Only trusts proxy headers if the request comes from a trusted proxy.
     *
     * @param array $trustedProxies Optional. List of trusted proxy IPs or CIDR ranges.
     * @return string Client IP address
     */
    protected function getClientIpSecure(array $trustedProxies = []): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Validate REMOTE_ADDR
        if (!filter_var($remoteAddr, FILTER_VALIDATE_IP)) {
            return '0.0.0.0';
        }

        // If no trusted proxies, only trust REMOTE_ADDR
        if (empty($trustedProxies)) {
            return $remoteAddr;
        }

        // Check if request comes from a trusted proxy
        if (!$this->isFromTrustedProxy($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        // Proxy headers in priority order
        $proxyHeaders = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',        // Nginx proxy
            'HTTP_X_FORWARDED_FOR',  // Standard proxy header
        ];

        foreach ($proxyHeaders as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $this->extractFirstIp($_SERVER[$header]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return $remoteAddr;
    }

    /**
     * Check if request comes from a trusted proxy
     *
     * @param string $ip             IP to check
     * @param array  $trustedProxies List of trusted IPs/CIDRs
     * @return bool True if from trusted proxy
     */
    private function isFromTrustedProxy(string $ip, array $trustedProxies): bool
    {
        foreach ($trustedProxies as $proxy) {
            if ($this->ipMatchesRange($ip, $proxy)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract first IP from comma-separated list
     *
     * @param string $headerValue Header value (possibly comma-separated)
     * @return string First IP address
     */
    private function extractFirstIp(string $headerValue): string
    {
        if (strpos($headerValue, ',') !== false) {
            $ips = explode(',', $headerValue);
            return trim($ips[0]);
        }
        return trim($headerValue);
    }

    /**
     * Check if IP matches a range (single IP or CIDR)
     *
     * @param string $ip    IP to check
     * @param string $range Range (single IP or CIDR notation)
     * @return bool True if IP is in range
     */
    private function ipMatchesRange(string $ip, string $range): bool
    {
        // Handle IPv6 (basic check)
        if (strpos($range, ':') !== false) {
            return $this->ipv6InRange($ip, $range);
        }

        // Single IP comparison
        if (strpos($range, '/') === false) {
            return $ip === $range;
        }

        // CIDR notation
        [$subnet, $bits] = explode('/', $range);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = -1 << (32 - (int) $bits);
        $subnetLong &= $mask;

        return ($ipLong & $mask) === $subnetLong;
    }

    /**
     * Check if IPv6 is in range
     *
     * @param string $ip   IPv6 address
     * @param string $cidr CIDR range
     * @return bool True if in range
     */
    private function ipv6InRange(string $ip, string $cidr): bool
    {
        // Skip if IP is not IPv6
        if (strpos($ip, ':') === false) {
            return false;
        }

        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int) $bits;

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // Compare bytes
        $fullBytes = (int) floor($bits / 8);
        $remainingBits = $bits % 8;

        if (substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
            return false;
        }

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
     * Get trusted proxies from settings, including CloudFlare if enabled
     *
     * @return array List of trusted proxy IPs/CIDRs
     */
    protected function getTrustedProxiesFromSettings(): array
    {
        $settings = get_option('spectrus_shield_settings', []);
        $trustedProxies = isset($settings['trusted_proxies']) ? (array) $settings['trusted_proxies'] : [];

        // If CloudFlare is enabled, add CF IPs
        if (!empty($settings['cloudflare_enabled'])) {
            $cfIps = get_transient('sg_cloudflare_ip_ranges');
            if (is_array($cfIps)) {
                $trustedProxies = array_merge($trustedProxies, $cfIps);
            }
        }

        return $trustedProxies;
    }
}
