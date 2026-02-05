#!/usr/bin/env php
<?php
/**
 * SpectrusGuard Integrity Manifest Generator
 *
 * Generates integrity.json with SHA-256 hashes of critical plugin files.
 * Run this script before creating a release.
 *
 * Usage:
 *   php scripts/generate-integrity.php
 *
 * @package SpectrusGuard
 * @since   3.1.0
 */

// Configuration
const HASH_ALGORITHM = 'sha256';
const PLUGIN_DIR = __DIR__ . '/../';
const OUTPUT_FILE = PLUGIN_DIR . 'integrity.json';

// Files to include in manifest (relative to plugin root)
const CRITICAL_FILES = [
    // Core entry point
    'spectrus-guard.php',
    'uninstall.php',

    // MU-Plugin
    'mu-loader/spectrus-waf.php',

    // WAF Core
    'includes/waf/class-sg-firewall.php',

    // Hardening modules
    'includes/hardening/class-sg-api-guard.php',
    'includes/hardening/class-sg-ghost-cloak.php',
    'includes/hardening/class-sg-ghost-rescue.php',
    'includes/hardening/class-sg-login-guard.php',
    'includes/hardening/class-sg-two-factor.php',

    // Admin (high value targets for attackers)
    'includes/admin/class-sg-admin.php',
    'includes/admin/class-sg-ajax.php',

    // Scanner
    'includes/scanner/class-sg-scanner.php',
    'includes/scanner/class-sg-heuristic.php',

    // UEBA
    'includes/ueba/class-sg-ueba-engine.php',
    'includes/ueba/class-sg-response-engine.php',

    // Security (self-protection)
    'includes/security/class-sg-integrity.php',

    // Loader
    'includes/class-sg-loader.php',
];

const HIGH_RISK_FILES = [
    'includes/logger/class-sg-logger.php',
    'includes/logger/class-sg-log-parser.php',
    'includes/geo/class-sg-geo-blocker.php',
];

/**
 * Read version from main plugin file
 */
function get_plugin_version(): string
{
    $main_file = PLUGIN_DIR . 'spectrus-guard.php';
    $content = file_get_contents($main_file);

    if (preg_match('/Version:\s*(\d+\.\d+\.\d+)/', $content, $matches)) {
        return $matches[1];
    }

    return 'unknown';
}

/**
 * Generate hash for a file
 */
function hash_file_safe(string $path): ?string
{
    if (!file_exists($path)) {
        return null;
    }

    return hash_file(HASH_ALGORITHM, $path);
}

/**
 * Main execution
 */
function main(): int
{
    echo "SpectrusGuard Integrity Manifest Generator\n";
    echo "==========================================\n\n";

    $version = get_plugin_version();
    echo "Plugin Version: {$version}\n";
    echo "Algorithm: " . HASH_ALGORITHM . "\n\n";

    $manifest = [
        'version' => $version,
        'generated' => gmdate('c'),
        'algorithm' => HASH_ALGORITHM,
        'generator' => 'scripts/generate-integrity.php',
        'files' => [],
    ];

    $success = 0;
    $failed = 0;

    // Process critical files
    echo "Processing CRITICAL files:\n";
    foreach (CRITICAL_FILES as $file) {
        $path = PLUGIN_DIR . $file;
        $hash = hash_file_safe($path);

        if ($hash !== null) {
            $manifest['files'][$file] = [
                'hash' => $hash,
                'risk' => 'critical',
                'size' => filesize($path),
            ];
            echo "  ✓ {$file}\n";
            $success++;
        } else {
            echo "  ✗ {$file} (NOT FOUND)\n";
            $failed++;
        }
    }

    // Process high-risk files
    echo "\nProcessing HIGH RISK files:\n";
    foreach (HIGH_RISK_FILES as $file) {
        $path = PLUGIN_DIR . $file;
        $hash = hash_file_safe($path);

        if ($hash !== null) {
            $manifest['files'][$file] = [
                'hash' => $hash,
                'risk' => 'high',
                'size' => filesize($path),
            ];
            echo "  ✓ {$file}\n";
            $success++;
        } else {
            echo "  ✗ {$file} (NOT FOUND)\n";
            $failed++;
        }
    }

    // Save manifest
    echo "\n";
    echo "Files hashed: {$success}\n";
    echo "Files missing: {$failed}\n\n";

    $json = json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    $result = file_put_contents(OUTPUT_FILE, $json, LOCK_EX);

    if ($result !== false) {
        echo "✓ Manifest saved to: integrity.json\n";
        echo "  Size: " . strlen($json) . " bytes\n\n";

        // Show first file hash as verification
        $first_file = array_key_first($manifest['files']);
        $first_hash = $manifest['files'][$first_file]['hash'];
        echo "Verification (first file):\n";
        echo "  {$first_file}\n";
        echo "  SHA-256: {$first_hash}\n";

        return 0;
    } else {
        echo "✗ Failed to save manifest!\n";
        return 1;
    }
}

// Run
exit(main());
