<?php
/**
 * SpectrusGuard Heuristics Scanner
 *
 * Performs heuristic analysis of files to detect suspicious patterns,
 * files in wrong locations, and dangerous permissions.
 *
 * @package SpectrusGuard
 * @since   1.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Heuristics
 *
 * Heuristic file analysis for detecting suspicious content.
 */
class SG_Heuristics
{

    /**
     * Maximum file size to scan (5MB)
     *
     * @var int
     */
    const MAX_FILE_SIZE = 5242880;

    /**
     * Maximum files to scan per directory
     *
     * @var int
     */
    const MAX_FILES_PER_DIR = 5000;

    /**
     * Scan uploads directory for PHP files
     *
     * PHP files in uploads are almost always malicious.
     *
     * @return array Array of PHP file paths found.
     */
    public function scan_uploads_for_php()
    {
        $uploads_dir = wp_upload_dir();
        $base_dir = $uploads_dir['basedir'];

        if (!is_dir($base_dir)) {
            return array();
        }

        $php_files = array();

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($base_dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            $count = 0;
            foreach ($iterator as $file) {
                if (++$count > self::MAX_FILES_PER_DIR) {
                    break;
                }

                if (!$file->isFile()) {
                    continue;
                }

                $extension = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));

                // Check for PHP extensions (including disguised ones)
                if (in_array($extension, array('php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'phps'), true)) {
                    $php_files[] = str_replace(ABSPATH, '', $file->getPathname());
                }

                // Check for double extensions (image.jpg.php)
                if (preg_match('/\.(jpg|jpeg|png|gif|bmp|svg|ico)\.(php|phtml|phar)/i', $file->getFilename())) {
                    $php_files[] = str_replace(ABSPATH, '', $file->getPathname());
                }
            }
        } catch (Exception $e) {
            // Directory access error, skip
        }

        return array_unique($php_files);
    }

    /**
     * Scan for hidden files (starting with .)
     *
     * @return array Array of hidden file paths.
     */
    public function scan_hidden_files()
    {
        $hidden_files = array();

        $directories = array(
            WP_CONTENT_DIR,
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
        );

        // Whitelist of legitimate hidden files
        $whitelist = array(
            '.htaccess',
            '.htpasswd',
            '.well-known',
            '.gitignore',
            '.git',
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );

                $count = 0;
                foreach ($iterator as $file) {
                    if (++$count > self::MAX_FILES_PER_DIR) {
                        break;
                    }

                    $filename = $file->getFilename();

                    // Check if starts with dot and is not whitelisted
                    if (strpos($filename, '.') === 0) {
                        $is_whitelisted = false;
                        foreach ($whitelist as $allowed) {
                            if ($filename === $allowed || strpos($filename, $allowed) === 0) {
                                $is_whitelisted = true;
                                break;
                            }
                        }

                        if (!$is_whitelisted && $file->isFile()) {
                            $hidden_files[] = str_replace(ABSPATH, '', $file->getPathname());
                        }
                    }
                }
            } catch (Exception $e) {
                continue;
            }
        }

        return $hidden_files;
    }

    /**
     * Scan for dangerous file permissions
     *
     * @return array Array of files with dangerous permissions.
     */
    public function scan_dangerous_permissions()
    {
        $dangerous = array();

        $directories = array(
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads',
        );

        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );

                $count = 0;
                foreach ($iterator as $file) {
                    if (++$count > self::MAX_FILES_PER_DIR) {
                        break;
                    }

                    if (!$file->isFile()) {
                        continue;
                    }

                    $perms = fileperms($file->getPathname());
                    $perms_octal = substr(sprintf('%o', $perms), -3);

                    // Check for world-writable (x7x, xx7)
                    if ($perms_octal === '777' || $perms_octal === '776' || $perms_octal === '767') {
                        $dangerous[] = array(
                            'file' => str_replace(ABSPATH, '', $file->getPathname()),
                            'permissions' => $perms_octal,
                        );
                    }

                    // Check for world-writable PHP files specifically
                    $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                    if ($ext === 'php' && ($perms & 0x0002)) {
                        $dangerous[] = array(
                            'file' => str_replace(ABSPATH, '', $file->getPathname()),
                            'permissions' => $perms_octal,
                        );
                    }
                }
            } catch (Exception $e) {
                continue;
            }
        }

        return $dangerous;
    }

    /**
     * Scan files for malware signatures
     *
     * @param string $directory Directory to scan.
     * @param array  $signatures Malware signatures.
     * @return array Matched files.
     */
    public function scan_for_signatures($directory, $signatures)
    {
        $matches = array();

        if (!is_dir($directory)) {
            return $matches;
        }

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            $count = 0;
            foreach ($iterator as $file) {
                if (++$count > self::MAX_FILES_PER_DIR) {
                    break;
                }

                if (!$file->isFile()) {
                    continue;
                }

                // Only scan PHP files
                $ext = strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION));
                if (!in_array($ext, array('php', 'phtml', 'php5', 'php7'), true)) {
                    continue;
                }

                // Skip large files
                if ($file->getSize() > self::MAX_FILE_SIZE) {
                    continue;
                }

                $file_matches = $this->scan_file_for_signatures($file->getPathname(), $signatures);
                $matches = array_merge($matches, $file_matches);
            }
        } catch (Exception $e) {
            // Continue on error
        }

        return $matches;
    }

    /**
     * Scan a single file for malware signatures
     *
     * @param string $file_path File path.
     * @param array  $signatures Signatures to check.
     * @return array Matches found.
     */
    private function scan_file_for_signatures($file_path, $signatures)
    {
        $matches = array();

        if (!file_exists($file_path)) {
            return $matches;
        }

        $handle = @fopen($file_path, 'r');
        if (false === $handle) {
            return $matches;
        }

        // Flatten signatures to a list of checks
        $checks = array();
        foreach ($signatures as $name => $patterns) {
            if (!is_array($patterns)) {
                $patterns = array($patterns);
            }
            foreach ($patterns as $pattern) {
                $checks[] = array(
                    'name' => $name,
                    'pattern' => $pattern,
                    'is_regex' => (strpos($pattern, '/') === 0),
                );
            }
        }

        $buffer = '';
        $global_line_offset = 0;
        $chunk_size = 8192; // 8KB
        $overlap_size = 1024; // 1KB overlap

        while (!feof($handle) || strlen($buffer) > 0) {
            // Read chunk if available
            if (!feof($handle)) {
                $chunk = fread($handle, $chunk_size);
                if ($chunk === false) {
                    break;
                }
                $buffer .= $chunk;
            }

            if (empty($buffer)) {
                break;
            }

            $remaining_checks = array();

            foreach ($checks as $check) {
                $found = false;
                $match_pos = false;

                if ($check['is_regex']) {
                    if (@preg_match($check['pattern'], $buffer, $match, PREG_OFFSET_CAPTURE)) {
                        $match_pos = $match[0][1];
                        $found = true;
                    }
                } else {
                    $match_pos = stripos($buffer, $check['pattern']);
                    if (false !== $match_pos) {
                        $found = true;
                    }
                }

                if ($found) {
                    $line = $global_line_offset + substr_count(substr($buffer, 0, $match_pos), "\n") + 1;
                    $matches[] = array(
                        'file' => str_replace(ABSPATH, '', $file_path),
                        'signature' => $check['name'],
                        'line' => $line,
                        'snippet' => $this->get_snippet($buffer, $match_pos),
                    );
                } else {
                    $remaining_checks[] = $check;
                }
            }
            $checks = $remaining_checks;

            if (empty($checks)) {
                break;
            }

            if (feof($handle)) {
                break;
            }

            // Keep overlap
            if (strlen($buffer) > $overlap_size) {
                $discard_len = strlen($buffer) - $overlap_size;
                $discarded = substr($buffer, 0, $discard_len);
                $global_line_offset += substr_count($discarded, "\n");
                $buffer = substr($buffer, -$overlap_size);
            }
        }

        fclose($handle);
        return $matches;
    }

    /**
     * Get a code snippet around a position
     *
     * @param string $content File content.
     * @param int    $pos Position.
     * @return string Snippet.
     */
    private function get_snippet($content, $pos)
    {
        $start = max(0, $pos - 30);
        $length = 80;

        $snippet = substr($content, $start, $length);
        $snippet = str_replace(array("\n", "\r", "\t"), ' ', $snippet);
        $snippet = preg_replace('/\s+/', ' ', $snippet);

        return trim($snippet);
    }

    /**
     * Quick scan to check if a file looks suspicious
     *
     * @param string $file_path File path.
     * @return bool True if suspicious.
     */
    public function is_file_suspicious($file_path)
    {
        if (!file_exists($file_path)) {
            return false;
        }

        $content = @file_get_contents($file_path);
        if (false === $content) {
            return false;
        }

        // Quick checks
        $suspicious_patterns = array(
            'eval(base64_decode',
            'eval(gzinflate',
            'eval(str_rot13',
            'eval($_',
            'assert($_',
            'preg_replace(.*e.*,.*\$_',
            'FilesMan',
            'WSO ',
            'c99shell',
            'r57shell',
            'webshell',
        );

        foreach ($suspicious_patterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                return true;
            }
        }

        // Check for extremely long lines (obfuscation indicator)
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            if (strlen($line) > 5000) {
                return true;
            }
        }

        return false;
    }
}
