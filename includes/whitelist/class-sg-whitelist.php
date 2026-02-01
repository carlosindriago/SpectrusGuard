<?php
/**
 * SpectrusGuard Whitelist Manager
 *
 * Manages the whitelist of files that users have explicitly marked as safe.
 * Uses SHA-256 hashes to detect file modifications.
 *
 * @package SpectrusGuard
 * @since   3.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_Whitelist
 *
 * Manages whitelisted files for the scanner.
 */
class SG_Whitelist
{

    /**
     * Table name
     *
     * @var string
     */
    private $table_name;

    /**
     * Constructor
     */
    public function __construct()
    {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'spectrus_whitelist';
    }

    /**
     * Check if a file is whitelisted
     *
     * @param string $file_path Full file path.
     * @param string $file_hash Optional SHA-256 hash of file content.
     * @return bool|object Whitelist entry if found, false otherwise.
     */
    public function check($file_path, $file_hash = null)
    {
        global $wpdb;

        // If hash provided, check both path and hash (in case file was modified)
        if ($file_hash) {
            $result = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$this->table_name} WHERE file_path = %s AND file_hash = %s LIMIT 1",
                $file_path,
                $file_hash
            ));

            if ($result) {
                return $result;
            }

            // Check if file was whitelisted but hash changed (file modified)
            $old_entry = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$this->table_name} WHERE file_path = %s LIMIT 1",
                $file_path
            ));

            if ($old_entry && $old_entry->file_hash !== $file_hash) {
                // File was modified after being whitelisted - return false to flag it
                return false;
            }
        }

        // Check by path only
        $result = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table_name} WHERE file_path = %s LIMIT 1",
            $file_path
        ));

        return $result ? $result : false;
    }

    /**
     * Add file to whitelist
     *
     * @param string $file_path Full file path.
     * @param string $file_hash SHA-256 hash of file content.
     * @param string $notes Optional user notes.
     * @return int|false Insert ID on success, false on failure.
     */
    public function add($file_path, $file_hash, $notes = '')
    {
        global $wpdb;

        // Check if already whitelisted
        $existing = $this->check($file_path);
        if ($existing) {
            // Update hash if changed
            if ($existing->file_hash !== $file_hash) {
                return $wpdb->update(
                    $this->table_name,
                    array(
                        'file_hash' => $file_hash,
                        'whitelisted_at' => current_time('mysql'),
                        'whitelisted_by' => get_current_user_id(),
                        'notes' => $notes,
                    ),
                    array('id' => $existing->id),
                    array('%s', '%s', '%d', '%s'),
                    array('%d')
                );
            }
            return $existing->id;
        }

        // Insert new whitelist entry
        $result = $wpdb->insert(
            $this->table_name,
            array(
                'file_path' => $file_path,
                'file_hash' => $file_hash,
                'whitelisted_at' => current_time('mysql'),
                'whitelisted_by' => get_current_user_id(),
                'notes' => $notes,
            ),
            array('%s', '%s', '%s', '%d', '%s')
        );

        return $result ? $wpdb->insert_id : false;
    }

    /**
     * Remove file from whitelist
     *
     * @param int $whitelist_id Whitelist entry ID.
     * @return bool True on success, false on failure.
     */
    public function remove($whitelist_id)
    {
        global $wpdb;

        $result = $wpdb->delete(
            $this->table_name,
            array('id' => $whitelist_id),
            array('%d')
        );

        return $result !== false;
    }

    /**
     * Get all whitelisted files
     *
     * @param int $limit Optional limit.
     * @param int $offset Optional offset.
     * @return array Array of whitelisted files.
     */
    public function get_all($limit = 0, $offset = 0)
    {
        global $wpdb;

        // Security: Cast to int to prevent SQL injection
        $limit = (int) $limit;
        $offset = (int) $offset;

        $limit_clause = $limit > 0 ? "LIMIT $limit" : '';
        $offset_clause = $offset > 0 ? "OFFSET $offset" : '';

        $results = $wpdb->get_results(
            "SELECT * FROM {$this->table_name} ORDER BY whitelisted_at DESC $limit_clause $offset_clause"
        );

        return $results ? $results : array();
    }

    /**
     * Get total count of whitelisted files
     *
     * @return int Total count.
     */
    public function get_count()
    {
        global $wpdb;

        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name}");
    }

    /**
     * Check if a specific file is whitelisted (simplified version)
     *
     * @param string $file_path Full file path.
     * @return bool True if whitelisted, false otherwise.
     */
    public function is_whitelisted($file_path)
    {
        return $this->check($file_path) !== false;
    }

    /**
     * Get whitelist entry by ID
     *
     * @param int $whitelist_id Whitelist entry ID.
     * @return object|null Whitelist entry or null if not found.
     */
    public function get_by_id($whitelist_id)
    {
        global $wpdb;

        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table_name} WHERE id = %d LIMIT 1",
            $whitelist_id
        ));
    }

    /**
     * Clear all whitelisted files
     *
     * @return int Number of rows deleted.
     */
    public function clear_all()
    {
        global $wpdb;

        return $wpdb->query("TRUNCATE TABLE {$this->table_name}");
    }
}
