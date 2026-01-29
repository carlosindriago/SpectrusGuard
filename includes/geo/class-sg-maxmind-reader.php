<?php
/**
 * SpectrusGuard MaxMind MMDB Reader
 *
 * Pure PHP reader for MaxMind's .mmdb database format.
 * Based on the MaxMind DB specification.
 * No external dependencies required.
 *
 * @package SpectrusGuard
 * @since   1.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class SG_MaxMind_Reader
 *
 * Reads MaxMind .mmdb binary database files.
 */
class SG_MaxMind_Reader
{
    /**
     * Database file handle
     *
     * @var resource|null
     */
    private $fileHandle = null;

    /**
     * Database metadata
     *
     * @var array
     */
    private $metadata = array();

    /**
     * Database content (memory mapped for performance)
     *
     * @var string
     */
    private $database = '';

    /**
     * Pointer to the start of the data section
     *
     * @var int
     */
    private $dataStart = 0;

    /**
     * Size of a node in bytes
     *
     * @var int
     */
    private $nodeByteSize = 0;

    /**
     * Search tree size in bytes
     *
     * @var int
     */
    private $searchTreeSize = 0;

    /**
     * Data types in MMDB format
     */
    const DATA_TYPE_EXTENDED = 0;
    const DATA_TYPE_POINTER = 1;
    const DATA_TYPE_UTF8_STRING = 2;
    const DATA_TYPE_DOUBLE = 3;
    const DATA_TYPE_BYTES = 4;
    const DATA_TYPE_UINT16 = 5;
    const DATA_TYPE_UINT32 = 6;
    const DATA_TYPE_MAP = 7;
    const DATA_TYPE_INT32 = 8;
    const DATA_TYPE_UINT64 = 9;
    const DATA_TYPE_UINT128 = 10;
    const DATA_TYPE_ARRAY = 11;
    const DATA_TYPE_CONTAINER = 12;
    const DATA_TYPE_END_MARKER = 13;
    const DATA_TYPE_BOOLEAN = 14;
    const DATA_TYPE_FLOAT = 15;

    /**
     * Metadata start marker
     */
    const METADATA_START_MARKER = "\xab\xcd\xefMaxMind.com";

    /**
     * Constructor
     *
     * @param string $database Path to the .mmdb file.
     * @throws Exception If the database cannot be opened.
     */
    public function __construct($database)
    {
        if (!file_exists($database)) {
            throw new Exception("MaxMind database not found: $database");
        }

        $this->database = file_get_contents($database);
        if ($this->database === false) {
            throw new Exception("Could not read MaxMind database: $database");
        }

        $this->parseMetadata();
        $this->setupDatabase();
    }

    /**
     * Parse the metadata section of the database
     */
    private function parseMetadata()
    {
        $markerPos = strrpos($this->database, self::METADATA_START_MARKER);
        if ($markerPos === false) {
            throw new Exception('Invalid MaxMind database: metadata marker not found');
        }

        $metadataStart = $markerPos + strlen(self::METADATA_START_MARKER);
        $this->metadata = $this->decode($metadataStart)[0];
    }

    /**
     * Setup database pointers based on metadata
     */
    private function setupDatabase()
    {
        $nodeCount = $this->metadata['node_count'];
        $recordSize = $this->metadata['record_size'];

        $this->nodeByteSize = $recordSize / 4;
        $this->searchTreeSize = $nodeCount * $this->nodeByteSize;
        $this->dataStart = $this->searchTreeSize + 16; // 16 bytes for data section separator
    }

    /**
     * Get country data for an IP address
     *
     * @param string $ip IP address.
     * @return array|null Country data or null if not found.
     */
    public function get($ip)
    {
        $pointer = $this->findAddressInTree($ip);
        if ($pointer === 0) {
            return null;
        }

        return $this->resolveDataPointer($pointer);
    }

    /**
     * Get just the country ISO code for an IP
     *
     * @param string $ip IP address.
     * @return string|null ISO country code or null.
     */
    public function getCountryCode($ip)
    {
        $record = $this->get($ip);
        
        if ($record === null) {
            return null;
        }

        // Handle different record structures
        if (isset($record['country']['iso_code'])) {
            return $record['country']['iso_code'];
        }

        if (isset($record['registered_country']['iso_code'])) {
            return $record['registered_country']['iso_code'];
        }

        return null;
    }

    /**
     * Find the pointer for an IP address in the search tree
     *
     * @param string $ip IP address.
     * @return int Pointer to the data section.
     */
    private function findAddressInTree($ip)
    {
        $rawAddress = inet_pton($ip);
        if ($rawAddress === false) {
            return 0;
        }

        $ipVersion = strlen($rawAddress) === 4 ? 4 : 6;
        $bitCount = strlen($rawAddress) * 8;
        
        // For IPv4 in IPv6 database, start at node 96
        $node = 0;
        if ($ipVersion === 4 && $this->metadata['ip_version'] === 6) {
            $node = $this->ipv4StartNode();
        }

        $nodeCount = $this->metadata['node_count'];

        for ($i = 0; $i < $bitCount; $i++) {
            if ($node >= $nodeCount) {
                break;
            }

            $bit = $this->getBit($rawAddress, $i);
            $node = $this->readNode($node, $bit);
        }

        if ($node === $nodeCount) {
            // Record is empty
            return 0;
        }

        if ($node > $nodeCount) {
            // This is a pointer to the data section
            return $node;
        }

        return 0;
    }

    /**
     * Get the start node for IPv4 addresses in an IPv6 database
     *
     * @return int Node number.
     */
    private function ipv4StartNode()
    {
        if ($this->metadata['ip_version'] !== 6) {
            return 0;
        }

        $node = 0;
        $nodeCount = $this->metadata['node_count'];

        // Navigate through 96 zero bits to reach IPv4 section
        for ($i = 0; $i < 96; $i++) {
            if ($node >= $nodeCount) {
                break;
            }
            $node = $this->readNode($node, 0);
        }

        return $node;
    }

    /**
     * Get a specific bit from a binary string
     *
     * @param string $data Binary data.
     * @param int    $bit  Bit position.
     * @return int 0 or 1.
     */
    private function getBit($data, $bit)
    {
        $byte = ord($data[(int) ($bit / 8)]);
        return ($byte >> (7 - ($bit % 8))) & 1;
    }

    /**
     * Read a node from the search tree
     *
     * @param int $nodeNumber Node number.
     * @param int $index      0 for left, 1 for right.
     * @return int Next node number or pointer.
     */
    private function readNode($nodeNumber, $index)
    {
        $recordSize = $this->metadata['record_size'];
        $baseOffset = $nodeNumber * $this->nodeByteSize;

        switch ($recordSize) {
            case 24:
                $offset = $baseOffset + ($index * 3);
                $bytes = substr($this->database, $offset, 3);
                return $this->unpackInteger($bytes);

            case 28:
                if ($index === 0) {
                    $bytes = substr($this->database, $baseOffset, 4);
                    return (ord($bytes[0]) >> 4 << 24) | $this->unpackInteger(substr($bytes, 1, 3));
                } else {
                    $bytes = substr($this->database, $baseOffset + 3, 4);
                    return ((ord($bytes[0]) & 0x0F) << 24) | $this->unpackInteger(substr($bytes, 1, 3));
                }

            case 32:
                $offset = $baseOffset + ($index * 4);
                $bytes = substr($this->database, $offset, 4);
                return $this->unpackInteger($bytes);

            default:
                throw new Exception("Unsupported record size: $recordSize");
        }
    }

    /**
     * Resolve a data pointer to actual data
     *
     * @param int $pointer Pointer value.
     * @return mixed Decoded data.
     */
    private function resolveDataPointer($pointer)
    {
        $nodeCount = $this->metadata['node_count'];
        $resolved = $this->dataStart + ($pointer - $nodeCount) - 16;
        return $this->decode($resolved)[0];
    }

    /**
     * Decode data at a given offset
     *
     * @param int $offset Offset in the database.
     * @return array [decoded_value, new_offset].
     */
    private function decode($offset)
    {
        $ctrlByte = ord($this->database[$offset]);
        $offset++;

        $type = $ctrlByte >> 5;

        // Extended type
        if ($type === self::DATA_TYPE_EXTENDED) {
            $type = 7 + ord($this->database[$offset]);
            $offset++;
        }

        // Calculate size
        $size = $ctrlByte & 0x1F;

        if ($type === self::DATA_TYPE_POINTER) {
            return $this->decodePointer($ctrlByte, $offset);
        }

        if ($size >= 29) {
            $bytesToRead = $size - 28;
            $sizeBytes = substr($this->database, $offset, $bytesToRead);
            $offset += $bytesToRead;

            if ($size === 29) {
                $size = 29 + ord($sizeBytes);
            } elseif ($size === 30) {
                $size = 285 + $this->unpackInteger($sizeBytes);
            } elseif ($size === 31) {
                $size = 65821 + $this->unpackInteger($sizeBytes);
            }
        }

        return $this->decodeByType($type, $offset, $size);
    }

    /**
     * Decode a pointer
     *
     * @param int $ctrlByte Control byte.
     * @param int $offset   Current offset.
     * @return array [pointed_value, new_offset].
     */
    private function decodePointer($ctrlByte, $offset)
    {
        $pointerSize = (($ctrlByte >> 3) & 0x03) + 1;
        $pointerBytes = chr($ctrlByte & 0x07) . substr($this->database, $offset, $pointerSize - 1);
        $pointer = $this->unpackInteger($pointerBytes);

        $base = 0;
        if ($pointerSize === 2) {
            $base = 2048;
        } elseif ($pointerSize === 3) {
            $base = 526336;
        } elseif ($pointerSize === 4) {
            $base = 0; // Full pointer
            $pointer = $this->unpackInteger(substr($this->database, $offset, 4));
            $pointerSize = 4;
        }

        $absolutePointer = $this->dataStart + $pointer + $base;
        $data = $this->decode($absolutePointer)[0];

        return array($data, $offset + $pointerSize - 1);
    }

    /**
     * Decode data by type
     *
     * @param int $type   Data type.
     * @param int $offset Current offset.
     * @param int $size   Data size.
     * @return array [decoded_value, new_offset].
     */
    private function decodeByType($type, $offset, $size)
    {
        switch ($type) {
            case self::DATA_TYPE_MAP:
                return $this->decodeMap($offset, $size);

            case self::DATA_TYPE_ARRAY:
                return $this->decodeArray($offset, $size);

            case self::DATA_TYPE_BOOLEAN:
                return array($size !== 0, $offset);

            case self::DATA_TYPE_UTF8_STRING:
                $value = substr($this->database, $offset, $size);
                return array($value, $offset + $size);

            case self::DATA_TYPE_DOUBLE:
                $bytes = substr($this->database, $offset, 8);
                $value = unpack('E', $bytes)[1];
                return array($value, $offset + 8);

            case self::DATA_TYPE_FLOAT:
                $bytes = substr($this->database, $offset, 4);
                $value = unpack('G', $bytes)[1];
                return array($value, $offset + 4);

            case self::DATA_TYPE_BYTES:
                $value = substr($this->database, $offset, $size);
                return array($value, $offset + $size);

            case self::DATA_TYPE_UINT16:
            case self::DATA_TYPE_UINT32:
            case self::DATA_TYPE_UINT64:
            case self::DATA_TYPE_UINT128:
                $bytes = substr($this->database, $offset, $size);
                $value = $size === 0 ? 0 : $this->unpackInteger($bytes);
                return array($value, $offset + $size);

            case self::DATA_TYPE_INT32:
                $bytes = substr($this->database, $offset, $size);
                $value = unpack('N', str_pad($bytes, 4, "\x00", STR_PAD_LEFT))[1];
                // Handle signed
                if ($value >= 2147483648) {
                    $value -= 4294967296;
                }
                return array($value, $offset + $size);

            default:
                throw new Exception("Unknown data type: $type");
        }
    }

    /**
     * Decode a map (associative array)
     *
     * @param int $offset Current offset.
     * @param int $size   Number of key-value pairs.
     * @return array [decoded_map, new_offset].
     */
    private function decodeMap($offset, $size)
    {
        $map = array();
        for ($i = 0; $i < $size; $i++) {
            list($key, $offset) = $this->decode($offset);
            list($value, $offset) = $this->decode($offset);
            $map[$key] = $value;
        }
        return array($map, $offset);
    }

    /**
     * Decode an array
     *
     * @param int $offset Current offset.
     * @param int $size   Number of elements.
     * @return array [decoded_array, new_offset].
     */
    private function decodeArray($offset, $size)
    {
        $array = array();
        for ($i = 0; $i < $size; $i++) {
            list($value, $offset) = $this->decode($offset);
            $array[] = $value;
        }
        return array($array, $offset);
    }

    /**
     * Unpack an integer from bytes (big-endian)
     *
     * @param string $bytes Binary string.
     * @return int Integer value.
     */
    private function unpackInteger($bytes)
    {
        $length = strlen($bytes);
        $integer = 0;
        for ($i = 0; $i < $length; $i++) {
            $integer = ($integer << 8) + ord($bytes[$i]);
        }
        return $integer;
    }

    /**
     * Get database metadata
     *
     * @return array Metadata.
     */
    public function getMetadata()
    {
        return $this->metadata;
    }
}
