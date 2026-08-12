<?php

declare(strict_types=1);

namespace app\session;

use RuntimeException;
use think\contract\SessionHandlerInterface;
use think\facade\Db;

/**
 * Database-backed session storage for hosts where PHP cannot write runtime/.
 *
 * Session payloads remain PHP's internal serialized data and are never
 * returned by an API. The table is created lazily for an upgraded deployment;
 * install.php also creates it through the normal migration path.
 */
final class DatabaseSession implements SessionHandlerInterface
{
    private const TABLE = 'sessions';

    private static bool $schemaReady = false;

    private readonly string $table;

    private readonly int $expire;

    public function __construct(array $config = [])
    {
        $table = (string) ($config['database_table'] ?? self::TABLE);
        if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $table) !== 1) {
            throw new RuntimeException('Invalid database session table configuration.');
        }

        $this->table = $table;
        $this->expire = max(300, min(43200, (int) ($config['expire'] ?? 7200)));
    }

    public function read(string $sessionId): string
    {
        $this->ensureSchema();

        $row = Db::name($this->table)
            ->where('session_id', $sessionId)
            ->where('expires_at', '>', date('Y-m-d H:i:s'))
            ->find();
        if (!is_array($row)) {
            return '';
        }

        $payload = $row['payload'] ?? '';

        return is_string($payload) ? $payload : '';
    }

    public function write(string $sessionId, string $data): bool
    {
        $this->ensureSchema();

        $now = date('Y-m-d H:i:s');
        $values = [
            'payload' => $data,
            'expires_at' => date('Y-m-d H:i:s', time() + $this->expire),
            'updated_at' => $now,
        ];

        $updated = Db::name($this->table)->where('session_id', $sessionId)->update($values);
        if ($updated === 0 && Db::name($this->table)->where('session_id', $sessionId)->value('session_id') === null) {
            try {
                Db::name($this->table)->insert(['session_id' => $sessionId] + $values);
            } catch (\Throwable $exception) {
                // A concurrent request can create the same regenerated ID
                // first. Retry the update without treating that as logout.
                if (Db::name($this->table)->where('session_id', $sessionId)->value('session_id') === null) {
                    throw $exception;
                }
                Db::name($this->table)->where('session_id', $sessionId)->update($values);
            }
        }

        $this->deleteExpired();

        return true;
    }

    public function delete(string $sessionId): bool
    {
        $this->ensureSchema();
        Db::name($this->table)->where('session_id', $sessionId)->delete();

        return true;
    }

    private function ensureSchema(): void
    {
        if (self::$schemaReady) {
            return;
        }

        $prefix = (string) Db::getConfig('connections.mysql.prefix', '');
        $table = $prefix . $this->table;
        if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $table) !== 1) {
            throw new RuntimeException('Invalid database table prefix configuration.');
        }

        try {
            Db::execute(
                'CREATE TABLE IF NOT EXISTS `' . $table . '` ('
                . '`session_id` CHAR(32) NOT NULL,'
                . '`payload` MEDIUMBLOB NOT NULL,'
                . '`expires_at` DATETIME NOT NULL,'
                . '`updated_at` DATETIME NOT NULL,'
                . 'PRIMARY KEY (`session_id`),'
                . 'KEY `idx_sessions_expires_at` (`expires_at`)'
                . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
            );
        } catch (\Throwable $exception) {
            throw new RuntimeException('Database session storage is unavailable. Run php think migrate:run and verify the MySQL account can read and write the sessions table.', 0, $exception);
        }

        self::$schemaReady = true;
    }

    private function deleteExpired(): void
    {
        // Keep cleanup bounded to avoid adding a full table scan to a request.
        if (random_int(1, 100) !== 1) {
            return;
        }

        Db::name($this->table)->where('expires_at', '<=', date('Y-m-d H:i:s'))->limit(100)->delete();
    }
}
