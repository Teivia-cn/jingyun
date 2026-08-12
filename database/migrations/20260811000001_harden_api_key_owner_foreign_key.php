<?php

declare(strict_types=1);

use think\migration\Migrator;

/**
 * Repairs installations where the prior migration stopped after creating the
 * api_keys table but before MySQL accepted its owner foreign key.
 */
final class HardenApiKeyOwnerForeignKey extends Migrator
{
    public function up(): void
    {
        if (!$this->hasTable('api_keys')) {
            return;
        }

        $adapter = $this->getAdapter();
        $prefix = (string) $adapter->getOption('table_prefix');
        $apiKeys = $adapter->quoteTableName($prefix . 'api_keys');
        $users = $adapter->quoteTableName($prefix . 'users');
        $row = $this->fetchRow(
            'SELECT COUNT(*) AS orphan_count FROM ' . $apiKeys . ' AS k '
            . 'LEFT JOIN ' . $users . ' AS u ON u.`id` = k.`owner_user_id` '
            . 'WHERE u.`id` IS NULL'
        );

        if ((int) ($row['orphan_count'] ?? 0) > 0) {
            throw new RuntimeException('Cannot add the api_keys owner foreign key while orphaned API keys exist.');
        }

        $this->execute('ALTER TABLE ' . $apiKeys . ' MODIFY `owner_user_id` INT UNSIGNED NOT NULL');

        $table = $this->table('api_keys');
        if (!$table->hasForeignKey('owner_user_id', 'fk_api_keys_owner')) {
            $table
                ->addForeignKeyWithName(
                    'fk_api_keys_owner',
                    'owner_user_id',
                    'users',
                    'id',
                    ['delete' => 'CASCADE', 'update' => 'CASCADE']
                )
                ->update();
        }
    }

    public function down(): void
    {
        if (!$this->hasTable('api_keys')) {
            return;
        }

        $table = $this->table('api_keys');
        if ($table->hasForeignKey('owner_user_id', 'fk_api_keys_owner')) {
            $table->dropForeignKey('owner_user_id', 'fk_api_keys_owner')->update();
        }
    }
}
