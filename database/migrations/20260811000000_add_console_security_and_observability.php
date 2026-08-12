<?php

declare(strict_types=1);

use think\migration\Migrator;

/**
 * Stores console-only configuration and external API credentials separately
 * from cloud-provider credentials. Secret values are always encrypted before
 * persistence; external API keys are stored as keyed hashes only.
 */
final class AddConsoleSecurityAndObservability extends Migrator
{
    public function change(): void
    {
        // `change()` can be retried after an interrupted MySQL DDL batch. Each
        // table is therefore created independently if it is still absent.
        if (!$this->hasTable('system_settings')) {
            $this->table('system_settings', [
                'engine' => 'InnoDB',
                'collation' => 'utf8mb4_unicode_ci',
                'comment' => 'Encrypted system configuration values',
            ])
                ->addColumn('setting_key', 'string', ['limit' => 100, 'null' => false])
                ->addColumn('encrypted_value', 'text', ['null' => true])
                ->addColumn('updated_by', 'integer', ['null' => true, 'signed' => false])
                ->addColumn('created_at', 'datetime', ['null' => false])
                ->addColumn('updated_at', 'datetime', ['null' => false])
                ->addIndex(['setting_key'], ['unique' => true, 'name' => 'uq_system_settings_key'])
                ->create();
        }

        if (!$this->hasTable('api_keys')) {
            $this->table('api_keys', [
                'engine' => 'InnoDB',
                'collation' => 'utf8mb4_unicode_ci',
                'comment' => 'Hashed external management API keys',
            ])
                ->addColumn('owner_user_id', 'integer', ['null' => false, 'signed' => false])
                ->addColumn('name', 'string', ['limit' => 120, 'null' => false])
                ->addColumn('key_prefix', 'string', ['limit' => 24, 'null' => false])
                ->addColumn('key_hash', 'string', ['limit' => 64, 'null' => false])
                ->addColumn('scopes', 'json', ['null' => false])
                ->addColumn('expires_at', 'datetime', ['null' => true])
                ->addColumn('last_used_at', 'datetime', ['null' => true])
                ->addColumn('revoked_at', 'datetime', ['null' => true])
                ->addColumn('created_at', 'datetime', ['null' => false])
                ->addColumn('updated_at', 'datetime', ['null' => false])
                ->addIndex(['key_prefix'], ['name' => 'idx_api_keys_prefix'])
                ->addIndex(['owner_user_id', 'revoked_at'], ['name' => 'idx_api_keys_owner_state'])
                ->addIndex(['key_hash'], ['unique' => true, 'name' => 'uq_api_keys_hash'])
                ->addForeignKeyWithName('fk_api_keys_owner', 'owner_user_id', 'users', 'id', ['delete' => 'CASCADE', 'update' => 'CASCADE'])
                ->create();
        }

        if (!$this->hasTable('api_usage_logs')) {
            $this->table('api_usage_logs', [
                'engine' => 'InnoDB',
                'collation' => 'utf8mb4_unicode_ci',
                'comment' => 'External API request usage, never request content',
            ])
                ->addColumn('api_key_id', 'integer', ['null' => false, 'signed' => false])
                ->addColumn('method', 'string', ['limit' => 10, 'null' => false])
                ->addColumn('path', 'string', ['limit' => 255, 'null' => false])
                ->addColumn('status_code', 'integer', ['null' => false])
                ->addColumn('ip_address', 'string', ['limit' => 45, 'null' => true])
                ->addColumn('created_at', 'datetime', ['null' => false])
                ->addIndex(['api_key_id', 'created_at'], ['name' => 'idx_api_usage_key_created'])
                ->addIndex(['created_at'], ['name' => 'idx_api_usage_created'])
                ->addForeignKeyWithName('fk_api_usage_key', 'api_key_id', 'api_keys', 'id', ['delete' => 'CASCADE', 'update' => 'CASCADE'])
                ->create();
        }

        if (!$this->hasTable('notification_logs')) {
            $this->table('notification_logs', [
                'engine' => 'InnoDB',
                'collation' => 'utf8mb4_unicode_ci',
                'comment' => 'Delivery audit without message bodies or secrets',
            ])
                ->addColumn('user_id', 'integer', ['null' => true, 'signed' => false])
                ->addColumn('event_type', 'string', ['limit' => 100, 'null' => false])
                ->addColumn('recipient', 'string', ['limit' => 254, 'null' => false])
                ->addColumn('status', 'string', ['limit' => 24, 'null' => false])
                ->addColumn('error_summary', 'string', ['limit' => 500, 'null' => true])
                ->addColumn('metadata', 'json', ['null' => true])
                ->addColumn('created_at', 'datetime', ['null' => false])
                ->addIndex(['event_type', 'created_at'], ['name' => 'idx_notification_event_created'])
                ->addIndex(['user_id', 'created_at'], ['name' => 'idx_notification_user_created'])
                ->addForeignKeyWithName('fk_notification_user', 'user_id', 'users', 'id', ['delete' => 'SET_NULL', 'update' => 'CASCADE'])
                ->create();
        }
    }
}
