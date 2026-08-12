<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateCloudAccountsTable extends Migrator
{
    public function change(): void
    {
        $this->table('cloud_accounts', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Configured cloud, domain, and billing provider accounts',
        ])
            ->addColumn('provider_slug', 'string', ['limit' => 64, 'null' => false])
            ->addColumn('name', 'string', ['limit' => 120, 'null' => false])
            ->addColumn('external_account_id', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('endpoint', 'string', ['limit' => 2048, 'null' => true])
            ->addColumn('region', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('sync_enabled', 'boolean', ['null' => false, 'default' => true])
            ->addColumn('sync_interval_minutes', 'integer', ['null' => false, 'default' => 30])
            ->addColumn('settings', 'json', ['null' => true, 'comment' => 'Non-secret provider options only'])
            ->addColumn('encrypted_credentials', 'text', ['null' => true, 'comment' => 'AES-256-GCM encrypted JSON only'])
            ->addColumn('credential_key_version', 'string', ['limit' => 64, 'null' => true])
            ->addColumn('credential_fingerprint', 'string', ['limit' => 128, 'null' => true])
            ->addColumn('status', 'string', ['limit' => 32, 'null' => false, 'default' => 'pending_verification'])
            ->addColumn('last_verified_at', 'datetime', ['null' => true])
            ->addColumn('last_sync_at', 'datetime', ['null' => true])
            ->addColumn('created_at', 'datetime', ['null' => false])
            ->addColumn('updated_at', 'datetime', ['null' => false])
            ->addIndex(['provider_slug', 'name'], ['unique' => true, 'name' => 'uq_cloud_accounts_provider_name'])
            ->addIndex(['provider_slug', 'status'], ['name' => 'idx_cloud_accounts_provider_status'])
            ->addIndex(['sync_enabled', 'last_sync_at'], ['name' => 'idx_cloud_accounts_schedule'])
            ->create();
    }
}
