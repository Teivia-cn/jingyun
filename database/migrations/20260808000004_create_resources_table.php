<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateResourcesTable extends Migrator
{
    public function change(): void
    {
        $this->table('cloud_resources', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Normalized resources discovered from provider APIs',
        ])
            // Match the unsigned AUTO_INCREMENT parent key on cloud_accounts.
            ->addColumn('cloud_account_id', 'integer', ['null' => false, 'signed' => false])
            ->addColumn('provider_slug', 'string', ['limit' => 64, 'null' => false])
            ->addColumn('external_id', 'string', ['limit' => 512, 'null' => false])
            ->addColumn('resource_type', 'string', ['limit' => 80, 'null' => false])
            ->addColumn('name', 'string', ['limit' => 512, 'null' => false])
            ->addColumn('region', 'string', ['limit' => 128, 'null' => true])
            ->addColumn('status', 'string', ['limit' => 64, 'null' => true])
            ->addColumn('metadata', 'json', ['null' => true, 'comment' => 'Non-secret normalized attributes'])
            ->addColumn('tags', 'json', ['null' => true])
            ->addColumn('last_synced_at', 'datetime', ['null' => true])
            ->addColumn('created_at', 'datetime', ['null' => false])
            ->addColumn('updated_at', 'datetime', ['null' => false])
            ->addIndex(['cloud_account_id', 'resource_type', 'external_id'], ['unique' => true, 'name' => 'uq_cloud_resource_identity'])
            ->addIndex(['provider_slug', 'resource_type', 'name'], ['name' => 'idx_cloud_resources_catalog'])
            ->addIndex(['cloud_account_id', 'status'], ['name' => 'idx_cloud_resources_account_status'])
            ->addForeignKey('cloud_account_id', 'cloud_accounts', 'id', ['delete' => 'CASCADE', 'update' => 'CASCADE', 'constraint' => 'fk_cloud_resources_account'])
            ->create();
    }
}
