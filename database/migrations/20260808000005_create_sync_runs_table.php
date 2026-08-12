<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateSyncRunsTable extends Migrator
{
    public function change(): void
    {
        $this->table('sync_jobs', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Queued and completed provider synchronization jobs',
        ])
            // Match the unsigned AUTO_INCREMENT parent key on cloud_accounts.
            ->addColumn('cloud_account_id', 'integer', ['null' => false, 'signed' => false])
            ->addColumn('trigger_type', 'string', ['limit' => 24, 'null' => false, 'default' => 'manual'])
            ->addColumn('status', 'string', ['limit' => 24, 'null' => false, 'default' => 'queued'])
            ->addColumn('resources_discovered', 'integer', ['null' => false, 'default' => 0])
            ->addColumn('resources_created', 'integer', ['null' => false, 'default' => 0])
            ->addColumn('resources_updated', 'integer', ['null' => false, 'default' => 0])
            ->addColumn('error_message', 'text', ['null' => true])
            ->addColumn('started_at', 'datetime', ['null' => true])
            ->addColumn('completed_at', 'datetime', ['null' => true])
            ->addColumn('created_at', 'datetime', ['null' => false])
            ->addColumn('updated_at', 'datetime', ['null' => false])
            ->addIndex(['cloud_account_id', 'status', 'created_at'], ['name' => 'idx_sync_jobs_account_status'])
            ->addForeignKey('cloud_account_id', 'cloud_accounts', 'id', ['delete' => 'CASCADE', 'update' => 'CASCADE', 'constraint' => 'fk_sync_jobs_account'])
            ->create();
    }
}
