<?php

declare(strict_types=1);

use think\migration\Migrator;

/**
 * Adds recovery information to the durable sync queue and inventory state to
 * normalized resources. Existing discovered resources start as active so the
 * first successful full reconciliation can mark only truly absent records as
 * stale without deleting history.
 */
final class AddSyncReliabilityAndResourceReconciliation extends Migrator
{
    public function up(): void
    {
        $this->table('sync_jobs')
            ->addColumn('attempt_count', 'integer', ['null' => false, 'default' => 0, 'comment' => 'Number of claimed execution attempts'])
            ->addColumn('last_attempt_at', 'datetime', ['null' => true])
            ->addColumn('next_retry_at', 'datetime', ['null' => true, 'comment' => 'Queued jobs are not eligible before this time'])
            ->addColumn('heartbeat_at', 'datetime', ['null' => true])
            ->addColumn('lease_expires_at', 'datetime', ['null' => true, 'comment' => 'Running job ownership lease'])
            ->addColumn('resources_stale', 'integer', ['null' => false, 'default' => 0])
            ->addIndex(['status', 'next_retry_at', 'id'], ['name' => 'idx_sync_jobs_ready'])
            ->addIndex(['status', 'lease_expires_at'], ['name' => 'idx_sync_jobs_lease'])
            ->update();

        $this->table('cloud_resources')
            ->addColumn('inventory_state', 'string', ['limit' => 24, 'null' => false, 'default' => 'active', 'comment' => 'active, stale, or manual'])
            ->addColumn('last_seen_at', 'datetime', ['null' => true, 'comment' => 'Last successful provider inventory observation'])
            ->addColumn('stale_at', 'datetime', ['null' => true, 'comment' => 'When a successful reconciliation stopped seeing this resource'])
            ->addIndex(['cloud_account_id', 'inventory_state', 'last_seen_at'], ['name' => 'idx_cloud_resources_reconcile'])
            ->update();

        // Preserve the intent of records created through the pre-reconciliation
        // manual resource API. They must never be marked stale by a provider
        // inventory pass merely because no upstream API can discover them.
        $adapter = $this->getAdapter();
        $table = $adapter->quoteTableName((string) $adapter->getOption('table_prefix') . 'cloud_resources');
        $this->execute("UPDATE {$table} SET `inventory_state` = 'manual' WHERE `status` = 'manual'");
    }

    public function down(): void
    {
        $this->table('cloud_resources')
            ->removeIndexByName('idx_cloud_resources_reconcile')
            ->removeColumn('stale_at')
            ->removeColumn('last_seen_at')
            ->removeColumn('inventory_state')
            ->update();

        $this->table('sync_jobs')
            ->removeIndexByName('idx_sync_jobs_lease')
            ->removeIndexByName('idx_sync_jobs_ready')
            ->removeColumn('resources_stale')
            ->removeColumn('lease_expires_at')
            ->removeColumn('heartbeat_at')
            ->removeColumn('next_retry_at')
            ->removeColumn('last_attempt_at')
            ->removeColumn('attempt_count')
            ->update();
    }
}
