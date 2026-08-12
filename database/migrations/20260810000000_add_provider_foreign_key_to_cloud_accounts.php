<?php

declare(strict_types=1);

use think\migration\Migrator;

/**
 * Keeps the denormalized account provider slug tied to the seeded provider
 * catalog. The existing provider_slug/name unique index starts with the
 * referencing column, so MySQL can use it for this foreign key as well.
 */
final class AddProviderForeignKeyToCloudAccounts extends Migrator
{
    public function up(): void
    {
        $adapter = $this->getAdapter();
        $prefix = (string) $adapter->getOption('table_prefix');
        $accountsTable = $adapter->quoteTableName($prefix . 'cloud_accounts');
        $providersTable = $adapter->quoteTableName($prefix . 'providers');
        $row = $this->fetchRow(
            'SELECT COUNT(*) AS orphan_count '
            . 'FROM ' . $accountsTable . ' AS ca '
            . 'LEFT JOIN ' . $providersTable . ' AS p ON p.`slug` = ca.`provider_slug` '
            . 'WHERE p.`id` IS NULL'
        );
        $orphanCount = is_array($row) ? (int) ($row['orphan_count'] ?? 0) : 0;
        if ($orphanCount > 0) {
            throw new \RuntimeException(
                'Cannot add the cloud_accounts provider foreign key: '
                . $orphanCount
                . ' account(s) reference a provider missing from the catalog. '
                . 'Run ProviderCatalogSeeder, reconcile the affected accounts, and retry.'
            );
        }

        $table = $this->table('cloud_accounts');
        if (!$table->hasForeignKey('provider_slug', 'fk_cloud_accounts_provider')) {
            $table
                ->addForeignKeyWithName(
                    'fk_cloud_accounts_provider',
                    'provider_slug',
                    'providers',
                    'slug',
                    ['delete' => 'RESTRICT', 'update' => 'CASCADE']
                )
                ->update();
        }
    }

    public function down(): void
    {
        $table = $this->table('cloud_accounts');
        if ($table->hasForeignKey('provider_slug', 'fk_cloud_accounts_provider')) {
            $table->dropForeignKey('provider_slug', 'fk_cloud_accounts_provider')->update();
        }
    }
}
