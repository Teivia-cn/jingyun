<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateProvidersTable extends Migrator
{
    public function change(): void
    {
        $table = $this->table('providers', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Cloud, domain, and billing provider definitions',
        ]);

        $table
            ->addColumn('slug', 'string', [
                'limit' => 64,
                'null' => false,
                'comment' => 'Stable catalog key, e.g. aliyun or cloudflare',
            ])
            ->addColumn('name', 'string', [
                'limit' => 120,
                'null' => false,
            ])
            ->addColumn('category', 'string', [
                'limit' => 32,
                'null' => false,
                'comment' => 'cloud, domain, or billing',
            ])
            ->addColumn('description', 'text', [
                'null' => true,
            ])
            ->addColumn('docs_url', 'string', [
                'limit' => 2048,
                'null' => false,
            ])
            ->addColumn('default_base_url', 'string', [
                'limit' => 2048,
                'null' => true,
                'comment' => 'Provider endpoint; null when supplied per account',
            ])
            ->addColumn('base_url_mode', 'string', [
                'limit' => 16,
                'null' => false,
                'default' => 'fixed',
                'comment' => 'fixed or custom',
            ])
            ->addColumn('auth_type', 'string', [
                'limit' => 64,
                'null' => false,
            ])
            ->addColumn('credential_schema', 'json', [
                'null' => true,
                'comment' => 'Credential field definitions; contains no credential values',
            ])
            ->addColumn('is_enabled', 'boolean', [
                'null' => false,
                'default' => true,
            ])
            ->addColumn('created_at', 'datetime', ['null' => false])
            ->addColumn('updated_at', 'datetime', ['null' => false])
            ->addIndex(['slug'], ['unique' => true, 'name' => 'uq_providers_slug'])
            ->addIndex(['category', 'is_enabled'], ['name' => 'idx_providers_category_enabled'])
            ->create();
    }
}
