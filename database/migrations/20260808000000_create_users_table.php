<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateUsersTable extends Migrator
{
    public function change(): void
    {
        $table = $this->table('users', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'System users',
        ]);

        $table
            ->addColumn('username', 'string', [
                'limit' => 64,
                'null' => false,
                'comment' => 'Unique login name',
            ])
            ->addColumn('email', 'string', [
                'limit' => 254,
                'null' => false,
                'comment' => 'Unique email address',
            ])
            ->addColumn('password_hash', 'string', [
                'limit' => 255,
                'null' => false,
                'comment' => 'Password hash only; never a plaintext password',
            ])
            ->addColumn('display_name', 'string', [
                'limit' => 120,
                'null' => false,
                'default' => '',
            ])
            ->addColumn('avatar_url', 'string', [
                'limit' => 2048,
                'null' => true,
            ])
            ->addColumn('status', 'integer', [
                'limit' => 1,
                'null' => false,
                'default' => 1,
                'comment' => '1 active, 0 disabled',
            ])
            ->addColumn('last_login_at', 'datetime', [
                'null' => true,
            ])
            ->addColumn('created_at', 'datetime', [
                'null' => false,
            ])
            ->addColumn('updated_at', 'datetime', [
                'null' => false,
            ])
            ->addIndex(['username'], ['unique' => true, 'name' => 'uq_users_username'])
            ->addIndex(['email'], ['unique' => true, 'name' => 'uq_users_email'])
            ->addIndex(['status'], ['name' => 'idx_users_status'])
            ->create();
    }
}
