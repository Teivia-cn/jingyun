<?php

declare(strict_types=1);

use think\migration\Migrator;

final class AddRoleToUsersTable extends Migrator
{
    public function change(): void
    {
        $this->table('users')
            ->addColumn('role', 'string', [
                'limit' => 16,
                'null' => false,
                'default' => 'viewer',
                'after' => 'display_name',
                'comment' => 'Authorization role: admin or viewer',
            ])
            ->addIndex(['role', 'status'], ['name' => 'idx_users_role_status'])
            ->update();
    }
}
