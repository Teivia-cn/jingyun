<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateDatabaseSessionsTable extends Migrator
{
    public function change(): void
    {
        if ($this->hasTable('sessions')) {
            return;
        }

        $this->table('sessions', [
            'id' => false,
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Server-side authenticated web sessions',
        ])
            ->addColumn('session_id', 'string', ['limit' => 32, 'null' => false])
            ->addColumn('payload', 'blob', ['null' => false])
            ->addColumn('expires_at', 'datetime', ['null' => false])
            ->addColumn('updated_at', 'datetime', ['null' => false])
            ->addIndex(['session_id'], ['unique' => true, 'name' => 'uq_sessions_id'])
            ->addIndex(['expires_at'], ['name' => 'idx_sessions_expires_at'])
            ->create();
    }
}
