<?php

declare(strict_types=1);

use think\migration\Migrator;

final class CreateAuditLogsTable extends Migrator
{
    public function change(): void
    {
        $this->table('audit_logs', [
            'engine' => 'InnoDB',
            'collation' => 'utf8mb4_unicode_ci',
            'comment' => 'Append-only operator and system audit trail',
        ])
            ->addColumn('actor_id', 'string', ['limit' => 128, 'null' => false, 'default' => 'system'])
            ->addColumn('actor_name', 'string', ['limit' => 120, 'null' => false, 'default' => 'System'])
            ->addColumn('action', 'string', ['limit' => 128, 'null' => false])
            ->addColumn('subject_type', 'string', ['limit' => 80, 'null' => false])
            ->addColumn('subject_id', 'integer', ['null' => false])
            ->addColumn('ip_address', 'string', ['limit' => 45, 'null' => true])
            ->addColumn('user_agent', 'string', ['limit' => 500, 'null' => true])
            ->addColumn('metadata', 'json', ['null' => true, 'comment' => 'Sanitized metadata, never credentials'])
            ->addColumn('created_at', 'datetime', ['null' => false])
            ->addIndex(['action', 'created_at'], ['name' => 'idx_audit_logs_action_created'])
            ->addIndex(['subject_type', 'subject_id'], ['name' => 'idx_audit_logs_subject'])
            ->create();
    }
}
