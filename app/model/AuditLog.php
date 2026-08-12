<?php

declare(strict_types=1);

namespace app\model;

use think\Model;

final class AuditLog extends Model
{
    protected $name = 'audit_logs';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    // Audit entries are append-only. The table intentionally has no updated_at column.
    protected $updateTime = false;

    protected $json = ['metadata'];

    protected $jsonAssoc = true;

    protected $type = [
        'created_at' => 'datetime',
    ];

}
