<?php

declare(strict_types=1);

namespace app\model;

use think\Model;
use think\model\relation\BelongsTo;

final class SyncRun extends Model
{
    protected $name = 'sync_jobs';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    protected $updateTime = 'updated_at';

    protected $type = [
        'started_at' => 'datetime',
        'last_attempt_at' => 'datetime',
        'next_retry_at' => 'datetime',
        'heartbeat_at' => 'datetime',
        'lease_expires_at' => 'datetime',
        'completed_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function cloudAccount(): BelongsTo
    {
        return $this->belongsTo(CloudAccount::class, 'cloud_account_id');
    }

}
