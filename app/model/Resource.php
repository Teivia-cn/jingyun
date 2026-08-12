<?php

declare(strict_types=1);

namespace app\model;

use think\Model;
use think\model\relation\BelongsTo;

final class Resource extends Model
{
    protected $name = 'cloud_resources';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    protected $updateTime = 'updated_at';

    protected $json = ['metadata', 'tags'];

    protected $jsonAssoc = true;

    protected $type = [
        'last_synced_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'stale_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    public function cloudAccount(): BelongsTo
    {
        return $this->belongsTo(CloudAccount::class, 'cloud_account_id');
    }
}
