<?php

declare(strict_types=1);

namespace app\model;

use think\Model;

final class Provider extends Model
{
    protected $name = 'providers';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    protected $updateTime = 'updated_at';

    protected $json = ['credential_schema'];

    protected $jsonAssoc = true;

    protected $type = [
        'is_enabled' => 'boolean',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

}
