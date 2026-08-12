<?php

declare(strict_types=1);

namespace app\model;

use think\Model;

final class User extends Model
{
    protected $name = 'users';

    protected $autoWriteTimestamp = true;

    protected $createTime = 'created_at';

    protected $updateTime = 'updated_at';

    protected $hidden = ['password_hash'];

    protected $type = [
        'status' => 'integer',
        'last_login_at' => 'datetime',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

}
