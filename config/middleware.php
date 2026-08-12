<?php
// 中间件配置
return [
    'alias'    => [],
    // SessionInit is intentionally outermost so authorization always sees
    // the session selected from the request cookie.
    'priority' => [
        \think\middleware\SessionInit::class,
        \app\middleware\ApiAuthorization::class,
    ],
];
