<?php
// +----------------------------------------------------------------------
// | 会话设置
// +----------------------------------------------------------------------

$secureCookie = filter_var(
    env('SESSION_SECURE_COOKIE', !filter_var(env('APP_DEBUG', false), FILTER_VALIDATE_BOOL)),
    FILTER_VALIDATE_BOOL
);

return [
    // session name
    'name'           => env('SESSION_NAME', $secureCookie ? '__Host-jingyun_session' : 'jingyun_session'),
    // SESSION_ID的提交变量,解决flash上传跨域
    'var_session_id' => '',
    // Keep authenticated sessions in MySQL so PHP does not need permission to
    // create files below runtime/session on a shared-hosting deployment.
    'type'           => \app\session\DatabaseSession::class,
    // 存储连接标识 当type使用cache的时候有效
    'store'          => null,
    // 过期时间
    'expire'         => min(43200, max(300, (int) env('SESSION_EXPIRE', 7200))),
    // 前缀
    'prefix'         => '',
    // Table name is validated by the driver. It deliberately uses the same
    // database connection and configured DB_PREFIX as application tables.
    'database_table' => env('SESSION_DATABASE_TABLE', 'sessions'),
];
