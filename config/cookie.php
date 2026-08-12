<?php
// +----------------------------------------------------------------------
// | Cookie设置
// +----------------------------------------------------------------------
$secureCookie = filter_var(
    env('SESSION_SECURE_COOKIE', !filter_var(env('APP_DEBUG', false), FILTER_VALIDATE_BOOL)),
    FILTER_VALIDATE_BOOL
);

return [
    // cookie 保存时间
    'expire'    => 0,
    // cookie 保存路径
    'path'      => '/',
    // cookie 有效域名
    'domain'    => '',
    //  cookie 启用安全传输
    // Local HTTP can opt out; production defaults to a secure-only cookie.
    'secure'    => $secureCookie,
    // httponly设置
    'httponly'  => true,
    // 是否使用 setcookie
    'setcookie' => true,
    // samesite 设置，支持 'strict' 'lax'
    'samesite'  => 'strict',
];
