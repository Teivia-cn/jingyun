<?php
// 全局中间件定义文件
return [
    // Session must be initialized before API authorization reads its state.
    \think\middleware\SessionInit::class,
    \app\middleware\ApiAuthorization::class,
];
