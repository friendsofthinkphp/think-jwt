<?php

return [
    // 单点登录
    'sso' => true,

    // 单点登录用户唯一标识
    'sso_key' => 'id',
    
    // 秘钥
    'signer_key' => '5k*!X^oF',

    // 在此时间前不可用(秒)
    'not_before' => 0,

    // 默认有效时间为一小时（秒）
    'expires_at' => 3600,

    // 默认使用sha256签名
    'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,

    'claims' => [
        //发布端url
        'iss' => '',
        //请求端url
        'aud' => ''
    ]
];