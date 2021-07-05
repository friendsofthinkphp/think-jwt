<?php

use xiaodi\JWTAuth\Event;

return [
    'stores' => [
        // 单应用
        'default' => [
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'not_before'    => 0,
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'signer'        => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'type'          => 'Header',
            'iss'           => 'client.tant',
            'aud'           => 'server.tant',
            'event_handler' => Event::class,
            'user_model'    => \app\common\model\User::class
        ],
        // 多应用
        'admin' => [
            'signer_key'    => 'oP0qmqzHS4Vvml5a',
            'public_key'    => 'file://path/public.key',
            'private_key'   => 'file://path/private.key',
            'not_before'    => 0,
            'expires_at'    => 3600,
            'refresh_ttL'   => 7200,
            'signer'        => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
            'type'          => 'Header',
            'iss'           => 'client.tant',
            'aud'           => 'server.tant',
            'event_handler' => Event::class,
            'user_model'    => \app\common\model\User::class
        ]
    ],
    'manager' => [
        // 缓存前缀
        'prefix' => 'jwt',
        // 黑名单缓存名
        'blacklist' => 'blacklist',
        // 白名单缓存名
        'whitelist' => 'whitelist'
    ]
];
