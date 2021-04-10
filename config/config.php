<?php

return [
    'stores' => [
        // 单应用
        'default' => [
            'sso' => [
                'enable' => false,
            ],
            'token' => [
                'signer_key'    => 'tant',
                'public_key'    => 'file://path/public.key',
                'private_key'   => 'file://path/private.key',
                'not_before'    => 0,
                'expires_at'    => 3600,
                'refresh_ttL'   => 7200,
                'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
                'type'         => 'Header',
                'relogin_code'      => 50001,
                'refresh_code'      => 50002,
                'iss'          => 'client.tant',
                'aud'          => 'server.tant',
                'automatic_renewal' => false,
            ],
            'user' => [
                'bind' => false,
                'class'  => null,
            ]
        ],
        // 多应用
        'admin' => [
            'sso' => [
                'enable' => false,
            ],
            'token' => [
                'signer_key'    => 'tant',
                'not_before'    => 0,
                'expires_at'    => 3600,
                'refresh_ttL'   => 7200,
                'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
                'type'         => 'Header',
                'relogin_code'      => 50001,
                'refresh_code'      => 50002,
                'iss'          => 'client.tant',
                'aud'          => 'server.tant',
                'automatic_renewal' => false,
            ],
            'user' => [
                'bind' => false,
                'class'  => null,
            ]
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
