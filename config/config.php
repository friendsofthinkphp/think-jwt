<?php

return [
    'default' => 'admin',
    'apps' => [
        'admin' => [
            'token' => [
                'uniqidKey'    => 'uid',
                'signerKey'    => '',
                'notBefore'    => 0,
                'expiresAt'    => 3600,
                'refreshTTL'   => 7200,
                'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
                'type'         => 'Header',
                'refresh'      => 50001,
                'relogin'      => 50002,
                'iss'          => 'client.tant',
                'aud'          => 'server.tant',
                'automaticRenewal' => false,
            ],
            'user' => [
                'bind' => false,
                'model'  => '',
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
