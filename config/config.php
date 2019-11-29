<?php

return [
    'sso' => true,

    'sso_key' => 'uid',

    'signer_key' => '',

    'not_before' => 0,

    'expires_at' => 3600,

    'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,

    'claims' => [
        'iss' => '',
        'aud' => '',
    ],

    'inject_user' => false,

    'user' => '',
];
