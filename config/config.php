<?php

return [
    'default' => [
        'key'          => 'uid', 
        'signerKey'    => '',
        'notBefore'    => 0,
        'expiresAt'    => 3600,
        'refreshExp'   => 7200,
        'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
        'type'         => 'Header',
        'relogin'      => 50400,
        'hasLogged'    => 50401,
        'tokenAlready' => 50402,
        'iss'          => '',
        'aud'          => ''
    ],
    'user' => [
        'inject' => false,
        'model' => ''
    ]
];
