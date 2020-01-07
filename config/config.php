<?php

return [
    'sso'         => true,
    'ssoCacheKey' => 'jwt-auth-user',
    'ssoKey'      => 'uid',
    'signerKey'   => '',
    'notBefore'   => 0,
    'expiresAt'   => 3600,
    'signer'      => 'Lcobucci\JWT\Signer\Hmac\Sha256',
    'injectUser'  => false,
    'userModel'   => '',
    'hasLogged'   => 50401,
    'tokenAlready' => 50402
];
