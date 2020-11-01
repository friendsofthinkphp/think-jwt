<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth;

use xiaodi\JWTAuth\Service\Jwt;
use xiaodi\JWTAuth\Service\Manager;
use xiaodi\JWTAuth\Service\Token;
use xiaodi\JWTAuth\Service\SSO;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', Jwt::class);
        $this->app->bind('jwt.manager', Manager::class);
        $this->app->bind('jwt.token', Token::class);
        $this->app->bind('jwt.sso', SSO::class);
    }

    public function boot()
    {
        // $this->commands(JwtCommand::class);
    }
}
