<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth;

use xiaodi\JWTAuth\Service\JwtAuth;
use xiaodi\JWTAuth\Service\Manager;
use xiaodi\JWTAuth\Service\Token;
use xiaodi\JWTAuth\Service\SSO;
use xiaodi\JWTAuth\Service\User;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', JwtAuth::class);
        $this->app->bind('jwt.manager', Manager::class);
        $this->app->bind('jwt.token', Token::class);
        $this->app->bind('jwt.sso', SSO::class);
        $this->app->bind('jwt.user', User::class);
    }

    public function boot()
    {
        // $this->commands(JwtCommand::class);
    }
}
