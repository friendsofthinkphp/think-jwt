<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use xiaodi\JWTAuth\Command\JwtCommand;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', \xiaodi\JWTAuth\Jwt::class);
        $this->app->bind('jwt.manager', \xiaodi\JWTAuth\Manager::class);
        $this->app->bind('jwt.user', \xiaodi\JWTAuth\User::class);
        $this->app->bind('jwt.blacklist', \xiaodi\JWTAuth\Blacklist::class);
    }

    public function boot()
    {
        $this->commands(JwtCommand::class);
    }
}
