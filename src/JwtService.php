<?php

namespace xiaodi;

use xiaodi\Command\JwtCommand;
use xiaodi\Jwt;
use xiaodi\Middleware\Jwt as Middleware;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('JwtMiddleware', Middleware::class);
        $this->app->bind('jwt', Jwt::class);
    }

    public function boot()
    {
        $this->commands(JwtCommand::class);
    }
}
