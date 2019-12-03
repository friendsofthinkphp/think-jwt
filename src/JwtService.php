<?php

namespace xiaodi;

use xiaodi\Command\JwtCommand;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('JwtMiddleware', \xiaodi\Middleware\Jwt::class);
        $this->app->bind('jwt', \xiaodi\Jwt::class);
        $this->app->bind('user', config('jwt.user_model'));
    }

    public function boot()
    {
        $this->commands(JwtCommand::class);
    }
}
