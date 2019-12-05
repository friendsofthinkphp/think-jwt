<?php

namespace xiaodi;

use xiaodi\Command\JwtCommand;

class JwtService extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', \xiaodi\Jwt::class);
    }

    public function boot()
    {
        $this->commands(JwtCommand::class);
    }
}
