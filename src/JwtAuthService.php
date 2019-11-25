<?php

namespace xiaodi;

use xiaodi\JwtAuth;
use think\facade\Route;
use xiaodi\Command\JwtAuthCommand;

class JwtAuthService extends \think\Service
{
    public function register()
    {
        $this->app->bind('auth', JwtAuth::class);
    }

    public function boot()
    {
        $this->commands(JwtAuthCommand::class);
    }
}
