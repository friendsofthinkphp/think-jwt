<?php

namespace think\JwtAuth;

use think\JwtAuth\Command\JwtAuthCommand;

class JwtAuthService extends \think\Service
{
    public function register()
    {
    }

    public function boot()
    {
        $this->commands(JwtAuthCommand::class);
    }
}
