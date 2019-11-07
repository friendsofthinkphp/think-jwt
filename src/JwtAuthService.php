<?php

namespace think\JwtAuth;

use think\JwtAuth\Command\JwtAuthCommand;
use think\JwtAuth\Command\JwtAuthCommand2;

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
