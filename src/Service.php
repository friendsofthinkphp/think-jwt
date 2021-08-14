<?php

namespace xiaodi\think\jwt;

use xiaodi\think\jwt\JwtAuth;

class Service extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', JwtAuth::class);
    }
}
