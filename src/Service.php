<?php

namespace xiaodi\JWTAuth;

use xiaodi\JWTAuth\JwtAuth;

class Service extends \think\Service
{
    public function register()
    {
        $this->app->bind('jwt', JwtAuth::class);
    }
}
