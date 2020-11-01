<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth;

use think\App;

class JwtAuth
{
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function __call($func, $params)
    {
        return call_user_func([$this->app->jwt, $func], ...$params);
    }
}
