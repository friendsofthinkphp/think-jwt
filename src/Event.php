<?php

namespace xiaodi\JWTAuth;

use think\App;
use JwtAuth\EventHandler;
use Lcobucci\JWT\Token;

class Event implements EventHandler
{
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function login(Token $token)
    {
        // TODO
    }

    public function logout(Token $token)
    {
        // TODO
    }
}
