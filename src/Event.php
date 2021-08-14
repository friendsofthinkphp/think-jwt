<?php

namespace xiaodi\think\jwt;

use think\App;
use JwtAuth\EventHandler;
use Lcobucci\JWT\Token;

class Event implements EventHandler
{
    /**
     * @var App
     */
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    /**
     * @var Token
     */
    public function login(Token $token)
    {
        // TODO
    }

    /**
     * @var Token
     */
    public function logout(Token $token)
    {
        // TODO
    }

    public function verify(Token $token)
    {
        // TODO
    }
}
