<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth\Service;

use think\App;

use Lcobucci\JWT\Token as JwtToken;

class Jwt
{
    /**
     * 应用名称
     *
     * @var string
     */
    protected $store;

    /**
     * Token
     *
     * @var Token
     */
    protected $token;

    protected $user;

    public function __construct(App $app)
    {
        $this->app = $app;

        $this->init();
    }

    public function store(string $store)
    {
        $this->store = $store;
    }

    public function getStore()
    {
        return $this->store ?? $this->getDefaultApp();
    }

    protected function init()
    {
    }

    protected function getDefaultApp(): string
    {
        return $this->app->http->getName();
    }

    /**
     * 生成 Token
     *
     * @param array $claims
     * @return JwtToken
     */
    public function token(array $claims): JwtToken
    {
        $token = $this->app->get('jwt.token')->make($claims);

        $this->app->get('jwt.manager')->login($token);

        return $token;
    }

    public function user()
    {
    }

    /**
     * 验证 Token
     *
     * @param string $token
     * @return boolean
     */
    public function verify(string $token): bool
    {
        return $this->app->get('jwt.token')->verify($token);
    }

    public function destroyStoreWhitelist($store)
    {
        return $this->app->get('jwt.manager')->destroyStoreWhitelist($store);
    }
}
