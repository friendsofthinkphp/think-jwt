<?php

declare(strict_types=1);

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

    public function getToken()
    {
        return $this->app->get('jwt.token')->getToken();
    }

    /**
     * 验证 Token
     *
     * @param string $token
     * @return boolean
     */
    public function verify(?string $token = null): bool
    {
        if (!$token) {
            $token = $this->app->get('jwt.token')->getRequestToken();
        }

        return $this->app->get('jwt.token')->verify($token);
    }

    public function destroyStoreWhitelist($store)
    {
        return $this->app->get('jwt.manager')->destroyStoreWhitelist($store);
    }

    public function user()
    {
        return $this->app->get('jwt.user');
    }

    public function type()
    {
        return $this->app->get('jwt.token')->getType();
    }

    public function refreshTTL()
    {
        return $this->app->get('jwt.token')->getRefreshTTL();
    }

    public function ttl()
    {
        return $this->app->get('jwt.token')->getRefreshTTL();
    }

    public function refresh(?string $token = null)
    {
        return $this->app->get('jwt.token')->refresh($token);
    }

    public function logout(?string $token = null)
    {
        return $this->app->get('jwt.token')->logout($token);
    }

    public function destroyToken($jti, $store)
    {
        return $this->app->get('jwt.manager')->destroyToken($jti, $store);
    }
}
