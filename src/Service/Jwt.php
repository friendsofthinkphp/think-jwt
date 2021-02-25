<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use DateTime;
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

    public function store(string $store = null): self
    {
        if ($store) {
            $this->store = $store;
        }

        return $this;
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
    public function token($identifier, array $claims = []): JwtToken
    {
        $token = $this->app->get('jwt.token')->make($identifier, $claims);

        // $this->app->get('jwt.manager')->login($token);

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
    public function verify(?string $token): bool
    {
        $service = $this->app->get('jwt.token');
        if (!$token) {
            $token = $service->getRequestToken();
        }

        if (!$service->verify($token)) {
            $token = $service->getToken();
            if ($token->isExpired(new DateTime())) {
                // todo 过期
            }

        }

        return true;
    }
}
