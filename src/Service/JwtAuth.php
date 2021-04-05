<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use DateTimeImmutable;
use think\App;

use Lcobucci\JWT\Token;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;

class JwtAuth
{
    /**
     * 应用名称
     *
     * @var string
     */
    protected $store;

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
     * @return Token
     */
    public function token($identifier, array $claims = []): Token
    {
        $token = $this->app->get('jwt.token')->make($identifier, $claims);

        $this->app->get('jwt.manager')->login($token);

        return $token;
    }

    /**
     * 验证 Token
     *
     * @param string $token
     * @return boolean
     */
    public function verify(string $token = null): bool
    {
        $service = $this->app->get('jwt.token');
        if (!$token) {
            $token = $service->getRequestToken();
        }

        // 是否存在黑名单
        $this->wasBan($token);

        if (!$service->validate($token)) {
            $now = new DateTimeImmutable();

            $token = $service->getToken();
            if (!$service->isRefreshExpired($now)) {
                $config = $service->getConfig();
                if ($config->getAutomaticRenewal()) {
                    $token = $service->automaticRenewalToken($token);
                }
            } else {
                throw new JWTException('效验失败', 401);
            }
        } else {
            $token = $this->app->get('jwt.token')->getToken();
        }

        return true;
    }

    protected function wasBan($token)
    {
        $token = $this->app->get('jwt.token')->parse($token);
        if (true === $this->app->get('jwt.manager')->wasBan($token)) {
            $config = $this->app->get('jwt.token')->getConfig();

            throw new TokenAlreadyEexpired('token was ban', $config->getReloginCode());
        }
    }

    public function logout(string $token = null)
    {
        $service = $this->app->get('jwt.token');
        if (!$token) {
            $token = $service->getRequestToken();
        }

        $token = $service->parse($token);
        $this->app->get('jwt.manager')->logout($token);
    }
}
