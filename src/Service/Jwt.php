<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use DateTime;
use DateTimeImmutable;
use Exception;
use think\App;

use Lcobucci\JWT\Token as JwtToken;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\Exception\TokenAlreadyEexpired;

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

        return $token;
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
        }

        // 是否存在黑名单
        if (true === $this->app->get('jwt.manager')->wasBan($token)) {
            throw new TokenAlreadyEexpired('token was ban', $this->config->getReloginCode());
        }

        return true;
    }
}
