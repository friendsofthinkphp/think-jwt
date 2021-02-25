<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use think\App;
use xiaodi\JWTAuth\Config\SSO as Config;

class SSO
{
    /**
     *
     * @var Config
     */
    protected $config;

    public function __construct(App $app)
    {
        $this->app = $app;

        $this->init();
    }

    protected function init()
    {
        $options = $this->resolveConfig();

        $this->config = new Config($options);
    }

    /**
     * @var Config
     */
    public function getConfig()
    {
        return $this->config;
    }

    protected function getStore(): string
    {
        return $this->app->get('jwt')->getStore();
    }

    protected function resolveConfig(): array
    {
        $store = $this->getStore();
        $options = $this->app->config->get("jwt.stores.{$store}.sso", []);

        return $options;
    }

    public function getEnable(): bool
    {
        return $this->config->getEnable();
    }
}
