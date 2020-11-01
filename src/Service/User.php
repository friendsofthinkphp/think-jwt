<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use think\App;
use think\Model;
use xiaodi\JWTAuth\Config\User as Config;

class User
{
    protected $config;

    protected $app;

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

    protected function getStore()
    {
        return $this->app->get('jwt')->getStore();
    }

    protected function resolveConfig(): array
    {
        $store = $this->getStore();
        $options = $this->app->config->get("jwt.stores.{$store}.user", []);

        return $options;
    }
}
