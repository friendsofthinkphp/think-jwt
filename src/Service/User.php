<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use Exception;
use think\App;
use think\Model;
use xiaodi\JWTAuth\Config\User as Config;
use xiaodi\JWTAuth\Exception\JWTException;

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

    protected function getClass(): string
    {
        $store = $this->getStore();
        $class = $this->config->getClass();
        if (!$class) {
            throw new JWTException("{$store}应用未配置用户模型文件");
        }

        return $class;
    }

    public function get()
    {
        $class = $this->getClass();
        $token = $this->app->get('jwt')->getToken();
        $uid = $token->getHeader('jti');

        $model = new $class();
        return $model->find($uid);
    }
}
