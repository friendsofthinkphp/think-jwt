<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use think\App;
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

    /**
     * @var Config
     */
    public function getConfig()
    {
        return $this->config;
    }

    public function getClass(): string
    {
        $token = $this->app->get('jwt.token')->getToken();

        try {
            $class = $token->claims()->get('model', $this->config->getClass());
        } catch (\OutOfBoundsException $e) {
            $store = $this->getStore();
            throw new JWTException("{$store}应用未配置用户模型文件");
        }

        return $class;
    }

    public function getBind()
    {
        return $this->config->getBind();
    }

    public function find()
    {
        $class = $this->getClass();
        $token = $this->app->get('jwt.token')->getToken();
        $uid = $token->claims()->get('jti');

        $model = new $class();
        return $model->find($uid);
    }
}
