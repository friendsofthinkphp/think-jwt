<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use think\App;
use think\Model;
use xiaodi\JWTAuth\Exception\JWTException;

class User
{
    private $bind = false;
    private $model;
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
        $this->setStoreConfig();
    }

    public function setStoreConfig()
    {
        $store = $this->app->jwt->getStore();
        $configs = $this->app->config->get("jwt.apps.{$store}.user", []);

        foreach ($configs as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 是否开启注入.
     *
     * @return bool
     */
    public function bind()
    {
        return $this->bind;
    }

    /**
     * 获取 用户模型文件.
     *
     * @return string
     */
    public function getClass()
    {
        $class = $this->model;
        if (!$class) {
            $store = $this->app->jwt->getStore();
            throw new JWTException("{$store} 应用  未配置 用户模型文件");
        }

        return $class; 
    }

    /**
     * 获取 具用登录信息的用户模型.
     *
     * @return Model
     */
    public function get(): Model
    {
        $token = $this->app->jwt->getToken();
        
        if (!$token) {
            throw new JWTException('未登录.', 500);
        }

        if (!$this->bind()) {
            throw new JWTException('未开启注入功能.', 500);
        }

        $uid = $token->getClaim($this->app->jwt->getUniqidKey());

        $namespace = $this->getClass();
        $model = new $namespace();
        $user = $model->findOrFail($uid);

        return $user;
    }
}
