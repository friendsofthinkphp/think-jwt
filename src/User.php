<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use think\Model;
use xiaodi\JWTAuth\Exception\JWTException;

class User
{
    private $inject = false;
    private $model;

    public function __construct(Jwt $jwt)
    {
        $this->jwt = $jwt;
        $this->setConfig();
    }

    public function setConfig()
    {
        $config = $this->jwt->getConfig();
        $configs = app('config')->get("jwt.{$config}.user", []);

        foreach ($configs as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 是否开启注入.
     *
     * @return bool
     */
    public function hasInject()
    {
        return $this->inject;
    }

    /**
     * 获取 用户模型文件.
     *
     * @return string
     */
    public function getModel()
    {
        return $this->model;
    }

    /**
     * 获取 具用登录信息的用户模型.
     *
     * @return Model
     */
    public function get(): Model
    {
        $token = $this->jwt->getToken();

        if (!$token) {
            throw new JWTException('未登录.', 500);
        }

        if (!$this->hasInject()) {
            throw new JWTException('未开启注入功能.', 500);
        }

        $uid = $token->getClaim($this->jwt->getUniqidKey());

        $namespace = $this->getModel();
        $model = new $namespace();
        $user = $model->findOrFail($uid);

        return $user;
    }
}
