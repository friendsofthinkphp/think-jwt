<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use think\App;

class User
{
    private $inject = true;
    private $model;

    public function __construct()
    {
        $config = $this->getConfig();
        foreach ($config as $key => $v) {
            $this->$key = $v;
        }
    }

    public function getConfig()
    {
        return $this->app->config->get('jwt.user', []);
    }

    public function hasInject()
    {
        return $this->inject;
    }

    public function getModel()
    {
        return $this->model;
    }
}
