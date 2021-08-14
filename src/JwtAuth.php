<?php

namespace xiaodi\think\jwt;

use think\App;
use JwtAuth\Config;
use xiaodi\think\jwt\Event;

class JwtAuth
{
    /**
     * @return App
     */
    protected $app;

    /**
     * @param string $store
     */
    protected $store;

    /**
     * @param $string $defaultStore
     */
    protected $defaultStore = 'default';

    protected $jwt;

    /**
     * @param App $app
     * @param string $store
     * 
     * @return \JwtAuth\JwtAuth
     */
    public function __construct(App $app, $store = null)
    {
        $this->app = $app;

        $config = $this->getConfig($store);
        $eventContext = new Event($app);

        $this->jwt = new \JwtAuth\JwtAuth($config, $eventContext);
    }

    /**
     * 获取应用配置
     * @return Config
     */
    protected function getConfig($store)
    {
        if (!$store) {
            $store = $this->getDefaultApp();
        }

        $options = $this->app->config->get('jwt.stores.' . $store);
        return new Config($options);
    }

    /**
     * 获取应用
     * @return string
     */
    public function getStore()
    {
        return $this->store ?? $this->getDefaultApp();
    }

    /**
     * 获取默认应用
     * @return string
     */
    protected function getDefaultApp()
    {
        return $this->defaultStore;
    }

    public function __call($name, $arguments)
    {
        return call_user_func_array([$this->jwt, $name], [...$arguments]);
    }
}
