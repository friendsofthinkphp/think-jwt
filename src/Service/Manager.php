<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth\Service;

use Lcobucci\JWT\Token;
use think\App;
use think\Container;
use xiaodi\JWTAuth\Config\Manager as Config;
use xiaodi\JWTAuth\Exception\JWTException;

class Manager
{
    protected $cache;

    protected $app;

    protected $config;

    public function __construct(App $app)
    {
        $this->app = $app;

        $this->init();
    }

    protected function init()
    {
        $this->resloveConfig();
    }

    protected function resloveConfig()
    {
        $options = $this->app->config->get('jwt.manager', []);

        $this->config = new Config($options);
    }

    public function login(Token $token)
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        $exp = $token->getClaim('exp') - time();

        if ($this->app->get('jwt.sso')->getEnable()) {
            $this->pushBlacklist($store, $jti, (string) $token, $exp);
        }
        
        $this->pushWhitelist($store, $jti, (string) $token, $exp);
    }

    protected function pushWhitelist($store, $jti, string $value, $exp)
    {
        $this->setCache($store, 'whitelist', $jti, $value, $exp);
    }

    protected function pushBlacklist($store, $jti, string $value, $exp)
    {
        $this->setCache($store, 'blacklist', $jti, $value, $exp);
    }

    private function setCache($store, $type, $uid, $value, $exp)
    {
        $key = implode(':', ['jwt', $store, $type, $uid]);
        $this->app->cache->set($key, $value, $exp);
    }

    public function logout()
    {}

    public function destroyStore($store)
    {}

    public function destroyToken($id)
    {}
}
