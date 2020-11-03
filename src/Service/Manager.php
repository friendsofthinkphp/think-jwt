<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use Lcobucci\JWT\Token;
use think\App;
use xiaodi\JWTAuth\Config\Manager as Config;

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

    public function login(Token $token): void
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        $exp = $token->getClaim('exp') - time();

        if ($this->app->get('jwt.sso')->getEnable()) {
            $this->handleSSO($store, $jti, (string) $token, $exp);
        }

        $this->pushWhitelist($store, $jti, (string) $token, $exp);
    }

    protected function handleSSO($store, $jti, $token, $exp)
    {
        $key = $this->formatWhiteKey($store, $jti);
        if ($this->app->cache->has($key)) {
            $this->clearCache($store, $this->config->getWhitelist(), $jti);
            $this->pushBlacklist($store, $jti, (string) $token, $exp);
        }
    }

    protected function pushWhitelist($store, $jti, string $value, $exp): void
    {
        $this->setCache($store, $this->config->getWhitelist(), $jti, $value, $exp);
    }

    protected function pushBlacklist($store, $jti, string $value, $exp): void
    {
        $this->setCache($store, $this->config->getBlacklist(), $jti, $value, $exp);
    }

    public function logout(Token $token): void
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        $exp = $token->getClaim('exp') - time();
        $this->pushBlacklist($store, $jti, (string) $token, $exp);
    }

    public function wasBan(Token $token): bool
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        return $this->getBlacklist($store, $jti) ? true : false;
    }

    protected function getBlacklist($store, $jti)
    {
        return $this->getCache($store, $jti, $this->config->getBlacklist());
    }

    public function destroyStoreWhitelist($store): void
    {
        $this->clearStoreWhitelist($store);
    }

    public function destroyStoreBlacklist($store): void
    {
        $this->clearStoreBlacklist($store);
    }

    public function destroyToken($id, $store): void
    {
        $this->clearCache($store, $this->config->getWhitelist(), $id);
    }

    protected function clearStoreWhitelist($store): void
    {
        $this->clearTag($store . '-' . $this->config->getWhitelist());
    }

    protected function clearStoreBlacklist($store): void
    {
        $this->clearTag($store . '-' . $this->config->getBlacklist());
    }

    private function clearTag($tag): void
    {
        $this->app->cache->tag($tag)->clear();
    }

    private function setCache($store, $type, $uid, $value, $exp): void
    {
        $key = $this->formatKey($store, $type, $uid);

        $this->app->cache->tag($store . '-' . $type)->set($key, $value, $exp);
    }

    protected function formatWhitelist($store, $uid): string
    {
        return $this->formatKey($store, $this->config->getWhitelist(), $uid);
    }

    protected function formatBlacklist($store, $uid): string
    {
        return $this->formatKey($store, $this->config->getBlacklist(), $uid);
    }

    private function formatKey($store, $type, $uid): string
    {
        $key = implode(':', [$this->config->getPrefix(), $store, $type, $uid]);

        return $key;
    }

    private function clearCache($store, $type, $uid): void
    {
        $key = $this->formatKey($store, $type, $uid);

        $this->app->cache->delete($key);
    }

    private function getCache($store, $uid, $type)
    {
        $key = implode('', [$this->config->getPrefix(), $store, $type, $uid]);

        return $this->app->cache->get($key);
    }
}
