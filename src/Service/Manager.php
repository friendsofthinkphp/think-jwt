<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
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
        if ($this->app->get('jwt.sso')->getEnable()) {
            $this->handleSSO($token);
        }

        $this->pushWhitelist($token);
    }

    protected function handleSSO(Token $token): void
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');
        $exp = $token->getClaim('exp') - time();

        $this->destroyToken($jti, $store);
    }

    protected function pushWhitelist(Token $token): void
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');
        $exp = $token->getClaim('exp') - time();
        $tag = $store .'-' . $this->config->getWhitelist();

        $key = $this->formatKey($store, $this->config->getWhitelist(), $jti, (string)$token);
        $this->setCache($tag, $key, (string)$token, $exp);
    }

    protected function pushBlacklist(Token $token): void
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        $exp = $token->getClaim('exp') - time();
        $tag = $store .'-' . $this->config->getBlacklist();
        $key = $this->formatKey($store, $this->config->getBlacklist(), $jti, (string)$token);

        $this->setCache($tag, $key, (string)$token, $exp);
    }

    public function logout(Token $token): void
    {
        $this->pushBlacklist($token);
    }

    public function wasBan(Token $token): bool
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        return $this->getBlacklist($store, $jti, (string)$token) === (string) $token ? true : false;
    }

    protected function getBlacklist(string $store, string $jti, string $token)
    {
        return $this->getCache($store, $this->config->getBlacklist(), $jti, $token);
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
        $type = $this->config->getWhitelist();
        $tag = $store .'-' . $type;

        $rule = implode(':', [$this->config->getPrefix(), $store, $type, $id]);
        $keys = $this->app->cache->getTagItems($tag);

        $parser = new Parser();

        foreach($keys as $key) {
            if (false !== strpos($key, $rule)) {
                $value = $this->app->cache->get($key);
                $token = $parser->parse($value);

                $this->pushBlacklist($token);
            }
        }
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

    private function setCache($tag, $key, $value, $exp): void
    {
        $this->app->cache->tag($tag)->set($key, $value, $exp);
    }

    private function formatKey($store, $type, $uid, $value): string
    {
        $key = implode(':', [$this->config->getPrefix(), $store, $type, $uid, md5($value)]);

        return $key;
    }

    private function clearCache($store, $type, $uid): void
    {
        $key = $this->formatKey($store, $type, $uid);

        $this->app->cache->delete($key);
    }

    private function getCache($store, $type, $jti, $token)
    {
        $key = implode(':', [$this->config->getPrefix(), $store, $type, $jti, md5($token)]);

        return $this->app->cache->get($key);
    }
}
