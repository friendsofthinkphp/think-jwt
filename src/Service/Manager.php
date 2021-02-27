<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Service;

use think\App;
use Lcobucci\JWT\Token;
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

    /**
     * @var Config
     */
    public function getConfig()
    {
        return $this->config;
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
        $jti = $token->claims()->get('jti');
        $store = $token->claims()->get('store');

        $this->destroyToken($jti, $store);
    }

    protected function pushWhitelist(Token $token): void
    {
        $jti = $token->claims()->get('jti');
        $store = $token->claims()->get('store');

        $now = time();
        $exp = $token->claims()->get('exp');

        $ttl = $exp->getTimestamp() - $now;
        $tag = $store . '-' . $this->config->getWhitelist();

        $key = $this->makeKey($store, $this->config->getWhitelist(), $jti, $token);
        $this->setCache($tag, $key, $token, $ttl);
    }

    protected function pushBlacklist(Token $token): void
    {
        $jti = $token->claims()->get('jti');
        $store = $token->claims()->get('store');

        $now = time();
        $exp = $token->claims()->get('exp');
        $ttl = $this->app->get('jwt.token')->getConfig()->getRefreshTTL();
        $exp = $exp->modify("+{$ttl} sec");
        $ttl = $exp->getTimestamp() - $now;
        $tag = $store . '-' . $this->config->getBlacklist();
        $key = $this->makeKey($store, $this->config->getBlacklist(), $jti, $token);

        $this->setCache($tag, $key, $token, $ttl);
    }

    public function logout(Token $token): void
    {
        $this->pushBlacklist($token);
    }

    public function wasBan(Token $token): bool
    {
        return $this->getBlacklist($token) === $token->toString();
    }

    protected function getBlacklist(Token $token)
    {
        $jti = $token->claims()->get('jti');
        $store = $token->claims()->get('store');
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

    protected function decodeFileCache($filename)
    {
        $content = @file_get_contents($filename);
        if (false !== $content) {
            $expire = (int) substr($content, 8, 12);

            $content = substr($content, 32);
            return is_string($content) ? ['content' => $content, 'expire' => $expire] : null;
        }
    }

    public function destroyToken($id, $store): void
    {
        $type = $this->config->getWhitelist();
        $tag = $store . '-' . $type;
        $keys = $this->app->cache->getTagItems($tag);

        foreach ($keys as $key) {
            $handle = strtolower($this->app->config->get('cache.default'));
            if ($handle == 'file') {
                $token = unserialize($this->decodeFileCache($key)['content']);
            } else if ($handle == 'redis') {
                $token = $this->app->cache->get($key);
            }

            $token = $this->app->get('jwt.token')->parse($token);
            if ($token->claims()->has('jti') && $token->claims()->get('jti') == $id) {
                $this->pushBlacklist($token);
            }
        }
    }

    private function makeKey($store, $type, $uid, Token $token): string
    {
        $key = implode(':', [$this->config->getPrefix(), $store, $type, $uid, md5($token->toString())]);

        return $key;
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

    private function setCache($tag, $key, Token $token, $exp): void
    {
        $this->app->cache->tag($tag)->set($key, $token->toString(), $exp);
    }

    private function getCache($store, $type, $jti, $token)
    {
        $key = $this->makeKey($store, $type, $jti, $token);
        return $this->app->cache->get($key);
    }
}
