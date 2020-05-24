<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use Lcobucci\JWT\Token;
use think\App;

/**
 * 黑名单.
 */
class Blacklist
{
    private $app;

    private $cacheKey;

    protected $cache;

    public function __construct(App $app)
    {
        $this->app = $app;

        $this->setStoreConfig();

        $this->cache = $this->getCache();
    }

    public function setStoreConfig()
    {
        $store = $this->app->jwt->getStore();
        $configs = $this->app->config->get("jwt.apps.{$store}.blacklist", []);

        foreach ($configs as $key => $v) {
            $this->$key = $v;
        }
    }

    /**
     * 获取 缓存驱动.
     *
     * @return void
     */
    public function getCache()
    {
        return $this->app->cache;
    }

    /**
     * 加入黑名单.
     *
     * @param Token $token
     *
     * @return void
     */
    public function add(Token $token)
    {
        if (false === $this->has($token)) {
            $claims = $token->getClaims();
            $exp = $claims['exp']->getValue() - time();
            $this->cache->push($this->cacheKey, (string) $token, $exp);
        }
    }

    /**
     * 是否存在黑名单.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function has(Token $token): bool
    {
        $blacklist = $this->getAll();

        return in_array((string) $token, $blacklist);
    }

    /**
     * 获取所有黑名单.
     *
     * @return array
     */
    public function getAll(): array
    {
        return $this->cache->get($this->cacheKey, []);
    }
}
