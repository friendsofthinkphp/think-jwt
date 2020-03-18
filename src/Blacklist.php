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

    private $store;

    protected $cacheName = 'blacklist';

    public function __construct(App $app)
    {
        $this->app = $app;

        $this->store = $this->getStore();

        $configs = $this->getConfig();

        foreach($configs as $key => $config) {
            $this->$key = $config;
        }
    }

    public function getConfig()
    {
        return $this->app->config->get('jwt.blacklist', []);
    }

    /**
     * 获取 缓存驱动.
     *
     * @return void
     */
    public function getStore()
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
            $this->store->push($this->cacheName, (string) $token, $exp);
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
        return $this->store->get($this->cacheName, []);
    }
}
