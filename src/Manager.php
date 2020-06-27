<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
use think\App;

class Manager
{
    protected $store;
    protected $cache;

    public function __construct(App $app)
    {
        $this->app = $app;
        $this->cache = $this->getDefaultCache();
    }

    /**
     * 获取 缓存驱动.
     *
     * @return void
     */
    protected function getDefaultCache()
    {
        return $this->app->cache;
    }

    /**
     * 处理登录时.
     *
     * @param Token $token
     *
     * @return void
     */
    public function login(Token $token)
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');

        if ($jwt = $this->getUidToken($jti, $store)) {
            $oldToken = (new Parser)->parse($jwt);
            $this->addBlackList($oldToken);
        }

        $this->addWhitelist($token);
    }

    /**
     * 加入白名单.
     *
     * @param Token $token
     *
     * @return void
     */
    public function addWhitelist(Token $token)
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');
        $key = $this->getUidWhiteKey($jti, $store);
        $exp = $token->getClaim('exp') - time();

        $this->cache->set($key, (string) $token, $exp);
        $this->addWhiteStore($store, $key);
    }

    /**
     * 加入缓存用户已登录的应用
     * 
     * @param [type] $store
     * @param [type] $value
     * @return void
     */
    protected function addWhiteStore($store, $value)
    {
        $key = 'jwt' . ':' . 'whitelist' . ':' . $store;
        $this->cache->push($key, $value);
    }

    /**
     * 加入黑名单
     *
     * @return void
     */
    public function addBlackList(Token $token)
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');
        $key = $this->getUidBlackKey($jti, $store);

        $exp = $token->getClaim('exp') - time();
        $key .= ':' . md5((string)$token);
        $this->cache->set($key, (string) $token, $exp);
    }

    /**
     * 获取用户最新token
     *
     * @param [type] $jti
     * @return void
     */
    public function getUidToken($jti, $store)
    {
        $key = $this->getUidWhiteKey($jti, $store);
        return $this->cache->get($key);
    }

    /**
     * 获取jti 白名单 key
     *
     * @param string $jti
     * @return string
     */
    public function getUidWhiteKey($jti, $store)
    {
        return 'jwt' . ':' . 'whitelist' . ':' . $store . ':' . $jti;
    }

    /**
     * 获取jti 黑名单 key
     *
     * @param [type] $jti
     * @return void
     */
    public function getUidBlackKey($jti, $store)
    {
        return 'jwt' . ':' . 'blacklist' . ':' . $store . ':' . $jti;
    }

    /**
     * 处理登出时.
     *
     * @param Token $token
     *
     * @return void
     */
    public function logout(Token $token)
    {
        $this->addBlackList($token);
    }

    /**
     * 处理刷新时.
     *
     * @param Token $token
     *
     * @return void
     */
    public function refresh(Token $token)
    {
        $this->logout($token);
    }

    /**
     * 是否存在黑名单.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function hasBlacklist(Token $token)
    {
        $jti = $token->getClaim('jti');
        $store = $token->getClaim('store');
        $key = $this->getUidBlackKey($jti, $store);
        $key .= ':' . md5((string)$token);
        return $this->cache->has($key);
    }

    /**
     * 删除应用所有白名单内的Token
     *
     * @param [type] $store
     * @return void
     */
    public function resetStoreWhiteToken($store)
    {
        $key = 'jwt' . ':' . 'whitelist' . ':' . $store;

        $keys = $this->cache->get($key);

        $parse = new Parser();
        if ($keys) {
            foreach($keys as $item) {
                $token = $this->cache->get($item);
                if ($token) {
                    $this->cache->delete($item);
                    $token = $parse->parse($token);
                    $store = $token->getClaim('store');
                    $this->addBlackList($token, $store);
                }
            }
            $this->cache->delete($key);
        }
    }
}
