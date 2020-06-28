<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Parser;
use think\App;
use xiaodi\JWTAuth\Exception\JWTException;

class Manager
{
    protected $cache;

    public function __construct(App $app)
    {
        $this->app = $app;
        $this->cache = $this->getDefaultCache();
        $this->config = $this->getConfig();
    }


    /**
     * 获取 配置
     *
     * @return void
     */
    public function getConfig()
    {
        $config = $this->app->config->get("jwt.manager", []);

        if (empty($config)) {
            throw new JWTException("jwt manager 未配置完整.", 500);
        }

        return $config;
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

        if ($jwt = $this->getLatestToken($jti, $store)) {
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
        $key = $this->makeWhitelistKey($jti, $store);
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
        $key = $this->makeKey([
            $this->config['prefix'],
            $this->config['whitelist'],
            $store
        ]);

        $init = [];
        $values = $this->cache->get($key, serialize($init));
        if (is_string($values)) {
            $values = unserialize($values);
        }

        array_push($values, $value);
        $this->cache->set($key, $values);
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
        $key = $this->makeBlacklistKey($jti, $store);

        $exp = $token->getClaim('exp') - time();
        $key .= ':' . md5((string) $token);
        $this->cache->set($key, (string) $token, $exp);
    }

    /**
     * 获取用户应用下最新token
     *
     * @param [type] $jti
     * @return void
     */
    public function getLatestToken($jti, $store)
    {
        $key = $this->makeWhitelistKey($jti, $store);
        return $this->cache->get($key);
    }

    /**
     * 获取 白名单 key
     *
     * @param string $jti
     * @return string
     */
    public function makeWhitelistKey($jti, $store)
    {
        return $this->makeKey([
            $this->config['prefix'],
            $this->config['whitelist'],
            $store,
            $jti
        ]);
    }

    /**
     * 获取 黑名单 key
     *
     * @param string $jti
     * @param string $store
     * @return string
     */
    public function makeBlacklistKey($jti, $store)
    {
        return $this->makeKey([
            $this->config['prefix'],
            $this->config['blacklist'],
            $store,
            $jti
        ]);
    }

    /**
     * Undocumented function
     *
     * @param array $value
     * @return string
     */
    protected function makeKey(array $value)
    {
        $key = implode(':', $value);

        return $key;
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
        $key = $this->makeBlacklistKey($jti, $store);
        $key .= ':' . md5((string) $token);

        return $this->cache->has($key);
    }

    public function getStoreWhitelistKey($store)
    {
        $arr = [
            $this->config['prefix'],
            $this->config['whitelist'],
            $store
        ];

        $key = implode(':', $arr);

        return $key;
    }

    /**
     * 将应用下所有Token加入到黑名单 （强制下线）
     *
     * @param string $store
     * @return void
     */
    public function joinToBlacklist($store)
    {
        $key = $this->makeStoreWhitelistKey($store);
        $keys = $this->storeLoggedKeys($store);
        $parse = new Parser();
        if ($keys) {
            foreach ($keys as $item) {
                $token = $this->cache->get($item);
                if ($token) {
                    $this->cache->delete($item);
                    $token = $parse->parse($token);
                    $this->addBlackList($token);
                }
            }
            $this->cache->delete($key);
        }
    }

    protected function makeStoreWhitelistKey($store)
    {
        return $this->makeKey([
            $this->config['prefix'],
            $this->config['whitelist'],
            $store
        ]);
    }

    /**
     * 获取应用下所有已登录的token
     *
     * @param string $store
     * @return array
     */
    public function storeLoggedKeys($store)
    {
        $key = $this->makeStoreWhitelistKey($store);

        return $this->cache->get($key);
    }

    /**
     * 强制手动注销指定用户
     *
     * @param string|array $uid
     * @return void
     */
    public function logoutByUid($uid)
    {
        // todo
    }
}
