<?php

namespace xiaodi;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use think\facade\Cache;
use xiaodi\Exception\JWTException;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\TokenAlreadyEexpired;

class Jwt
{
    private $builder;
    private $user;
    private $token;

    private $options = [
        // 单点登录
        'sso' => true,
        // 缓存前缀
        'sso_cache_key' => 'jwt-auth-user',
        // 单点登录用户唯一标识
        'sso_key' => 'uid',
        // 秘钥
        'signer_key' => '',
        // 在此时间前不可用(秒)
        'not_before' => 0,
        // 默认有效时间为一小时（秒）
        'expires_at' => 3600,
        // 默认使用sha256签名
        'signer' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        // 中间件自动注入用户模型
        'inject_user' => false,
        // 用户模型
        'user' => '',
    ];

    public function __construct(Builder $builder)
    {
        $this->builder = $builder;
        $this->options = array_merge($this->options, config('jwt', []));
    }

    /**
     * 生成 Token.
     *
     * @param array $claims
     *
     * @return string
     */
    public function token(array $claims)
    {
        $time = time();
        $expires_at = (int) $this->options['expires_at'] + $time;
        $not_before = (int) $this->options['not_before'] + $time;

        $uniqid = uniqid();
        // 单点登录
        if ($this->sso()) {
            $sso_key = $this->ssoKey();

            if (empty($claims[$sso_key])) {
                throw new JWTException('获取sso_key失败', 500);
            }
            $uniqid = $claims[$sso_key];
        }

        $this->builder->setIssuedAt($time)
            ->identifiedBy($uniqid, true)
            ->setNotBefore($not_before)
            ->setExpiration($expires_at);

        foreach ($claims as $key => $claim) {
            $this->builder->withClaim($key, $claim);
        }

        $token = $this->builder->getToken($this->getSigner(), $this->makeKey());

        if ($this->sso()) {
            $this->setCacheIssuedAt($uniqid, $time);
        }

        return $token->__toString();
    }

    public function ttl()
    {
        return $this->options['expires_at'];
    }

    public function type()
    {
        return 'bearer';
    }

    /**
     * 解析Token.
     *
     * @param string $token
     *
     * @return Token
     */
    public function parse(string $token)
    {
        try {
            $token = (new Parser())->parse($token);
        } catch (\InvalidArgumentException $e) {
            throw new JWTException('此 Token 解析失败', 500);
        }

        return $token;
    }

    /**
     * 验证 Token.
     *
     * @param string $token
     *
     * @return bool
     */
    public function verify(string $token)
    {
        // 解析Token
        $this->token = $this->parse($token);

        try {
            // 验证密钥是否与创建签名的密钥匹配
            if (false === $this->token->verify($this->getSigner(), $this->makeKey())) {
                throw new JWTException('此 Token 与 密钥不匹配', 500);
            }

            // 是否可用
            $exp = $this->token->getClaim('nbf');
            if (time() < $exp) {
                throw new JWTException('此 Token 暂未可用', 500);
            }

            // 是否已过期
            if ($this->token->isExpired()) {
                throw new TokenAlreadyEexpired('Token 已过期', 401);
            }

            // 单点登录
            if ($this->sso()) {
                $jwt_id = $this->token->getHeader('jti');
                // 当前Token签发时间
                $issued_at = $this->token->getClaim('iat');
                // 最新Token签发时间
                $cache_issued_at = $this->getCacheIssuedAt($jwt_id);
                if ($issued_at != $cache_issued_at) {
                    throw new HasLoggedException('已在其它终端登录，请重新登录', 401);
                }
            }
        } catch (\BadMethodCallException $e) {
            throw new JWTException('此 Token 未进行签名', 500);
        }

        return true;
    }

    /**
     * 缓存最新签发时间.
     *
     * @param string|int $jwt_id 唯一标识
     * @param string     $value  签发时间
     *
     * @return void
     */
    protected function setCacheIssuedAt($jwt_id, $value)
    {
        $key = $this->options['sso_cache_key'].'-'.$jwt_id;
        $ttl = $this->options['expires_at'] + $this->options['not_before'];

        Cache::set($key, $value, $ttl);
    }

    /**
     * 获取最新签发时间.
     *
     * @param string|int $jwt_id 唯一标识
     *
     * @return string
     */
    protected function getCacheIssuedAt($jwt_id)
    {
        return Cache::get($this->options['sso_cache_key'].'-'.$jwt_id);
    }

    /**
     * 获取Token对象
     *
     * @return void
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * 刷新 Token.
     *
     * @return void
     */
    public function refresh(Token $token)
    {
        $claims = $token->getClaims();

        unset($claims['iat']);
        unset($claims['jti']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['iss']);
        unset($claims['aud']);

        return $this->token($claims);
    }

    /**
     * 是否单点登录.
     *
     * @return bool
     */
    private function sso()
    {
        return $this->options['sso'];
    }

    /**
     * 获取 sso_key.
     *
     * @return string
     */
    private function ssoKey()
    {
        $key = $this->options['sso_key'];
        if (empty($key)) {
            throw new JWTException('sso_key 未配置', 500);
        }

        return $key;
    }

    /**
     * 获取私钥.
     *
     * @return string|null
     */
    private function getKey()
    {
        return $this->options['signer'];
    }

    /**
     * 生成私钥.
     *
     * @return Key
     */
    private function makeKey()
    {
        $key = $this->getKey();
        if (empty($key)) {
            throw new JWTException('私钥未配置.', 500);
        }

        return new Key($key);
    }

    /**
     * 获取加密方式.
     *
     * @return Signer|Exception
     */
    private function getSigner()
    {
        $signer = $this->options['signer'];

        if (empty($signer)) {
            throw new JWTException('加密方式未配置.', 500);
        }

        $signer = new $signer();

        if (!$signer instanceof Signer) {
            throw new JWTException('加密方式错误.', 500);
        }

        return $signer;
    }

    /**
     * 是否注入用户对象.
     *
     * @return bool
     */
    public function injectUser()
    {
        return $this->options['inject_user'];
    }

    /**
     * 获取用户模型.
     *
     * @return void
     */
    public function userModel()
    {
        return $this->options['user_model'];
    }

    /**
     * 获取用户模型对象
     *
     * @return void
     */
    public function user()
    {
        $uid = $this->token->getClaim($this->ssoKey());
        if ($uid) {
            $namespace = $this->options['user_model'];
            if (empty($namespace)) {
                throw new JWTException('用户模型文件未配置.', 500);
            }

            $r = new \ReflectionClass($namespace);
            $model = $r->newInstance();
            $this->user = $model->find($uid);
        }

        return $this->user;
    }

    public function getClaims()
    {
        return $this->token->getClaims();
    }
}
